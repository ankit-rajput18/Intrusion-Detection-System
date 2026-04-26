from __future__ import annotations

from collections import deque
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from model_service import ModelService
from schemas import (
    BatchPredictRequest,
    BatchPredictResponse,
    AlertResponse,
    BuzzerControlResponse,
    HealthResponse,
    MetadataResponse,
    MetricsResponse,
    PredictRequest,
    PredictionResult,
    SensorDataResponse,
    SensorRequest,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_PATH = os.getenv("IDS_PIPELINE_PATH", "models/ton_iot/ton_iot_model_pipeline.joblib")
ENCODER_PATH = os.getenv("IDS_ENCODER_PATH", "models/ton_iot/ton_iot_label_encoder.joblib")
METADATA_PATH = os.getenv("IDS_METADATA_PATH", "models/ton_iot/ton_iot_metadata.json")
ALERT_SOURCE = os.getenv("IDS_ALERT_SOURCE", "hybrid").strip().lower()
SENSOR_ONLINE_SECONDS = float(os.getenv("IDS_SENSOR_ONLINE_SECONDS", "20"))
SENSOR_STALE_SECONDS = float(os.getenv("IDS_SENSOR_STALE_SECONDS", "120"))
SENSOR_TEMP_MIN = float(os.getenv("IDS_SENSOR_TEMP_MIN", "18"))
SENSOR_TEMP_MAX = float(os.getenv("IDS_SENSOR_TEMP_MAX", "40"))
SENSOR_HUM_MIN = float(os.getenv("IDS_SENSOR_HUM_MIN", "20"))
SENSOR_HUM_MAX = float(os.getenv("IDS_SENSOR_HUM_MAX", "85"))
SENSOR_BURST_WINDOW_SECONDS = float(os.getenv("IDS_SENSOR_BURST_WINDOW_SECONDS", "15"))
SENSOR_BURST_MAX_POSTS = int(os.getenv("IDS_SENSOR_BURST_MAX_POSTS", "6"))
SENSOR_BURST_MAX_RATE = float(os.getenv("IDS_SENSOR_BURST_MAX_RATE", "0.35"))

app = FastAPI(title="TON-IoT IDS Inference API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    service = ModelService(
        project_root=PROJECT_ROOT,
        pipeline_rel_path=PIPELINE_PATH,
        label_encoder_rel_path=ENCODER_PATH,
        metadata_rel_path=METADATA_PATH,
    )
except Exception as exc:
    service = None
    load_error = str(exc)
else:
    load_error = None


sensor_state: dict[str, object] = {
    "temperature": None,
    "humidity": None,
    "device_id": None,
    "sensor_timestamp": None,
    "received_at": None,
}
sensor_events: deque[dict[str, object]] = deque(maxlen=2000)
sensor_total_posts = 0
sensor_benign_count = 0
sensor_malicious_count = 0
buzzer_silenced_until_normal = False


def _sensor_status() -> tuple[str, float | None]:
    received_at = sensor_state.get("received_at")
    if not isinstance(received_at, (int, float)):
        return "offline", None

    age = time.time() - float(received_at)
    if age <= SENSOR_ONLINE_SECONDS:
        return "online", age
    if age <= SENSOR_STALE_SECONDS:
        return "stale", age
    return "offline", age


def _sensor_alert() -> dict[str, object]:
    status, age = _sensor_status()
    temperature = sensor_state.get("temperature")
    humidity = sensor_state.get("humidity")

    if status == "offline":
        return {
            "status": "offline",
            "attack_type": "sensor_offline",
            "confidence": None,
            "detection_mode": "sensor-rule",
            "anomaly_reason": "no-recent-sensor-update",
            "timestamp": sensor_state.get("received_at"),
        }

    if not isinstance(temperature, (int, float)) or not isinstance(humidity, (int, float)):
        return {
            "status": "offline",
            "attack_type": "sensor_invalid",
            "confidence": None,
            "detection_mode": "sensor-rule",
            "anomaly_reason": "missing-temperature-or-humidity",
            "timestamp": sensor_state.get("received_at"),
        }

    temp_out = float(temperature) < SENSOR_TEMP_MIN or float(temperature) > SENSOR_TEMP_MAX
    hum_out = float(humidity) < SENSOR_HUM_MIN or float(humidity) > SENSOR_HUM_MAX

    if temp_out or hum_out:
        return {
            "status": "attack",
            "attack_type": "sensor_anomaly",
            "confidence": 0.95,
            "detection_mode": "sensor-rule",
            "anomaly_reason": f"temp-humidity-out-of-range(age={age:.1f}s)",
            "timestamp": sensor_state.get("received_at"),
        }

    return {
        "status": "normal",
        "attack_type": "sensor_normal",
        "confidence": 0.99,
        "detection_mode": "sensor-rule",
        "anomaly_reason": f"sensor-healthy(age={age:.1f}s)",
        "timestamp": sensor_state.get("received_at"),
    }


def _sensor_burst_alert() -> dict[str, object]:
    recent = time.time() - SENSOR_BURST_WINDOW_SECONDS
    current_ts = sensor_state.get("received_at")
    recent_posts = [
        evt for evt in sensor_events
        if isinstance(evt.get("timestamp"), (int, float)) and float(evt["timestamp"]) >= recent
    ]

    if isinstance(current_ts, (int, float)) and float(current_ts) >= recent:
        recent_posts = [
            *recent_posts,
            {"timestamp": float(current_ts)},
        ]

    if not recent_posts:
        return {
            "status": "normal",
            "attack_type": "sensor_normal",
            "confidence": 0.0,
            "detection_mode": "sensor-burst",
            "anomaly_reason": None,
            "timestamp": sensor_state.get("received_at"),
        }

    window_seconds = max(1.0, SENSOR_BURST_WINDOW_SECONDS)
    rate = len(recent_posts) / window_seconds
    if len(recent_posts) >= SENSOR_BURST_MAX_POSTS or rate >= SENSOR_BURST_MAX_RATE:
        return {
            "status": "attack",
            "attack_type": "sensor_flood",
            "confidence": 0.92,
            "detection_mode": "sensor-burst",
            "anomaly_reason": f"sensor-post-burst(posts={len(recent_posts)},rate={rate:.2f}/s)",
            "timestamp": recent_posts[0].get("timestamp"),
        }

    return {
        "status": "normal",
        "attack_type": "sensor_normal",
        "confidence": 0.0,
        "detection_mode": "sensor-burst",
        "anomaly_reason": None,
        "timestamp": sensor_state.get("received_at"),
    }


def _append_sensor_event() -> None:
    alert = _sensor_alert()
    burst_alert = _sensor_burst_alert()
    is_attack = str(alert.get("status", "normal")).lower() == "attack" or str(burst_alert.get("status", "normal")).lower() == "attack"
    combined_label = alert.get("attack_type", "sensor_normal")
    if str(burst_alert.get("status", "normal")).lower() == "attack":
        combined_label = burst_alert.get("attack_type", "sensor_flood")
        alert = burst_alert
    event = {
        "predicted_label": combined_label,
        "confidence": alert.get("confidence"),
        "probabilities": {},
        "latency_ms": 0.0,
        "source": "esp32-sensor",
        "detection_mode": alert.get("detection_mode"),
        "anomaly_reason": alert.get("anomaly_reason"),
        "packet_rate": None,
        "total_packets": None,
        "total_bytes": None,
        "unique_dst_ports": None,
        "temperature": sensor_state.get("temperature"),
        "humidity": sensor_state.get("humidity"),
        "device_id": sensor_state.get("device_id"),
        "timestamp": time.time(),
    }
    sensor_events.appendleft(event)


def _recent_events(limit: int) -> list[dict[str, object]]:
    max_limit = max(1, min(limit, 1000))
    if service is None:
        return list(sensor_events)[:max_limit]

    merged = list(service.recent_events(limit=max_limit)) + list(sensor_events)[:max_limit]
    merged.sort(key=lambda item: float(item.get("timestamp") or 0.0), reverse=True)
    return merged[:max_limit]


def _latest_alert() -> dict[str, object]:
    sensor_alert = _sensor_alert()
    burst_alert = _sensor_burst_alert()
    sensor_is_attack = str(sensor_alert.get("status", "normal")).lower() == "attack"
    burst_is_attack = str(burst_alert.get("status", "normal")).lower() == "attack"

    if ALERT_SOURCE == "sensor":
        if burst_is_attack:
            return burst_alert
        return sensor_alert

    if service is None:
        return {
            "status": "offline",
            "attack_type": "unknown",
            "confidence": None,
            "detection_mode": None,
            "anomaly_reason": None,
            "timestamp": None,
        }

    events = service.recent_events(limit=1)
    if not events:
        if ALERT_SOURCE == "hybrid":
            if burst_is_attack:
                return burst_alert
            if sensor_is_attack:
                return sensor_alert
            return sensor_alert
        return {
            "status": "normal",
            "attack_type": "normal",
            "confidence": None,
            "detection_mode": None,
            "anomaly_reason": None,
            "timestamp": None,
        }

    latest = events[0]
    label = str(latest.get("predicted_label", "normal"))
    is_attack = label.lower() != "normal"
    if burst_is_attack:
        return burst_alert
    if sensor_is_attack:
        return sensor_alert
    return {
        "status": "attack" if is_attack else "normal",
        "attack_type": label,
        "confidence": latest.get("confidence"),
        "detection_mode": latest.get("detection_mode"),
        "anomaly_reason": latest.get("anomaly_reason"),
        "timestamp": latest.get("timestamp"),
    }


def _alert_with_buzzer() -> dict[str, object]:
    global buzzer_silenced_until_normal

    alert = _latest_alert()
    is_attack = str(alert.get("status", "normal")).lower() == "attack"

    # Auto-rearm once the system leaves attack state.
    if not is_attack and buzzer_silenced_until_normal:
        buzzer_silenced_until_normal = False

    buzzer_on = is_attack and not buzzer_silenced_until_normal
    alert["buzzer"] = "on" if buzzer_on else "off"
    alert["buzzer_silenced_until_normal"] = buzzer_silenced_until_normal
    return alert


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    model_type = type(service.artifacts.pipeline).__name__ if service is not None else None
    status = "ok" if service is not None else f"error: {load_error}"
    return HealthResponse(status=status, model_loaded=service is not None, model_type=model_type)


@app.get("/metadata", response_model=MetadataResponse)
def metadata() -> MetadataResponse:
    if service is None:
        raise HTTPException(status_code=500, detail=f"Model service not available: {load_error}")
    return MetadataResponse(**service.metadata())


@app.get("/metrics", response_model=MetricsResponse)
def metrics() -> MetricsResponse:
    if service is None:
        base_metrics = {
            "total_requests": 0,
            "total_predictions": 0,
            "benign_count": 0,
            "malicious_count": 0,
            "avg_latency_ms": 0.0,
            "error_count": 0,
        }
    else:
        base_metrics = service.metrics()

    combined_metrics = {
        "total_requests": int(base_metrics.get("total_requests", 0)) + sensor_total_posts,
        "total_predictions": int(base_metrics.get("total_predictions", 0)) + sensor_total_posts,
        "benign_count": int(base_metrics.get("benign_count", 0)) + sensor_benign_count,
        "malicious_count": int(base_metrics.get("malicious_count", 0)) + sensor_malicious_count,
        "avg_latency_ms": float(base_metrics.get("avg_latency_ms", 0.0)),
        "error_count": int(base_metrics.get("error_count", 0)),
    }
    return MetricsResponse(**combined_metrics)


@app.get("/events")
def events(limit: int = Query(default=100, ge=1, le=1000)) -> dict:
    return {"events": _recent_events(limit=limit)}


@app.get("/get-alert", response_model=AlertResponse)
def get_alert() -> AlertResponse:
    return AlertResponse(**_alert_with_buzzer())


@app.post("/buzzer/off", response_model=BuzzerControlResponse)
def buzzer_off() -> BuzzerControlResponse:
    global buzzer_silenced_until_normal
    buzzer_silenced_until_normal = True
    alert = _alert_with_buzzer()
    return BuzzerControlResponse(
        status=str(alert.get("status", "normal")),
        buzzer=str(alert.get("buzzer", "off")),
        buzzer_silenced_until_normal=bool(alert.get("buzzer_silenced_until_normal", False)),
        message="Buzzer silenced until alert returns to normal.",
    )


@app.post("/buzzer/on", response_model=BuzzerControlResponse)
def buzzer_on() -> BuzzerControlResponse:
    global buzzer_silenced_until_normal
    buzzer_silenced_until_normal = False
    alert = _alert_with_buzzer()
    return BuzzerControlResponse(
        status=str(alert.get("status", "normal")),
        buzzer=str(alert.get("buzzer", "off")),
        buzzer_silenced_until_normal=bool(alert.get("buzzer_silenced_until_normal", False)),
        message="Buzzer re-enabled.",
    )


@app.post("/sensor", response_model=SensorDataResponse)
def post_sensor(payload: SensorRequest) -> SensorDataResponse:
    global sensor_total_posts, sensor_benign_count, sensor_malicious_count

    sensor_state["temperature"] = float(payload.temperature)
    sensor_state["humidity"] = float(payload.humidity)
    sensor_state["device_id"] = payload.device_id
    sensor_state["sensor_timestamp"] = float(payload.sensor_timestamp) if payload.sensor_timestamp is not None else time.time()
    sensor_state["received_at"] = time.time()

    sensor_total_posts += 1
    sensor_alert = _sensor_alert()
    burst_alert = _sensor_burst_alert()
    if str(sensor_alert.get("status", "normal")).lower() == "attack" or str(burst_alert.get("status", "normal")).lower() == "attack":
        sensor_malicious_count += 1
    else:
        sensor_benign_count += 1

    _append_sensor_event()
    return SensorDataResponse(**{**sensor_state, "status": "online"})


@app.get("/sensor-data", response_model=SensorDataResponse)
def get_sensor_data() -> SensorDataResponse:
    status, _age = _sensor_status()

    return SensorDataResponse(**sensor_state, status=status)


@app.post("/predict", response_model=PredictionResult)
def predict(payload: PredictRequest) -> PredictionResult:
    if service is None:
        raise HTTPException(status_code=500, detail=f"Model service not available: {load_error}")
    try:
        results = service.predict_many([payload.features], [payload.source])
        return PredictionResult(**results[0])
    except Exception as exc:
        service.error_count += 1
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/predict/batch", response_model=BatchPredictResponse)
def predict_batch(payload: BatchPredictRequest) -> BatchPredictResponse:
    if service is None:
        raise HTTPException(status_code=500, detail=f"Model service not available: {load_error}")
    if not payload.items:
        raise HTTPException(status_code=400, detail="No prediction items supplied")

    features = [item.features for item in payload.items]
    sources = [item.source for item in payload.items]

    try:
        results = service.predict_many(features, sources)
    except Exception as exc:
        service.error_count += 1
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    summary: dict[str, int] = {}
    for item in results:
        label = item["predicted_label"]
        summary[label] = summary.get(label, 0) + 1

    return BatchPredictResponse(
        results=[PredictionResult(**item) for item in results],
        summary=summary,
    )
