from __future__ import annotations

import argparse
import math
import random
import time

import requests


def main() -> None:
    parser = argparse.ArgumentParser(description="Periodic sensor payload publisher")
    parser.add_argument("--api", default="http://127.0.0.1:8000/sensor", help="Sensor endpoint URL")
    parser.add_argument("--device-id", default="ton-iot-sensor-01", help="Sensor device identifier")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between updates")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    parser.add_argument("--temperature-base", type=float, default=24.0, help="Baseline temperature in C")
    parser.add_argument("--humidity-base", type=float, default=52.0, help="Baseline humidity in %")
    args = parser.parse_args()

    start = time.time()
    print(f"Sending sensor heartbeats to: {args.api}")

    while True:
        elapsed = time.time() - start
        temperature = args.temperature_base + math.sin(elapsed / 18.0) * 1.8 + random.uniform(-0.2, 0.2)
        humidity = args.humidity_base + math.cos(elapsed / 24.0) * 3.5 + random.uniform(-0.5, 0.5)
        payload = {
            "temperature": round(temperature, 2),
            "humidity": round(humidity, 2),
            "device_id": args.device_id,
            "sensor_timestamp": time.time(),
        }

        try:
            response = requests.post(args.api, json=payload, timeout=args.timeout)
            response.raise_for_status()
            print(
                f"sensor temp={payload['temperature']:.2f}C humidity={payload['humidity']:.2f}% "
                f"device={args.device_id}"
            )
        except Exception as exc:
            print(f"sensor publish error: {exc}")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()