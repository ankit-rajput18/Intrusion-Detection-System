#include <WiFi.h>
#include <HTTPClient.h>
#include <DHT.h>

// WiFi credentials
const char* ssid = "OPPO A6x 5G b864";
const char* password = "ankit0000";

// Backend base URL (Phase 3 FastAPI)
// Example: http://192.168.1.100:8000
const char* backendBaseUrl = "http://10.113.82.27:8000";

// Device identity
const char* deviceId = "esp32-dht11-1";

// Hardware pins
#define DHTPIN 4
#define DHTTYPE DHT11
#define BUZZER_PIN 5
#define SENSOR_FLOOD_COUNT 2
#define SENSOR_FLOOD_DELAY_MS 400

DHT dht(DHTPIN, DHTTYPE);

unsigned long lastPublishMs = 0;
const unsigned long publishIntervalMs = 5000;
bool sensorFloodTestMode = false;

void printHelp() {
  Serial.println("Commands: flood on | flood off | flood status | help");
}

void handleSerialCommand(String command) {
  command.trim();
  command.toLowerCase();

  if (command == "flood on") {
    sensorFloodTestMode = true;
    Serial.println("Sensor flood test mode: ON");
  } else if (command == "flood off") {
    sensorFloodTestMode = false;
    Serial.println("Sensor flood test mode: OFF");
  } else if (command == "flood status") {
    Serial.print("Sensor flood test mode is ");
    Serial.println(sensorFloodTestMode ? "ON" : "OFF");
  } else if (command == "help") {
    printHelp();
  } else if (command.length() > 0) {
    Serial.println("Unknown command. Type: help");
  }
}

void readSerialCommands() {
  if (!Serial.available()) {
    return;
  }

  String command = Serial.readStringUntil('\n');
  handleSerialCommand(command);
}

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected. IP: ");
  Serial.println(WiFi.localIP());
}

bool postSensorData(float temperature, float humidity) {
  String sensorUrl = String(backendBaseUrl) + "/sensor";
  String jsonData = "{";
  jsonData += "\"temperature\":" + String(temperature, 2) + ",";
  jsonData += "\"humidity\":" + String(humidity, 2) + ",";
  jsonData += "\"device_id\":\"" + String(deviceId) + "\",";
  jsonData += "\"sensor_timestamp\":" + String((double)millis() / 1000.0, 3);
  jsonData += "}";

  HTTPClient http;
  http.begin(sensorUrl);
  http.setTimeout(6000);
  http.addHeader("Content-Type", "application/json");

  int code = http.POST(jsonData);
  String response = "";
  if (code > 0) {
    response = http.getString();
  }
  http.end();

  Serial.print("POST /sensor host: ");
  Serial.println(backendBaseUrl);
  Serial.print("POST /sensor code: ");
  Serial.println(code);
  if (code <= 0) {
    Serial.print("POST /sensor error: ");
    Serial.println(HTTPClient::errorToString(code));
  }
  Serial.print("POST /sensor response: ");
  Serial.println(response);

  return code >= 200 && code < 300;
}

void sendSensorFlood(float temperature, float humidity) {
  for (int i = 0; i < SENSOR_FLOOD_COUNT; i++) {
    bool posted = postSensorData(temperature, humidity);
    if (!posted) {
      digitalWrite(BUZZER_PIN, LOW);
      Serial.println("Could not publish sensor flood data");
      return;
    }

    String status = getAlertStatus();
    applyAlertToBuzzer(status);

    if (i < SENSOR_FLOOD_COUNT - 1) {
      delay(SENSOR_FLOOD_DELAY_MS);
    }
  }
}

String getAlertStatus() {
  String alertUrl = String(backendBaseUrl) + "/get-alert";

  HTTPClient http;
  http.begin(alertUrl);
  http.setTimeout(6000);
  int code = http.GET();
  String response = "";
  if (code > 0) {
    response = http.getString();
  }
  http.end();

  Serial.print("GET /get-alert host: ");
  Serial.println(backendBaseUrl);
  Serial.print("GET /get-alert code: ");
  Serial.println(code);
  if (code <= 0) {
    Serial.print("GET /get-alert error: ");
    Serial.println(HTTPClient::errorToString(code));
  }
  Serial.print("GET /get-alert response: ");
  Serial.println(response);

  if (code > 0) {
    // Prefer backend buzzer command when present.
    if (response.indexOf("\"buzzer\":\"on\"") >= 0) {
      return "attack";
    }
    if (response.indexOf("\"buzzer\":\"off\"") >= 0) {
      if (response.indexOf("\"status\":\"attack\"") >= 0) {
        return "silenced";
      }
      if (response.indexOf("\"status\":\"normal\"") >= 0) {
        return "normal";
      }
      return "offline";
    }

    // Backward compatibility if buzzer field is not available.
    if (response.indexOf("\"status\":\"attack\"") >= 0) {
      return "attack";
    }
    if (response.indexOf("\"status\":\"normal\"") >= 0) {
      return "normal";
    }
    return "offline";
  }

  return "offline";
}

void applyAlertToBuzzer(const String& status) {
  if (status == "attack") {
    digitalWrite(BUZZER_PIN, HIGH);
    Serial.println("ALERT: ATTACK DETECTED");
  } else {
    digitalWrite(BUZZER_PIN, LOW);
    if (status == "normal") {
      Serial.println("System normal");
    } else if (status == "silenced") {
      Serial.println("Attack detected but buzzer is silenced from dashboard");
    } else {
      Serial.println("Alert service offline/unknown");
    }
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  dht.begin();
  connectWiFi();
  printHelp();
}

void loop() {
  readSerialCommands();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi disconnected. Reconnecting...");
    connectWiFi();
  }

  unsigned long now = millis();
  if (now - lastPublishMs < publishIntervalMs) {
    delay(5000);
    return;
  }
  lastPublishMs = now;

  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();

  if (isnan(temperature) || isnan(humidity)) {
    Serial.println("Failed to read from DHT11");
    return;
  }

  Serial.print("Temp: ");
  Serial.print(temperature);
  Serial.print(" C | Hum: ");
  Serial.print(humidity);
  Serial.println(" %");

  if (sensorFloodTestMode) {
    Serial.println("Sensor flood test mode enabled");
    sendSensorFlood(temperature, humidity);
  } else {
    bool posted = postSensorData(temperature, humidity);
    if (!posted) {
      digitalWrite(BUZZER_PIN, LOW);
      Serial.println("Could not publish sensor data");
      return;
    }

    String status = getAlertStatus();
    applyAlertToBuzzer(status);
  }
}