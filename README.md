🚀 IoT-Based Intrusion Detection System (IDS)

📌 Overview

An IoT + Machine Learning based Intrusion Detection System that monitors network traffic and sensor data to detect cyber-attacks and anomalies in real-time.

🎯 **Objectives**

- Real-time intrusion detection
- Machine learning-based attack analysis
- Sensor monitoring (Temperature & Humidity)
- Dashboard visualization
- Attack simulation for testing

🧩 **System Components**

- **IoT Module**: ESP32 + DHT11, sends sensor data, buzzer alert system
- **Backend**: FastAPI server, handles API + ML inference
- **Machine Learning**: Trained on TON-IoT dataset, detects abnormal behavior
- **Dashboard**: Streamlit UI, real-time monitoring
- **Packet Profiler**: Captures network traffic
⚙️ Features
⚡ Real-time detection
🌐 Network attack monitoring
📊 Live dashboard
🔔 Buzzer alerts
🧪 Attack simulation
🏗️ **Architecture**

```mermaid
graph LR
A[ESP32 Sensor] --> B[Backend API]
B --> C[ML Model]
C --> D[Dashboard]
B --> E[Logs]
A --> F[Buzzer Alert]
```

The architecture consists of:
- **ESP32 Sensor**: Collects temperature and humidity data, sends to backend, and triggers buzzer alerts on anomaly detection.
- **Backend API**: Receives sensor and network data, performs ML inference, logs events, and communicates with the dashboard.
- **ML Model**: Detects attacks and anomalies using the TON-IoT dataset.
- **Dashboard**: Visualizes real-time detection results and system status.
- **Logs**: Stores events and alerts for analysis.
- **Buzzer Alert**: Provides immediate physical feedback on detected anomalies.
</details>
🧪 **Attack Scenarios**

| Attack           | Description                        | How to Test                                   |
|------------------|------------------------------------|-----------------------------------------------|
| 🔍 Port Scan     | Detects unusual port requests      | `python scan_traffic.py`                      |
| 🐢 Slowloris     | Slow request attack                | `python slow_traffic.py`                      |
| 💥 DoS           | High traffic burst                 | `python burst_traffic.py`                     |
| 🌡️ Sensor Anomaly | Abnormal temperature/humidity      | Send out-of-range values to `/sensor` endpoint |
| 📡 Sensor Flood  | Rapid sensor data                  | Use ESP32 flood mode or rapid POSTs           |

**Sensor Anomaly Example:**
```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/sensor" -ContentType "application/json" -Body '{"temperature":45,"humidity":5,"device_id":"esp32-dht11-1"}'
```

**Sensor Flood Example:**
- On ESP32 serial: `flood on`
- Or script rapid POSTs to `/sensor`

🚀 **Quick Start**

1. **Clone Repo**
   ```bash
   git clone https://github.com/your-username/ids-system.git
   cd ids-system
   ```
2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run Backend**
   ```bash
   uvicorn main:app --reload
   ```
4. **Run Dashboard**
   ```bash
   streamlit run app.py
   ```
5. **Run Attacks (for testing)**
   ```bash
   python scan_traffic.py
   python slow_traffic.py
   python burst_traffic.py
   ```

⚠️ **Requirements**
- Python 3.x
- ESP32
- DHT11 Sensor

📁 **Project Structure**
```
ids-system/
│── backend/
│── dashboard/
│── esp32/
│── models/
│── attacks/
```

📊 **Results & Capabilities**

- ✔ Detects multiple network attacks (Port Scan, Slowloris, DoS)
- ✔ Real-time sensor anomaly and flood detection
- ✔ Live dashboard for monitoring and event history
- ✔ Physical buzzer alerts for immediate notification
- ✔ Attack simulation tools for robust testing

---
👨‍💻 Author

Ankit Rajput
🎓 Academic Mini Project (IoT + Cybersecurity)

🔮 Future Scope
☁️ Cloud integration
🤖 Deep learning models
📱 Mobile app
add that image in architecture and all that add in readme file