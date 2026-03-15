# 🛡️ ZeroTrust Risk Analyzer

An enterprise-grade **Zero Trust Network Security Dashboard** that detects 
lateral movement, analyzes risk scores, and visualizes network topology in 
real time.

---

## 📸 Features

- 🔴 **Real-time Risk Scoring** — every node scored 0–100
- 🕸️ **Network Topology Graph** — force-directed live visualization
- ⚠️ **Lateral Movement Detection** — attack path analysis
- 🗄️ **SQLite Database** — historical risk logs and alerts
- 🔄 **Auto-refresh** — live data from backend
- 🐳 **Docker Support** — one command deployment

---

## 🏗️ Architecture
```
network_logs.json
       ↓
graph_builder.py / risk_engine.py / lateral_movement.py  (engines)
       ↓
graph_service.py / risk_service.py / movement_service.py (services)
       ↓
analysis.py (routes) → main.py (FastAPI) → port 8000
       ↓
App.js (React Dashboard) → port 3000
       ↓
SQLite Database (zerotrust.db)
```

---

## 🗂️ Project Structure
```
ZeroTrust_Risk_Analyzer/
├── backend/
│   ├── app/
│   │   ├── engines/
│   │   │   ├── graph_builder.py
│   │   │   ├── lateral_movement.py
│   │   │   └── risk_engine.py
│   │   ├── routes/
│   │   │   └── analysis.py
│   │   ├── services/
│   │   │   ├── graph_service.py
│   │   │   ├── movement_service.py
│   │   │   └── risk_service.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── main.py
│   │   ├── models.py
│   │   └── schemas.py
│   ├── dataset/
│   │   └── network_logs.json
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   └── dashboard/
│       ├── public/
│       ├── src/
│       │   ├── App.js
│       │   ├── App.css
│       │   └── index.js
│       ├── Dockerfile
│       └── package.json
│
├── docker-compose.yml
└── README.md
```

---

## 🚀 Getting Started

### Option 1 — Run Manually

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend/dashboard
npm install
npm start
```

### Option 2 — Run with Docker
```bash
docker-compose up --build
```

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/network-graph` | Network topology |
| GET | `/lateral-movement` | Attack paths |
| GET | `/risk-analysis` | Node risk scores |
| GET | `/history/risk` | Historical risk logs |
| GET | `/alerts` | All alerts |
| PUT | `/alerts/{id}/resolve` | Resolve an alert |

API Docs: `http://127.0.0.1:8000/docs`

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React.js |
| Backend | FastAPI (Python) |
| Database | SQLite + SQLAlchemy |
| Runtime | Uvicorn |
| Container | Docker |

---

## 📊 Risk Levels

| Score | Level | Color |
|-------|-------|-------|
| 80–100 | CRITICAL | 🔴 Red |
| 60–79 | HIGH | 🟠 Orange |
| 40–59 | MEDIUM | 🟡 Yellow |
| 0–39 | LOW | 🟢 Green |

---

## 👤 Author
Built as an enterprise security monitoring tool using 
Zero Trust principles — Never Trust, Always Verify.