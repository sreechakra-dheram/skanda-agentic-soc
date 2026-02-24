# SkANDA Prime — Agentic AI SOC

**SkANDA Prime** is an AI-powered autonomous Security Operations Center (SOC) designed to monitor real network traffic, detect cyber threats using Gemini AI, and execute automated mitigation actions.

## 🚀 Features

- **Live Telemetry Monitoring**: Real-time packet inspection via Zeek.
- **Agentic AI Analysis**: Multi-stage reasoning pipeline (Analyst, Planner, Responder) using Gemini.
- **Interactive Dashboard**: 3-6-3 grid layout with live wire stream, network map, and analytics.
- **Automated Mitigation**: Autonomous threat neutralization with safe-mode approval.
- **Forensic Reporting**: Instant PDF report generation for detected incidents.
- **Wireshark Integration**: Support for importing and replaying `.json` packet captures.

## 🛠️ Tech Stack

- **Frontend**: Vanilla HTML5, CSS3, Tailwind CSS, vis-network, Chart.js.
- **Backend**: Node.js, Express, WebSocket (`ws`).
- **Network**: Zeek (Network Monitoring), Microsoft Message Analyzer (Windows Bridge).
- **AI**: Gemini 1.5 Flash.

## 📥 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd skanda-prime-soc
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment**:
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_gemini_api_key
   GCP_PROJECT_ID=your_gcp_project_id
   PORT=5000
   SOC_API_KEY=skanda_secret_123
   AUTO_MITIGATION=true
   SAFE_MODE=true
   GEMINI_MODEL=gemini-1.5-flash
   ```

## 🏃 Running the SOC

To have a fully functional SOC, you need to run three components:

### 1. Start the Backend Server
```bash
npm run dev
```
The dashboard will be available at `http://127.0.0.1:5000`.

### 2. Start the Windows Telemetry Bridge
(Required for live Windows network monitoring)
```bash
node capture/liveBridge.js
```

### 3. Start the Zeek Log Watcher
```bash
node capture/zeekWatcher.js
```

## 📁 Directory Structure

- `backend/`: Express server, WebSocket logic, and AI services.
- `frontend/`: Dashboard UI and client-side logic.
- `capture/`: Network monitoring agents and Zeek watchers.
- `storage/`: Persistent JSON database for threats.
- `shared/`: Centralized logging and utilities.

## 🔐 Security & Safety
- **Safe Mode**: When `SAFE_MODE=true`, the AI will ask for manual confirmation before executing any firewall rules.
- **Sampling**: By default, the SOC samples only 1 out of 200 packets to optimize AI performance and cost.

---
*Built for Advanced Agentic Security Operations.*
