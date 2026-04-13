# SkANDA Prime — Agentic AI SOC

**SkANDA Prime** is an AI-powered autonomous Security Operations Center (SOC) designed to monitor real network traffic, detect cyber threats using Gemini AI, and execute automated mitigation actions.

## 🚀 Features

- **Live Telemetry Monitoring**: Real-time packet inspection via Zeek.
- **Agentic AI Analysis**: Multi-stage reasoning pipeline (Analyst, Planner, Responder) using Gemini.
- **Interactive Dashboard**: Real-time wire stream, network maps, and analytics.
- **Automated Mitigation**: Autonomous threat neutralization with safe-mode approval.
- **AI Forensic Chatbot**: Chat with your security database to identify patterns and find recent attacks.
- **Forensic Reporting**: Instant PDF report generation for detected incidents.
- **PCAP Support**: Upload and analyze Wireshark/PCAP captures directly from the dashboard.

## 🛠️ Tech Stack

- **Frontend**: Vanilla HTML5, CSS3, Tailwind CSS (via CDN), Lucide Icons.
- **Backend**: Node.js, Express, WebSocket (`ws`), Axios.
- **AI**: Gemini 1.5 Flash (Google AI Studio).

## 📥 Installation

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Configure Environment**:
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

To have a fully functional SOC locally, follow these steps:

### 1. Start the Backend Server
```bash
npm run dev
```
The dashboard will be available at `http://localhost:5000`.

### 2. Start the Telemetry Capture Agent
(Required for live network monitoring on Windows)
```bash
node capture/capture.js
```

### 3. Using the AI Chatbot
Once the dashboard is open, look for the **blue message icon** in the bottom-right corner. You can ask:
- *"Show me recent attacks."*
- *"Which IP is most suspicious?"*
- *"Give me a summary of last hour's activity."*

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
