import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { initWebSocket } from "./websocket.js";
import { DataPipeline } from "./DataPipeline.js";
import { MitigationAgent, ThreatRadar } from "./SOCAgent.js";
import { getProvider, setProvider, getAvailableModels } from "./AIProvider.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("frontend"));

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

// Security Middleware
const securityMiddleware = (req, res, next) => {
    const apiKey = req.headers["x-api-key"] || req.query.api_key;
    if (process.env.SOC_API_KEY && apiKey !== process.env.SOC_API_KEY) {
        return res.status(401).json({ error: "Unauthorized access to SOC API" });
    }
    next();
};

// --- API Routes ---
const router = express.Router();

router.post("/analyze", DataPipeline.analyze);
router.get("/threats", DataPipeline.getHistory);

router.get("/report", (req, res) => {
    res.json(ThreatRadar.generateReport([]));
});

router.post("/approve", async (req, res) => {
    const result = await MitigationAgent.approve(req.body);
    res.json(result);
});

router.get("/model", (req, res) => {
    res.json({ active: getProvider().name, available: getAvailableModels() });
});

router.post("/model", (req, res) => {
    const { model } = req.body;
    try {
        const provider = setProvider(model);
        res.json({ status: "ok", active: provider.name });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.use("/api", securityMiddleware, router);

// --- Start ---
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOC Server running on http://127.0.0.1:${PORT}`);
});
initWebSocket(server);
