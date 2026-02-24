import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { initWebSocket } from "./websocket.js";
import routes from "./routes.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("frontend"));

// Prevent process from crashing on unhandled errors
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

// Security Middleware (only for API routes)
const securityMiddleware = (req, res, next) => {
    const apiKey = req.headers["x-api-key"] || req.query.api_key;
    if (process.env.SOC_API_KEY && apiKey !== process.env.SOC_API_KEY) {
        return res.status(401).json({ error: "Unauthorized access to SOC API" });
    }
    next();
};

app.use("/api", securityMiddleware, routes);

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOC Server running on http://127.0.0.1:${PORT}`);
});

initWebSocket(server);