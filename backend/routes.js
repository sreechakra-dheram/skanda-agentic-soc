import express from "express";
import { analyzeLog, getThreats } from "./controllers/analysisController.js";
import { generateIncidentReport } from "./services/reportGenerator.js";
import { approveMitigation } from "./services/mitigationAgent.js";

const router = express.Router();

router.post("/analyze", analyzeLog);

router.get("/report", (req, res) => {
    const report = generateIncidentReport(getThreats());
    res.json(report);
});

router.post("/approve", async (req, res) => {
    const result = await approveMitigation(req.body);
    res.json(result);
});

export default router;