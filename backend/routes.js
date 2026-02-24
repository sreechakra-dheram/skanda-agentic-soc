import express from "express";
import { DataPipeline } from "./DataPipeline.js";
import { MitigationAgent } from "./SOCAgent.js";
import { ThreatRadar } from "./ThreatRadar.js";

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

export default router;