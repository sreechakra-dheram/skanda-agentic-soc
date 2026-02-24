import { AIAgent } from "../services/aiAgent.js";
import { evaluateThreat } from "../services/threatEngine.js";
import { broadcast, broadcastReasoning } from "../websocket.js";
import { logThreat } from "../../shared/logger.js";
import { saveThreat } from "../../storage/database.js";
import { createThreatModel } from "../../storage/threatModel.js";
import { mitigateThreat } from "../services/mitigationAgent.js";
import { RiskEngine } from "../services/riskEngine.js";
import { MemoryAgent } from "../services/memoryAgent.js";

const threats = [];
let packetCounter = 0;
const SAMPLING_RATE = 200;

export async function analyzeLog(req, res) {
    try {
        const log = req.body;
        packetCounter++;

        // Show only every 200th packet in the UI datastream as requested
        if (packetCounter % SAMPLING_RATE !== 0) {
            // Optional: log to terminal only for developer sanity
            // console.log(`Skipping packet ${packetCounter} (Sampling: 1/${SAMPLING_RATE})`);
            return res.json({ status: "skipped_sampling", count: packetCounter });
        }

        broadcast({
            type: "NEW_LOG",
            payload: log
        });

        broadcastReasoning(`📡 Telemetry Sampling: Capturing packet #${packetCounter}...`);
        broadcastReasoning(`🔬 Initializing AI-SOC Pipeline for Deep Packet Inspection...`);

        const aiResult = await AIAgent.processLog(log);
        const threat = createThreatModel(aiResult);

        // Add dynamic risk score
        const history = MemoryAgent.getIPHistory(log.src_ip);
        threat.riskScore = RiskEngine.calculateScore(threat, history);

        evaluateThreat(threat); // Updates threat object if needed

        threats.push(threat);

        logThreat(threat);
        saveThreat(threat);

        broadcast({
            type: "THREAT_DETECTED",
            payload: threat
        });

        const mitigation = await mitigateThreat(threat);
        if (mitigation) {
            broadcast({
                type: "MITIGATION_STATUS",
                payload: mitigation
            });
        }

        res.json(threat);
    } catch (error) {
        console.error("ANALYSIS ERROR:", error.message);
        broadcastReasoning(`⚠️ Error analyzing log: ${error.message}`);
        res.status(500).json({ error: "Analysis failed", details: error.message });
    }
}

export function getThreats() {
    return threats;
}