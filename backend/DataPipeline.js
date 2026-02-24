import { SOCAgent, MitigationAgent } from "./SOCAgent.js";
import { ThreatRadar } from "./ThreatRadar.js";
import { broadcast, broadcastReasoning } from "./websocket.js";
import { saveThreat, getThreatsDB } from "./Database.js";

let packetCounter = 0;
const SAMPLING_RATE = 1;

export function parseZeekLine(line) {
    if (!line || line.startsWith("#")) return null;
    const p = line.split("\t");
    if (p.length < 7) return null;
    return {
        ts: p[0],
        uid: p[1],
        src_ip: p[2],
        src_port: p[3],
        dst_ip: p[4],
        dst_port: p[5],
        protocol: p[6],
        service: p[7] || "-",
        duration: p[8] || "0",
        orig_bytes: parseInt(p[9]) || 0
    };
}

export const DataPipeline = {
    async analyze(req, res) {
        try {
            const rawLog = req.body;
            packetCounter++;

            if (packetCounter % SAMPLING_RATE !== 0) {
                return res.json({ status: "sampled", count: packetCounter });
            }

            // 1. Broadcast raw telemetry to UI
            broadcast({ type: "NEW_LOG", payload: rawLog });
            broadcastReasoning(`📡 Packet #${packetCounter} captured. Analyzing...`);

            // 2. Process through AI Agent
            const aiResult = await SOCAgent.processLog(rawLog);

            // 3. Transform to Threat Model
            const threat = ThreatRadar.createThreat(aiResult);
            threat.src_ip = rawLog.src_ip;

            // 4. Calculate Dynamic Risk
            const history = SOCAgent.MemoryAgent ? SOCAgent.MemoryAgent.getIPHistory(rawLog.src_ip) : null;
            threat.riskScore = ThreatRadar.calculateRisk(threat, history);

            // 5. Persist and Broadcast
            saveThreat(threat);
            broadcast({ type: "THREAT_DETECTED", payload: threat });

            // 6. Automated Response
            const mitigation = await MitigationAgent.execute(threat);
            if (mitigation) broadcast({ type: "MITIGATION_STATUS", payload: mitigation });

            res.json(threat);
        } catch (err) {
            console.error("Pipeline Error:", err);
            res.status(500).json({ error: "Pipeline failure" });
        }
    },

    getHistory(req, res) {
        res.json(getThreatsDB());
    }
};
