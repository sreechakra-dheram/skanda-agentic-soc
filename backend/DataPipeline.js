import { SOCAgent, MitigationAgent, ThreatRadar, MemoryAgent, saveThreat, getThreatsDB } from "./SOCAgent.js";
import { broadcast, broadcastReasoning } from "./websocket.js";

let packetCounter = 0;
const SAMPLING_RATE = 100;

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

            if (rawLog.src_ip === "127.0.0.1" || rawLog.dst_ip === "127.0.0.1" || rawLog.src_ip === "::1" || rawLog.dst_ip === "::1") {
                return res.json({ status: "filtered_localhost" });
            }

            packetCounter++;
            if (packetCounter % SAMPLING_RATE !== 0) {
                return res.json({ status: "sampled", count: packetCounter });
            }

            broadcast({ type: "NEW_LOG", payload: rawLog });
            broadcastReasoning(`📡 Packet #${packetCounter} captured. Analyzing...`);

            const aiResult = await SOCAgent.processLog(rawLog);
            const threat = ThreatRadar.createThreat(aiResult);
            threat.src_ip = rawLog.src_ip;

            const history = MemoryAgent.getIPHistory(rawLog.src_ip);
            threat.riskScore = ThreatRadar.calculateRisk(threat, history);

            saveThreat(threat);
            broadcast({ type: "THREAT_DETECTED", payload: threat });

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
