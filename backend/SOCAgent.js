import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import os from "os";
import { broadcastReasoning } from "./websocket.js";
import { getProvider } from "./AIProvider.js";

dotenv.config();

// --- DATABASE ---
const DB_PATH = path.resolve("storage/threats.json");
const MEMORY_PATH = path.resolve("storage/memory.json");

if (!fs.existsSync("storage")) fs.mkdirSync("storage");
if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify([]));

export function saveThreat(threat) {
    try {
        const threats = JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
        threats.push(threat);
        fs.writeFileSync(DB_PATH, JSON.stringify(threats, null, 2));
    } catch (err) { console.error("DB Save Error:", err); }
}

export function getThreatsDB() {
    try { return JSON.parse(fs.readFileSync(DB_PATH, "utf-8")); }
    catch (err) { return []; }
}

// --- MEMORY ---
export const MemoryAgent = {
    _load() {
        try {
            if (!fs.existsSync(MEMORY_PATH)) return { ipHistory: {}, recentAlerts: [], patterns: [] };
            return JSON.parse(fs.readFileSync(MEMORY_PATH, "utf-8"));
        } catch (err) { return { ipHistory: {}, recentAlerts: [], patterns: [] }; }
    },
    _save(memory) { fs.writeFileSync(MEMORY_PATH, JSON.stringify(memory, null, 2)); },
    getIPHistory(ip) {
        const memory = this._load();
        return memory.ipHistory[ip] || { count: 0, lastSeen: null, behaviors: [] };
    },
    logEvent(event) {
        const memory = this._load();
        const { src_ip, attack, severity } = event;
        if (src_ip) {
            if (!memory.ipHistory[src_ip]) memory.ipHistory[src_ip] = { count: 0, lastSeen: null, behaviors: [] };
            memory.ipHistory[src_ip].count++;
            memory.ipHistory[src_ip].lastSeen = new Date().toISOString();
            if (attack && !memory.ipHistory[src_ip].behaviors.includes(attack)) memory.ipHistory[src_ip].behaviors.push(attack);
        }
        memory.recentAlerts.push({ timestamp: new Date().toISOString(), attack, severity, src_ip });
        if (memory.recentAlerts.length > 100) memory.recentAlerts.shift();
        this._save(memory);
    },
    getRecentContextSummary() {
        const memory = this._load();
        const recentAttacks = memory.recentAlerts.slice(-5).map(a => `${a.attack} from ${a.src_ip} (${a.severity})`);
        return { recentAttacks };
    }
};

// --- THREAT RADAR ---
export const ThreatRadar = {
    createThreat(aiResult) {
        return {
            id: `TR-${Date.now()}`,
            title: aiResult.attack || "Anomalous Traffic",
            severity: aiResult.severity || "INFO",
            reason: aiResult.reason || "Packet inspection triggered alert.",
            mitigation: aiResult.mitigation || "Monitor IP activity.",
            timestamp: new Date().toISOString(),
            riskScore: 0
        };
    },
    calculateRisk(threat, history) {
        const severityMap = { CRITICAL: 50, HIGH: 35, MEDIUM: 20, LOW: 10, INFO: 5 };
        let score = (severityMap[threat.severity] || 5);
        if (history) {
            score += Math.min(history.count * 5, 30);
            score += Math.min(history.behaviors.length * 10, 20);
        }
        return Math.min(score, 100);
    },
    generateReport(threats) {
        const stats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        threats.forEach(t => stats[t.severity]++);
        return {
            generatedAt: new Date().toISOString(),
            totalIncidents: threats.length,
            severityMetrics: stats,
            summary: "Automated SOC Intelligence Report",
            detailedIncidents: threats
        };
    }
};

// --- AI ANALYZER ---
async function analyzeWithAI(log, memoryContext = "") {
    const provider = getProvider();
    return provider.analyze(log, memoryContext);
}

// --- MITIGATION AGENT ---
export const MitigationAgent = {
    async execute(threat) {
        if (process.env.AUTO_MITIGATION !== "true") return null;
        if (process.env.SAFE_MODE === "true") {
            broadcastReasoning("SAFE MODE: Awaiting manual approval for mitigation.");
            return { status: "PENDING_APPROVAL", threat };
        }
        return this.runFirewallCommand(threat);
    },
    runFirewallCommand(threat) {
        const ip = threat.src_ip || "0.0.0.0";
        const platform = os.platform();
        let command = platform === "win32"
            ? `netsh advfirewall firewall add rule name="SOC_Block_${ip}" dir=in action=block remoteip=${ip}`
            : `sudo iptables -A INPUT -s ${ip} -j DROP`;

        broadcastReasoning(`Executing firewall rule for ${ip} on ${platform}...`);
        exec(command, (err) => {
            if (err) broadcastReasoning(`Mitigation failed: ${err.message}`);
            else broadcastReasoning(`Successfully blocked IP ${ip}.`);
        });
        return { status: "MITIGATED", platform, ip };
    },
    async approve(threat) {
        return this.runFirewallCommand(threat);
    }
};

// --- SOC ORCHESTRATOR ---
export const SOCAgent = {
    async processLog(log) {
        broadcastReasoning("🧠 AI SOC Brain: Correlating telemetry...");
        const context = MemoryAgent.getRecentContextSummary();
        const analysis = await analyzeWithAI(log, context.recentAttacks.join(", "));

        if (analysis.attack !== "None") {
            MemoryAgent.logEvent({ src_ip: log.src_ip, attack: analysis.attack, severity: analysis.severity });
        }

        return analysis;
    }
};
