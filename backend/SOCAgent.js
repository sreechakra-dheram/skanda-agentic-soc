import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import os from "os";
import { broadcastReasoning } from "./websocket.js";

dotenv.config();

const MEMORY_PATH = path.resolve("storage/memory.json");
const MODELS_TO_TRY = [
    process.env.GEMINI_MODEL,
    "gemini-1.5-flash",
    "gemini-2.0-flash",
    "gemini-pro"
].filter(Boolean);

// --- MEMORY LOGIC ---
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

// --- AI ANALYZER ---
async function analyzeWithGemini(log, memoryContext = "") {
    const prompt = `Analyze this network log within this context: ${memoryContext}. Return FINAL JSON ONLY: { "attack": "Name", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "reason": "Reason", "mitigation": "Action" }. LOG: ${JSON.stringify(log)}`;
    const API_KEY = process.env.GEMINI_API_KEY;
    const PROJECT_ID = process.env.GCP_PROJECT_ID;

    for (const modelId of MODELS_TO_TRY) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${API_KEY}`;
        const headers = { 'Content-Type': 'application/json' };
        if (PROJECT_ID) headers['x-goog-user-project'] = PROJECT_ID;

        try {
            const response = await axios.post(url, { contents: [{ parts: [{ text: prompt }] }] }, { timeout: 10000, headers });
            const text = response.data.candidates[0].content.parts[0].text;
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) return JSON.parse(jsonMatch[0]);
        } catch (err) { continue; }
    }
    return { attack: "Unknown", severity: "INFO", reason: "AI Analysis failure", mitigation: "Manual Review" };
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

// --- ORCHESTRATOR ---
export const SOCAgent = {
    async processLog(log) {
        broadcastReasoning("🧠 AI SOC Brain: Correlating telemetry...");
        const context = MemoryAgent.getRecentContextSummary();
        const analysis = await analyzeWithGemini(log, context.recentAttacks.join(", "));

        if (analysis.attack !== "None") {
            MemoryAgent.logEvent({ src_ip: log.src_ip, attack: analysis.attack, severity: analysis.severity });
        }

        return analysis;
    }
};
