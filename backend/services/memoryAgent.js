import fs from "fs";
import path from "path";

const MEMORY_PATH = path.resolve("storage/memory.json");

// Initialize memory file if it doesn't exist
if (!fs.existsSync(MEMORY_PATH)) {
    fs.writeFileSync(MEMORY_PATH, JSON.stringify({
        ipHistory: {},
        recentAlerts: [],
        patterns: []
    }, null, 2));
}

/**
 * Memory Agent manages long-term context for the SOC
 */
export const MemoryAgent = {
    /**
     * Get historical information about a specific IP
     */
    getIPHistory(ip) {
        const memory = this._load();
        return memory.ipHistory[ip] || { count: 0, lastSeen: null, behaviors: [] };
    },

    /**
     * Store an event in memory for future correlation
     */
    logEvent(event) {
        const memory = this._load();
        const { src_ip, attack, severity } = event;

        if (src_ip) {
            if (!memory.ipHistory[src_ip]) {
                memory.ipHistory[src_ip] = { count: 0, lastSeen: null, behaviors: [] };
            }
            memory.ipHistory[src_ip].count++;
            memory.ipHistory[src_ip].lastSeen = new Date().toISOString();
            if (attack && !memory.ipHistory[src_ip].behaviors.includes(attack)) {
                memory.ipHistory[src_ip].behaviors.push(attack);
            }
        }

        memory.recentAlerts.push({
            timestamp: new Date().toISOString(),
            attack,
            severity,
            src_ip
        });

        // Keep last 100 alerts for context
        if (memory.recentAlerts.length > 100) {
            memory.recentAlerts.shift();
        }

        this._save(memory);
    },

    /**
     * Detects multi-stage attack patterns (Scanned -> Failed Login -> Success)
     */
    findCorrelations(ip) {
        const memory = this._load();
        const history = memory.recentAlerts.filter(a => a.src_ip === ip);

        if (history.length < 2) return null;

        const patterns = [];
        const titles = history.map(h => h.attack.toLowerCase());

        // Example Correlation: Brute Force -> Success
        if (titles.includes("brute force") && titles.includes("successful login")) {
            patterns.push("CRITICAL: Brute force attack followed by successful entry.");
        }

        // Example Correlation: External Scan -> Internal Exploitation
        if (titles.includes("port scan") && (titles.includes("rce") || titles.includes("exploitation"))) {
            patterns.push("HIGH: Reconnaissance followed by exploitation attempt.");
        }

        return patterns.length > 0 ? patterns : null;
    },

    /**
     * Returns a summary of recent activity for AI context injection
     */
    getRecentContextSummary() {
        const memory = this._load();
        const frequentIPs = Object.entries(memory.ipHistory)
            .filter(([ip, data]) => data.count > 5)
            .map(([ip, data]) => `${ip} (${data.count} hits)`);

        const recentAttacks = memory.recentAlerts.slice(-5)
            .map(a => `${a.attack} from ${a.src_ip} (${a.severity})`);

        return {
            frequentIPs,
            recentAttacks,
            totalUniqueIPs: Object.keys(memory.ipHistory).length
        };
    },

    _load() {
        try {
            return JSON.parse(fs.readFileSync(MEMORY_PATH, "utf-8"));
        } catch (err) {
            return { ipHistory: {}, recentAlerts: [], patterns: [] };
        }
    },

    _save(memory) {
        fs.writeFileSync(MEMORY_PATH, JSON.stringify(memory, null, 2));
    }
};
