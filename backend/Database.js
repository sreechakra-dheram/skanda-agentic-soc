import fs from "fs";
import path from "path";

const DB_PATH = path.resolve("storage/threats.json");

// Ensure storage exists
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
    try {
        return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
    } catch (err) { return []; }
}
