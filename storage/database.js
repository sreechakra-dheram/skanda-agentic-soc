import fs from "fs";
import path from "path";

const DB_PATH = path.resolve("storage/threats.json");

if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify([]));
}

export function readThreats() {
    return JSON.parse(fs.readFileSync(DB_PATH));
}

export function saveThreat(threat) {
    const threats = readThreats();
    threats.push(threat);
    fs.writeFileSync(DB_PATH, JSON.stringify(threats, null, 2));
}