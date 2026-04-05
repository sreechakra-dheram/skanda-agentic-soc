import { exec } from "child_process";
import fs from "fs";
import path from "path";
import chokidar from "chokidar";
import axios from "axios";
import { parseZeekLine } from "../backend/DataPipeline.js";
import dotenv from "dotenv";

dotenv.config();

const ZEEK_LOG = "./capture/zeek_logs/conn.log";

// Ensure log directory exists
const logDir = path.dirname(ZEEK_LOG);
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

// Reset log file on startup
fs.writeFileSync(ZEEK_LOG, "");

console.log(`🚀 SkANDA Live Bridge Started`);
console.log(`📊 Capturing real Windows network activity...`);
console.log(`📁 Writing to: ${ZEEK_LOG}`);

// --- LIVE BRIDGE: Capture Windows network traffic ---
function captureTraffic() {
    exec("netstat -n", (error, stdout) => {
        if (error) return;

        const lines = stdout.split("\n");
        const logEntries = [];

        lines.forEach(line => {
            const match = line.trim().match(/^(TCP|UDP)\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+/) ||
                line.trim().match(/^(TCP|UDP)\s+\[([a-f\d\:]+)\]:(\d+)\s+\[([a-f\d\:]+)\]:(\d+)\s+/);

            if (match) {
                const [_, proto, src_ip, src_port, dest_ip, dest_port] = match;

                if (src_ip === "127.0.0.1" || dest_ip === "127.0.0.1" || src_ip === "::1" || dest_ip === "::1") return;

                const ts = (Date.now() / 1000).toFixed(6);
                const uid = Math.random().toString(36).substring(7);
                logEntries.push(`${ts}\t${uid}\t${src_ip}\t${src_port}\t${dest_ip}\t${dest_port}\t${proto.toLowerCase()}\t-\t0.1\t100\t100\tSF\t-\t-\t0\tShAdDa\t5\t500\t5\t500\t-`);
            }
        });

        if (logEntries.length > 0) {
            fs.appendFileSync(ZEEK_LOG, logEntries.join("\n") + "\n");
        }
    });
}

setInterval(captureTraffic, 2000);

// --- ZEEK WATCHER: Send parsed logs to backend ---
let lastSize = 0;

console.log("[INFO] Watching Zeek logs...");

chokidar.watch(ZEEK_LOG).on("change", async () => {
    const stats = fs.statSync(ZEEK_LOG);

    if (stats.size < lastSize) {
        console.log("[INFO] Log file truncated. Resetting watcher.");
        lastSize = 0;
    }

    const stream = fs.createReadStream(ZEEK_LOG, { start: lastSize, end: stats.size });
    let buffer = "";

    stream.on("data", chunk => (buffer += chunk));

    stream.on("end", async () => {
        lastSize = stats.size;

        for (const line of buffer.split("\n")) {
            const parsed = parseZeekLine(line);
            if (!parsed) continue;

            if (parsed.src_ip === "127.0.0.1" || parsed.dst_ip === "127.0.0.1" || parsed.src_ip === "::1" || parsed.dst_ip === "::1") continue;

            try {
                await axios.post("http://127.0.0.1:5000/api/analyze", parsed, {
                    headers: { "x-api-key": process.env.SOC_API_KEY }
                });
            } catch (err) {
                console.error(`[ERROR] Failed to send log to backend: ${err.message}`);
            }
        }
    });
});
