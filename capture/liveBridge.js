import { exec } from "child_process";
import fs from "fs";
import path from "path";
import { ZEEK_LOG } from "./config.js";
import dotenv from "dotenv";

dotenv.config();

// Ensure log directory exists
const logDir = path.dirname(ZEEK_LOG);
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Reset log file on startup
fs.writeFileSync(ZEEK_LOG, "");
console.log(`🧹 Logs reset: ${ZEEK_LOG}`);

console.log(`🚀 SkANDA Live Bridge Started`);
console.log(`📊 Capturing real Windows network activity...`);
console.log(`📁 Writing to: ${ZEEK_LOG}`);

function captureTraffic() {
    // We use netstat to see active connections on Windows
    exec("netstat -n", (error, stdout, stderr) => {
        if (error) return;

        const lines = stdout.split("\n");
        const logEntries = [];

        lines.forEach(line => {
            // Match pattern: TCP    192.168.1.10:1234    1.2.3.4:443    ESTABLISHED
            const match = line.trim().match(/^(TCP|UDP)\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+/) ||
                line.trim().match(/^(TCP|UDP)\s+\[([a-f\d\:]+)\]:(\d+)\s+\[([a-f\d\:]+)\]:(\d+)\s+/);

            if (match) {
                const [_, proto, src_ip, src_port, dest_ip, dest_port] = match;

                // Format: ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
                // We only need the core fields for the parser
                const ts = (Date.now() / 1000).toFixed(6);
                const uid = Math.random().toString(36).substring(7);
                const entry = `${ts}\t${uid}\t${src_ip}\t${src_port}\t${dest_ip}\t${dest_port}\t${proto.toLowerCase()}\t-\t0.1\t100\t100\tSF\t-\t-\t0\tShAdDa\t5\t500\t5\t500\t-`;

                logEntries.push(entry);
            }
        });

        if (logEntries.length > 0) {
            fs.appendFileSync(ZEEK_LOG, logEntries.join("\n") + "\n");
        }
    });
}

// Update every 2 seconds
setInterval(captureTraffic, 2000);
