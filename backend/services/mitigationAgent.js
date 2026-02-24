import { exec } from "child_process";
import dotenv from "dotenv";
import os from "os";
import { broadcastReasoning } from "../websocket.js";

dotenv.config();

const AUTO = process.env.AUTO_MITIGATION === "true";
const SAFE = process.env.SAFE_MODE === "true";

export async function mitigateThreat(threat) {
    if (!AUTO) return;

    broadcastReasoning(`Mitigation agent evaluating response for ${threat.title}...`);

    if (SAFE) {
        broadcastReasoning("SAFE MODE enabled — awaiting user approval.");
        return {
            status: "PENDING_APPROVAL",
            threat
        };
    }

    return executeMitigation(threat);
}

function executeMitigation(threat) {
    const ip = threat.src_ip || "0.0.0.0";
    const platform = os.platform();

    broadcastReasoning(`Platform detected: ${platform}. Attempting firewall rule for ${ip}...`);

    let command = "";
    if (platform === "linux") {
        command = `sudo iptables -A INPUT -s ${ip} -j DROP`;
    } else if (platform === "win32") {
        command = `netsh advfirewall firewall add rule name="SkANDA_Block_${ip}" dir=in action=block remoteip=${ip}`;
    } else {
        broadcastReasoning(`Unsupported platform: ${platform}. Mitigation aborted.`);
        return { status: "FAILED", reason: "UNSUPPORTED_PLATFORM" };
    }

    exec(command, (err) => {
        if (err) {
            broadcastReasoning(`Firewall rule failed: ${err.message}`);
        } else {
            broadcastReasoning(`Firewall rule applied successfully on ${platform}.`);
        }
    });

    return {
        status: "MITIGATED",
        action: "IP_BLOCKED",
        platform,
        ip
    };
}

export async function approveMitigation(threat) {
    return executeMitigation(threat);
}