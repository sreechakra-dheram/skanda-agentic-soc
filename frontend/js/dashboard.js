import { initSocket } from "./socket.js";

function adaptAIThreat(ai) {
    return {
        id: ai.id,
        src: ai.src_ip || "AI-DETECTED",
        title: ai.title,
        type: "AI Threat",
        severity: ai.severity,
        riskScore: ai.riskScore || 0,
        port: 0,
        desc: ai.description,
        rec: ai.mitigation,
        timestamp: ai.timestamp
    };
}

function handleThreat(aiThreat) {
    const adapted = adaptAIThreat(aiThreat);
    window.triggerThreatFromAI?.(adapted);
}

/* ⭐ NEW — reasoning stream */
function handleReasoning(message) {
    if (window.typeWriter) {
        window.typeWriter(message, "text-blue-300");
    }
}

function handleMitigation(result) {
    if (window.typeWriter) {
        window.typeWriter(
            `AGENT ACTION: ${result.status}`,
            "text-emerald-400"
        );
    }

    if (result.status === "MITIGATED") {
        window.typeWriter(
            `IP ${result.ip} successfully blocked.`,
            "text-emerald-300"
        );
    }

    if (result.status === "PENDING_APPROVAL") {
        window.typeWriter(
            "Awaiting analyst approval...",
            "text-yellow-300"
        );
    }
}

function handleRawLog(log) {
    if (window.injectLiveLog) {
        window.injectLiveLog(log);
    }
}

export function initDashboard() {
    initSocket(handleThreat, handleReasoning, handleMitigation, handleRawLog);
}