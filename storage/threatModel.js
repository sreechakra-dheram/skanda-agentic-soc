export function createThreatModel(ai) {
    return {
        id: Date.now(),
        title: ai.attack || "Unknown Threat",
        severity: ai.severity || "LOW",
        description: ai.reason || "",
        mitigation: ai.mitigation || "",
        timestamp: new Date().toISOString()
    };
}