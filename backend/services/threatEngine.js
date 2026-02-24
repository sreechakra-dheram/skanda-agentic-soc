export function evaluateThreat(ai) {
    return {
        id: Date.now(),
        title: ai.attack,
        severity: ai.severity,
        description: ai.reason,
        mitigation: ai.mitigation,
        timestamp: new Date().toISOString()
    };
}