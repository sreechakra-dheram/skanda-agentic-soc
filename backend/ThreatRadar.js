export const ThreatRadar = {
    createThreat(aiResult) {
        return {
            id: `TR-${Date.now()}`,
            title: aiResult.attack || "Anomalous Traffic",
            severity: aiResult.severity || "INFO",
            reason: aiResult.reason || "Packet inspection triggered alert.",
            mitigation: aiResult.mitigation || "Monitor IP activity.",
            timestamp: new Date().toISOString(),
            riskScore: 0
        };
    },

    calculateRisk(threat, history) {
        const severityMap = { CRITICAL: 50, HIGH: 35, MEDIUM: 20, LOW: 10, INFO: 5 };
        let score = (severityMap[threat.severity] || 5);
        if (history) {
            score += Math.min(history.count * 5, 30); // History weight
            score += Math.min(history.behaviors.length * 10, 20); // Variety weight
        }
        return Math.min(score, 100);
    },

    generateReport(threats) {
        const stats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        threats.forEach(t => stats[t.severity]++);
        return {
            generatedAt: new Date().toISOString(),
            totalIncidents: threats.length,
            severityMetrics: stats,
            summary: "Automated SOC Intelligence Report",
            detailedIncidents: threats
        };
    }
};
