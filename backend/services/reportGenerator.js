export function generateIncidentReport(threats) {

    const severityCount = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };

    threats.forEach(t => {
        if (severityCount[t.severity] !== undefined)
            severityCount[t.severity]++;
    });

    return {
        generatedAt: new Date().toISOString(),
        totalThreats: threats.length,
        severityBreakdown: severityCount,
        summary:
            "AI SOC detected multiple anomalous behaviors during monitoring.",
        incidents: threats
    };
}