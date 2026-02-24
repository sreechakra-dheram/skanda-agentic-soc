/**
 * Risk Scoring Engine calculates a dynamic risk score (0-100)
 * Risk = (Severity Weight * 0.5) + (History Weight * 0.3) + (Behavior Weight * 0.2)
 */
export const RiskEngine = {
    calculateScore(threat, history) {
        let score = 0;

        // 1. Severity Weight (50%)
        const severityMap = {
            CRITICAL: 100,
            HIGH: 75,
            MEDIUM: 50,
            LOW: 25,
            INFO: 10
        };
        score += (severityMap[threat.severity] || 0) * 0.5;

        // 2. History Weight (30%)
        // Repeat offenders increase the risk significantly
        const historyCount = history ? history.count : 0;
        const historyScore = Math.min(historyCount * 10, 100);
        score += historyScore * 0.3;

        // 3. Behavior Weight (20%)
        // Multiple distinct attack types from one IP increase the risk
        const behaviorCount = history ? history.behaviors.length : 0;
        const behaviorScore = Math.min(behaviorCount * 20, 100);
        score += behaviorScore * 0.2;

        return Math.round(score);
    }
};
