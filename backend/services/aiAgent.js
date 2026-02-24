import { analyzeWithGemini } from "./geminiAnalyzer.js";
import { MemoryAgent } from "./memoryAgent.js";
import { broadcastReasoning } from "../websocket.js";

/**
 * AIAgent orchestrates the multi-agent logical flow:
 * 1. Analyst Agent: Analyzes raw telemetry with memory context.
 * 2. Planner Agent: Determines if mitigation is needed based on history.
 * 3. Responder Agent: Finalizes the response/mitigation steps.
 */
export const AIAgent = {
    async processLog(log) {
        broadcastReasoning("Initializing Agentic SOC Pipeline...");

        // 1. Fetch context from Memory Agent
        const context = MemoryAgent.getRecentContextSummary();
        const ipHistory = log.src_ip ? MemoryAgent.getIPHistory(log.src_ip) : null;

        broadcastReasoning("Analyst Agent: Correlating telemetry with long-term memory...");

        let memoryString = `Recent context: ${context.recentAttacks.join(", ")}.`;
        if (ipHistory && ipHistory.count > 0) {
            memoryString += ` Source IP ${log.src_ip} has been seen ${ipHistory.count} times before. Previous behaviors: ${ipHistory.behaviors.join(", ")}.`;

            const correlations = MemoryAgent.findCorrelations(log.src_ip);
            if (correlations) {
                broadcastReasoning(`⚠️ Multi-stage threat correlation detected for ${log.src_ip}`);
                memoryString += ` CRITICAL CORRELATION: ${correlations.join(" | ")}`;
            }
        }

        // 2. Analyst Role: Detection
        const analysis = await analyzeWithGemini(log, memoryString);

        // 3. Log to memory for future correlation
        if (analysis.attack && analysis.attack !== "None") {
            MemoryAgent.logEvent({
                src_ip: log.src_ip,
                attack: analysis.attack,
                severity: analysis.severity
            });
        }

        // 4. Planner Role: Mitigation Strategy (already partially in analyzeWithGemini, now refined)
        broadcastReasoning("Planner Agent: Formulating response strategy...");
        if (analysis.severity === "CRITICAL" || analysis.severity === "HIGH") {
            broadcastReasoning(`High risk detected. Escalating to automated responder.`);
        } else {
            broadcastReasoning(`Low/Medium risk. Monitoring and logging event.`);
        }

        // 5. Responder Role: (This is handled by the mitigationAgent in analysisController)
        broadcastReasoning("Responder Agent: Finalizing analysis report.");

        return analysis;
    }
};
