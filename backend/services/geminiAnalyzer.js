import axios from "axios";
import dotenv from "dotenv";
import { broadcastReasoning } from "../websocket.js";

dotenv.config();

const MODELS_TO_TRY = [
    process.env.GEMINI_MODEL,
    "gemini-1.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-001",
    "gemini-2.5-flash",
    "gemini-pro"
].filter(Boolean);

function think(step) {
    broadcastReasoning(step);
}

export async function analyzeWithGemini(log, memoryContext = "") {
    const prompt = `Analyze this network log. Explanations should be concise. Return FINAL JSON ONLY: { "attack": "Name", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "reason": "Reason", "mitigation": "Action" }. LOG: ${JSON.stringify(log)}`;

    const PROJECT_ID = process.env.GCP_PROJECT_ID;
    const API_KEY = process.env.GEMINI_API_KEY;

    for (const modelId of MODELS_TO_TRY) {
        const endpoints = [
            `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${API_KEY}`,
            `https://generativelanguage.googleapis.com/v1/models/${modelId}:generateContent?key=${API_KEY}`
        ];

        for (const url of endpoints) {
            // TIERED AUTH: Try without header first (Standard), then with header (Vertex/Project-bound)
            const headerOptions = [
                { 'Content-Type': 'application/json' } // Try standard first
            ];
            if (PROJECT_ID) {
                headerOptions.push({
                    'Content-Type': 'application/json',
                    'x-goog-user-project': PROJECT_ID
                });
            }

            for (const headers of headerOptions) {
                try {
                    const authMode = headers['x-goog-user-project'] ? "Project-Linked" : "Standard";
                    think(`🔗 AI Handshake: ${modelId} (${authMode})...`);

                    const response = await axios.post(url, {
                        contents: [{ parts: [{ text: prompt }] }]
                    }, {
                        timeout: 10000,
                        headers: headers
                    });

                    if (response.data?.candidates?.[0]?.content?.parts?.[0]?.text) {
                        const text = response.data.candidates[0].content.parts[0].text;
                        const jsonMatch = text.match(/\{[\s\S]*\}/);
                        if (jsonMatch) {
                            think(`✅ Analysis synchronized.`);
                            return JSON.parse(jsonMatch[0]);
                        }
                    }
                } catch (err) {
                    const status = err.response?.status;
                    const errorMsg = err.response?.data?.error?.message || err.message;

                    // Log to terminal for developer tracking
                    console.error(`Gemini Error (${modelId} | Auth: ${headers['x-goog-user-project'] ? 'Project' : 'Std'}):`, status, "-", errorMsg);

                    if (status === 429) {
                        think(`⚠️ Model ${modelId} rate limited. Moving to next...`);
                        break;
                    }
                    // If 404, the model/version combination is invalid, move to next version/endpoint
                    if (status === 404) break;

                    // If 403, we try the next header option for this endpoint
                    continue;
                }
            }
        }
    }
    throw new Error(`AI-SOC Mesh Offline. Check API Key and GCP Project permissions.`);
}