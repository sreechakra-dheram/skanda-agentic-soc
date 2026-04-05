import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

// --- Shared system prompt for all providers ---
const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in network vulnerability assessment. You will be given network packet data or log entries. Analyze them and return a structured JSON response with:
- "attack": Name of the attack or "None" if benign
- "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
- "reason": Brief explanation
- "mitigation": Recommended action
Return ONLY valid JSON, no markdown or extra text.`;

function buildUserPrompt(log, memoryContext) {
    return `Analyze this network log within this context: ${memoryContext}. Return FINAL JSON ONLY: { "attack": "Name", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "reason": "Reason", "mitigation": "Action" }. LOG: ${JSON.stringify(log)}`;
}

function parseAIResponse(text) {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
    return null;
}

const FALLBACK_RESULT = { attack: "Unknown", severity: "INFO", reason: "AI Analysis failure", mitigation: "Manual Review" };

// --- Gemini Provider ---
export class GeminiProvider {
    constructor() {
        this.apiKey = process.env.GEMINI_API_KEY;
        this.projectId = process.env.GCP_PROJECT_ID;
        this.modelsToTry = [
            process.env.GEMINI_MODEL,
            "gemini-1.5-flash",
            "gemini-2.0-flash",
            "gemini-pro"
        ].filter(Boolean);
    }

    get name() { return "gemini"; }

    async analyze(log, memoryContext = "") {
        const prompt = buildUserPrompt(log, memoryContext);

        for (const modelId of this.modelsToTry) {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${this.apiKey}`;
            const headers = { "Content-Type": "application/json" };
            if (this.projectId) headers["x-goog-user-project"] = this.projectId;

            try {
                const response = await axios.post(url, {
                    contents: [{ parts: [{ text: prompt }] }],
                    systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] }
                }, { timeout: 10000, headers });

                const text = response.data.candidates[0].content.parts[0].text;
                const parsed = parseAIResponse(text);
                if (parsed) return parsed;
            } catch (err) { continue; }
        }
        return FALLBACK_RESULT;
    }
}

// --- Llama (Vertex AI) Provider ---
export class LlamaVertexProvider {
    constructor() {
        this.projectId = process.env.GCP_PROJECT_ID;
        this.location = process.env.LLAMA_REGION || "us-east5";
        this.modelId = process.env.LLAMA_MODEL || "meta/llama-4-scout-17b-16e-instruct-maas";
        this.token = null;
        this.tokenExpiry = 0;
    }

    get name() { return "llama"; }

    async _refreshToken() {
        // Refresh if token expires within 5 minutes
        if (this.token && Date.now() < this.tokenExpiry - 300000) return;

        const { GoogleAuth } = await import("google-auth-library");
        const auth = new GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
        const client = await auth.getClient();
        const tokenResponse = await client.getAccessToken();
        this.token = tokenResponse.token;
        // GCP tokens typically last 3600s; set expiry conservatively
        this.tokenExpiry = Date.now() + 3500000;
    }

    async analyze(log, memoryContext = "") {
        await this._refreshToken();

        const baseUrl = `https://${this.location}-aiplatform.googleapis.com/v1/projects/${this.projectId}/locations/${this.location}/endpoints/openapi`;
        const prompt = buildUserPrompt(log, memoryContext);

        try {
            const response = await axios.post(
                `${baseUrl}/chat/completions`,
                {
                    model: this.modelId,
                    messages: [
                        { role: "system", content: SYSTEM_PROMPT },
                        { role: "user", content: prompt }
                    ],
                    max_tokens: 1024
                },
                {
                    timeout: 30000,
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${this.token}`
                    }
                }
            );

            const text = response.data.choices[0].message.content;
            const parsed = parseAIResponse(text);
            if (parsed) return parsed;
        } catch (err) {
            console.error("Llama Vertex AI error:", err.message);
        }

        return FALLBACK_RESULT;
    }
}

// --- Provider Factory ---
const providers = {
    gemini: () => new GeminiProvider(),
    llama: () => new LlamaVertexProvider(),
};

let activeProvider = null;

export function getProvider() {
    if (!activeProvider) {
        const model = (process.env.AI_MODEL || "gemini").toLowerCase();
        activeProvider = createProvider(model);
    }
    return activeProvider;
}

export function setProvider(modelName) {
    activeProvider = createProvider(modelName);
    return activeProvider;
}

export function createProvider(modelName) {
    const key = modelName.toLowerCase();
    if (!providers[key]) {
        throw new Error(`Unknown AI model: "${modelName}". Available: ${Object.keys(providers).join(", ")}`);
    }
    return providers[key]();
}

export function getAvailableModels() {
    return Object.keys(providers);
}
