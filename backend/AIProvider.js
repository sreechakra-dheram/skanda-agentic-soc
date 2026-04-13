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

const CHAT_SYSTEM_PROMPT = `You are "SkANDA AI", the embedded SOC (Security Operations Center) analyst for the SkANDA Prime threat detection platform.

Your exclusive domain is cybersecurity and network security operations. You have access to real-time session context including:
- All detected threats (title, severity, source IP, attack type, timestamp, risk score)
- Session summary (total packets analyzed, threat counts, current threat level, packets/sec)
- The last critical attack details
- Top attacking IP addresses
- Network safety score (0-100, computed from threat severity and count)
- Persistent incident history from the database

STRICT RULES:
1. ONLY answer questions related to: cybersecurity incidents, network threats, attack analysis, security recommendations, the current session's threat data, network safety assessment, IP reputation, CVEs, and SOC operations.
2. If asked ANYTHING outside cybersecurity/SOC domain (e.g., recipes, weather, general coding, jokes), respond: "I'm a dedicated SOC analyst AI. I can only assist with network security, threat analysis, and incident response. Please ask me about your network's security status."
3. ALWAYS reference actual data from the context when available. Never invent threat data.
4. If no threats are in the context, say so clearly and confirm the session is clean.
5. Use a precise, professional security analyst tone. Be alert but calm.
6. Format responses with **bold** for key terms, use bullet points for lists, and inline \`code\` for IPs and CVEs.
7. When calculating network safety, use the provided network_safety_score from context.
8. Always end recommendations with a concrete action the analyst can take.`;


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
        // Use stable production models only — preview models (2.5-flash) frequently timeout
        this.modelsToTry = [
            process.env.GEMINI_MODEL || "gemini-2.0-flash",
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash-latest",
            "gemini-pro"
        ].filter((v, i, a) => v && a.indexOf(v) === i); // deduplicate
    }

    get name() { return "gemini"; }

    async analyze(log, memoryContext = "") {
        const prompt = buildUserPrompt(log, memoryContext);

        for (const modelId of this.modelsToTry) {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${this.apiKey}`;
            const headers = { "Content-Type": "application/json" };
            try {
                const response = await axios.post(url, {
                    contents: [{ parts: [{ text: prompt }] }],
                    systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] }
                }, { timeout: 10000, headers });

                const text = response.data.candidates[0].content.parts[0].text;
                const parsed = parseAIResponse(text);
                if (parsed) return parsed;
            } catch (err) {
                const errMsg = err.response?.data?.error?.message || err.message;
                console.error(`[Gemini Analyze Error] ${modelId}: ${errMsg}`);
                continue;
            }
        }
        return FALLBACK_RESULT;
    }

    async chat(userQuery, context = "") {
        const prompt = `User Question: ${userQuery}\n\nContext Data (JSON): ${context}`;
        
        for (const modelId of this.modelsToTry) {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${this.apiKey}`;
            const headers = { "Content-Type": "application/json" };
            try {
                const response = await axios.post(url, {
                    contents: [{ parts: [{ text: prompt }] }],
                    systemInstruction: { parts: [{ text: CHAT_SYSTEM_PROMPT }] }
                }, { timeout: 20000, headers });

                return response.data.candidates[0].content.parts[0].text;
            } catch (err) {
                const errMsg = err.response?.data?.error?.message || err.message;
                console.error(`Gemini Chat Error with ${modelId}:`, errMsg);
                if (err.response?.status === 403) {
                    console.error("403 Forbidden: check if API key is valid or project is restricted.");
                }
                continue;
            }
        }
        return "I'm having trouble connecting to my brain. Please check your API configuration or model IDs.";
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

        const keyFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;
        if (!keyFile) {
            throw new Error(
                "GOOGLE_APPLICATION_CREDENTIALS is not set in .env. " +
                "Add: GOOGLE_APPLICATION_CREDENTIALS=C:/path/to/service-account-key.json"
            );
        }

        const { GoogleAuth } = await import("google-auth-library");
        // Explicitly pass keyFilename so it reads from .env, not system ADC
        const auth = new GoogleAuth({
            keyFilename: keyFile,
            scopes: ["https://www.googleapis.com/auth/cloud-platform"]
        });
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

    async chat(userQuery, context = "") {
        await this._refreshToken();
        const baseUrl = `https://${this.location}-aiplatform.googleapis.com/v1/projects/${this.projectId}/locations/${this.location}/endpoints/openapi`;
        try {
            const response = await axios.post(
                `${baseUrl}/chat/completions`,
                {
                    model: this.modelId,
                    messages: [
                        { role: "system", content: CHAT_SYSTEM_PROMPT },
                        { role: "user", content: `Context: ${context}\n\nQuestion: ${userQuery}` }
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
            return response.data.choices[0].message.content;
        } catch (err) {
            return "Llama chat unavailable. " + err.message;
        }
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
