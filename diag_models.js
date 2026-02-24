import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

async function listModels() {
    const key = process.env.GEMINI_API_KEY;
    const versions = ["v1", "v1beta"];

    for (const v of versions) {
        console.log(`\n--- Checking ${v} ---`);
        try {
            const url = `https://generativelanguage.googleapis.com/${v}/models?key=${key}`;
            const res = await axios.get(url);
            if (res.data.models) {
                res.data.models.forEach(m => console.log(m.name));
            } else {
                console.log("No models found.");
            }
        } catch (e) {
            console.error(`Error ${v}: ${e.response?.status || e.message}`);
        }
    }
}

listModels();
