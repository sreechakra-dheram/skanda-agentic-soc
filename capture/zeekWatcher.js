import chokidar from "chokidar";
import fs from "fs";
import axios from "axios";
import { ZEEK_LOG } from "./config.js";
import { parseZeekLine } from "../backend/DataPipeline.js";
import { logInfo, logError } from "../shared/logger.js";
import dotenv from "dotenv";

dotenv.config();

let lastSize = 0;

logInfo("Watching Zeek logs...");

chokidar.watch(ZEEK_LOG).on("change", async () => {
    const stats = fs.statSync(ZEEK_LOG);

    if (stats.size < lastSize) {
        logInfo("Log file truncated. Resetting watcher.");
        lastSize = 0;
    }

    const stream = fs.createReadStream(ZEEK_LOG, {
        start: lastSize,
        end: stats.size
    });

    let buffer = "";

    stream.on("data", chunk => (buffer += chunk));

    stream.on("end", async () => {
        lastSize = stats.size;

        const lines = buffer.split("\n");

        for (const line of lines) {
            const parsed = parseZeekLine(line);
            if (!parsed) continue;

            try {
                await axios.post(
                    "http://127.0.0.1:5000/api/analyze",
                    parsed,
                    {
                        headers: {
                            "x-api-key": process.env.SOC_API_KEY
                        }
                    }
                );
            } catch (err) {
                logError(`Failed to send log to backend: ${err.message}`);
            }
        }
    });
});