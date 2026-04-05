import { WebSocketServer } from "ws";

let wss;

export function initWebSocket(server) {
    wss = new WebSocketServer({ server });
    wss.on("connection", () => console.log("Dashboard connected"));
}

export function broadcast(data) {
    if (!wss) return;
    wss.clients.forEach(client => {
        if (client.readyState === 1) client.send(JSON.stringify(data));
    });
}

export function broadcastReasoning(message) {
    broadcast({ type: "AI_REASONING", payload: message });
}
