let socket;

export function initSocket(onThreat, onReasoning, onMitigation, onRawLog) {

    socket = new WebSocket("ws://127.0.0.1:5000");

    socket.onmessage = event => {
        const data = JSON.parse(event.data);

        if (data.type === "THREAT_DETECTED")
            onThreat(data.payload);

        if (data.type === "AI_REASONING")
            onReasoning(data.payload);

        if (data.type === "MITIGATION_STATUS")
            onMitigation(data.payload);

        if (data.type === "NEW_LOG")
            onRawLog(data.payload);
    };
}