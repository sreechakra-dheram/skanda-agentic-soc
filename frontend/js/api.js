const API_BASE = "http://localhost:5000/api";

/* ======================
   ANALYZE LOG (manual)
====================== */
export async function analyzeLog(data) {
    const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });

    return res.json();
}

/* ======================
   FETCH REPORT
====================== */
export async function fetchReport() {
    const res = await fetch(`${API_BASE}/report`);
    return res.json();
}

/* ======================
   FETCH STORED THREATS
====================== */
export async function fetchThreats() {
    const res = await fetch(`${API_BASE}/report`);
    const report = await res.json();
    return report.incidents || [];
}

export async function approveMitigation(threat) {
    await fetch("http://localhost:5000/api/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(threat)
    });
}