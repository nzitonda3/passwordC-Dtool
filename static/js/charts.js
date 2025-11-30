async function fetchLogs() {
    const res = await fetch("/admin/logs/data");
    return res.json();
}

async function fetchAlerts() {
    const res = await fetch("/admin/alerts/data");
    return res.json();
}


// --------------------------
// UPDATE LOG TABLE
// --------------------------
async function updateLogTable() {
    const logs = await fetchLogs();
    const tbody = document.querySelector("#logTable tbody");
    tbody.innerHTML = "";

    logs.forEach(log => {
        const row = `
            <tr>
                <td>${log.username}</td>
                <td>${log.ip}</td>
                <td>${log.status}</td>
                <td>${log.fingerprint}</td>
                <td>${log.timestamp}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}


// --------------------------
// UPDATE ALERT TABLE
// --------------------------
async function updateAlertTable() {
    const alerts = await fetchAlerts();
    const tbody = document.querySelector("#alertTable tbody");
    tbody.innerHTML = "";

    alerts.forEach(alert => {
        const row = `
            <tr>
                <td>${alert.alert_type}</td>
                <td>${alert.details}</td>
                <td>${alert.timestamp}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}


// --------------------------
// DRAW CHARTS
// --------------------------
async function drawCharts() {
    const logs = await fetchLogs();

    // Brute-force chart
    let ipCounts = {};
    logs.forEach(log => {
        if (log.status === "fail") {
            ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
        }
    });

    const bruteCtx = document.getElementById("bruteForceChart").getContext("2d");
    new Chart(bruteCtx, {
        type: "bar",
        data: {
            labels: Object.keys(ipCounts),
            datasets: [{
                label: "Failed Attempts per IP",
                data: Object.values(ipCounts),
                backgroundColor: "#00ff88"
            }]
        }
    });


    // Credential stuffing chart
    let fpCounts = {};
    logs.forEach(log => {
        fpCounts[log.fingerprint] = (fpCounts[log.fingerprint] || 0) + 1;
    });

    const stuffingCtx = document.getElementById("stuffingChart").getContext("2d");
    new Chart(stuffingCtx, {
        type: "pie",
        data: {
            labels: Object.keys(fpCounts),
            datasets: [{
                label: "Password Reuse by Fingerprint",
                data: Object.values(fpCounts),
                backgroundColor: ["#00ff88", "#009955", "#44ffbb", "#008844"]
            }]
        }
    });
}


// --------------------------
// AUTO-REFRESH EVERY 5 SEC
// --------------------------
async function refreshDashboard() {
    await updateLogTable();
    await updateAlertTable();
    await updateRiskTable();
    await drawCharts();
}

refreshDashboard();
setInterval(refreshDashboard, 5000);




async function updateRiskTable() {
    const res = await fetch("/admin/risk/data");
    const data = await res.json();

    const tbody = document.querySelector("#riskTable tbody");
    tbody.innerHTML = "";

    data.forEach(row => {
        tbody.innerHTML += `
            <tr>
                <td>${row.username}</td>
                <td>${row.risk}</td>
                <td>${row.guesses}</td>
                <td>${row.cracked}</td>
            </tr>
        `;
    });
}
