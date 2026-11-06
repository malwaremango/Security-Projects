
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 17 12:10:04 2026

@author: usah5
"""

HTML = """

<!DOCTYPE html>
<html lang="no">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Solar Park SCADA Security Monitor</title>

<style>

@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #10151a;
    --panel: #171e24;
    --panel-dark: #12181d;

    --border: #35414a;
    --border-light: #46535d;

    --text: #d5dde2;
    --muted: #82909a;

    --green: #55c97a;
    --yellow: #e0b94f;
    --red: #e05252;
    --orange: #d88b45;

    --neon-blue: #00b7ff;

    --grid: rgba(255,255,255,0.025);
}


/* Grunnoppsett */

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 18px 22px;

    background:
        linear-gradient(var(--grid) 1px, transparent 1px),
        linear-gradient(90deg, var(--grid) 1px, transparent 1px),
        var(--bg);

    background-size: 24px 24px;

    color: var(--text);

    font-family:
        "IBM Plex Mono",
        "Courier New",
        monospace;

    font-size: 13px;
}


/* Toppmenyen */

.top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;

    min-height: 62px;

    padding: 10px 14px;

    background: #141b20;

    border: 1px solid var(--border);
    border-bottom: 2px solid #4b5963;

    margin-bottom: 16px;
}


/* Navnet på SCADA-systemet */

h1 {
    margin: 0;

    font-size: 17px;
    font-weight: 600;

    letter-spacing: 0.3px;

    color: #7fc7df;

    text-shadow:
        0 0 4px rgba(0, 183, 255, 0.25);
}

.subtitle {
    margin-top: 6px;

    color: var(--muted);

    font-size: 11px;
    letter-spacing: 0.2px;
}

.top-bar > div:last-child {
    text-align: right;
    padding-left: 30px;
}


/* Overskrifter for de ulike delene */

.section {
    margin-bottom: 16px;
}

.section-title {
    display: flex;
    align-items: center;

    margin-bottom: 7px;

    color: #aeb9c0;

    font-size: 11px;
    font-weight: 600;

    text-transform: uppercase;

    letter-spacing: 1.2px;
}

.section-title::before {
    content: "";

    display: inline-block;

    width: 5px;
    height: 12px;

    margin-right: 7px;

    background: #687780;
}


/* Temperatur og produksjon */

.overview-display {
    display: grid;

    grid-template-columns: 1fr 1fr;

    gap: 12px;

    margin-bottom: 16px;
}

.hero-stat {
    position: relative;

    padding: 14px 18px;

    min-height: 100px;

    background:
        linear-gradient(
            135deg,
            rgba(255,255,255,0.025),
            transparent
        ),
        var(--panel);

    border: 1px solid var(--border);

    border-left: 4px solid var(--neon-blue);
}


/* Teksten over måleverdiene */

.hero-stat .label {
    margin-bottom: 8px;

    color: var(--muted);

    font-size: 10px;

    text-transform: uppercase;

    letter-spacing: 1px;
}


/* De store verdiene på dashboardet */

.hero-stat .value {
    font-family: "IBM Plex Mono", monospace;

    font-size: 38px;

    line-height: 1;

    font-weight: 500;

    color: var(--neon-blue);

    text-shadow:
        0 0 5px rgba(0, 183, 255, 0.7),
        0 0 12px rgba(0, 183, 255, 0.35);
}


/* Enheter som °C og MW */

.hero-stat .unit {
    margin-left: 7px;

    font-size: 15px;

    color: var(--neon-blue);

    text-shadow:
        0 0 5px rgba(0, 183, 255, 0.6);
}


/* Farger for systemstatus */

.status-text {
    font-family: "IBM Plex Mono", monospace;

    font-size: 11px;

    font-weight: 600;

    letter-spacing: 0.5px;
}

.status-text::before {
    content: "●";

    margin-right: 5px;

    font-size: 8px;
}

.status-text.online {
    color: var(--green);
}

.status-text.offline {
    color: var(--red);
}

.status-text.suspicious {
    color: var(--yellow);
}

.status-text.compromised {
    color: var(--red);
}


/* Enkel oversikt over OT-systemet */

.architecture {
    display: flex;

    align-items: center;

    min-height: 65px;

    padding: 10px 14px;

    background: #151c21;

    border: 1px solid var(--border);

    overflow-x: auto;
}

.node {
    position: relative;

    min-width: 115px;

    padding: 10px 13px;

    text-align: center;

    background: #1b2329;

    border: 1px solid #46535d;

    color: #c8d1d6;

    font-size: 11px;

    font-weight: 500;

    text-transform: uppercase;
}

.arrow {
    padding: 0 8px;

    color: #65747e;

    font-size: 16px;
}


/* Status for de forskjellige komponentene */

.component-grid {
    display: grid;

    grid-template-columns:
        repeat(5, minmax(150px, 1fr));

    gap: 8px;
}

.component-box {
    position: relative;

    min-height: 125px;

    padding: 12px;

    background: var(--panel);

    border: 1px solid var(--border);

    border-top: 3px solid #46535d;

    transition: border-color 0.2s;
}

.component-box:hover {
    border-color: var(--border-light);
}

.component-box h3 {
    margin: 0 0 13px 0;

    color: #d7dfe3;

    font-size: 12px;

    font-weight: 600;

    text-transform: uppercase;

    letter-spacing: 0.6px;
}

.component-box p {
    margin: 7px 0;

    color: var(--muted);

    font-size: 11px;
}

.component-box strong {
    color: #d5dde2;

    font-weight: 500;
}

.component-box .small {
    margin-top: 12px;

    color: #687780;
}


/* Loggen viser sikkerhetshendelser */

.alert-container {
    min-height: 150px;

    max-height: 220px;

    padding: 4px;

    overflow-y: auto;

    background: #0d1216;

    border: 1px solid var(--border);

    scrollbar-width: thin;

    scrollbar-color: #4a565f #10151a;
}

.alert {
    display: block;

    padding: 7px 10px;

    margin-bottom: 2px;

    background: #141b20;

    border-left: 3px solid #53616b;

    color: #aeb9c0;

    font-family: "IBM Plex Mono", monospace;

    font-size: 10px;

    line-height: 1.5;
}

.alert.ALERT {
    border-left-color: var(--yellow);

    background:
        linear-gradient(
            90deg,
            rgba(224,185,79,0.08),
            transparent
        );

    color: #d8c986;
}

.alert.CRITICAL {
    border-left-color: var(--red);

    background:
        linear-gradient(
            90deg,
            rgba(224,82,82,0.10),
            transparent
        );

    color: #e6aaaa;
}


/* Scrollbaren */

::-webkit-scrollbar {
    width: 7px;
    height: 7px;
}

::-webkit-scrollbar-track {
    background: #10151a;
}

::-webkit-scrollbar-thumb {
    background: #46535d;

    border: 1px solid #10151a;
}

::-webkit-scrollbar-thumb:hover {
    background: #5c6b75;
}


/* Tilpasser dashboardet til mindre skjermer */

@media (max-width: 1100px) {

    .component-grid {
        grid-template-columns:
            repeat(3, 1fr);
    }
}

@media (max-width: 750px) {

    body {
        padding: 10px;
    }

    .top-bar {
        align-items: flex-start;

        flex-direction: column;

        gap: 10px;
    }

    .top-bar > div:last-child {
        text-align: left;

        padding-left: 0;
    }

    .overview-display {
        grid-template-columns: 1fr;
    }

    .component-grid {
        grid-template-columns: 1fr 1fr;
    }

    .architecture {
        justify-content: flex-start;
    }
}

@media (max-width: 500px) {

    .component-grid {
        grid-template-columns: 1fr;
    }
}

</style>


<script>


/* Oppdaterer fargen på statusfeltet */

function updateStatusClasses(elementId, statusText) {

    const el = document.getElementById(elementId);

    if (!el) return;

    el.innerText = statusText;

    el.className = "status-text";

    const status = statusText.toLowerCase();

    if (status === "online" || status === "normal") {

        el.classList.add("online");

    } else if (status === "offline") {

        el.classList.add("offline");

    } else if (status === "suspicious") {

        el.classList.add("suspicious");

    } else if (status === "compromised") {

        el.classList.add("compromised");
    }
}


/* Henter nye data fra Flask-serveren */

async function updateDashboard() {

    try {

        const response = await fetch("/data");

        const data = await response.json();


        // Oppdaterer statusen øverst

        updateStatusClasses(
            "status",
            data.status
        );


        // Temperatur og produksjon

        document.getElementById("temperature").innerText =
            data.temperature;

        document.getElementById("power").innerText =
            data.power_mw;


        // PV-paneler

        updateStatusClasses(
            "pv-status",
            data.pv_panels.status
        );

        document.getElementById("pv-temp").innerText =
            data.pv_panels.temperature + " °C";


        // Inverter

        updateStatusClasses(
            "inverter-status",
            data.inverter.status
        );

        document.getElementById("inverter-power").innerText =
            data.inverter.output_mw + " MW";


        // PLC

        updateStatusClasses(
            "plc-status",
            data.plc.status
        );

        document.getElementById("plc-value").innerText =
            data.plc.value;


        // SCADA-server

        updateStatusClasses(
            "scada-status",
            data.scada.status
        );


        // Nettverket

        updateStatusClasses(
            "network-status",
            data.network.status
        );


        // Oppdaterer listen med sikkerhetshendelser

        const alertsDiv =
            document.getElementById("alerts");

        alertsDiv.innerHTML = "";


        if (data.alerts.length === 0) {

            alertsDiv.innerHTML =
                "<p class='small' style='padding:10px;'>No security events detected.</p>";
        }


        data.alerts.forEach(alert => {

            const div =
                document.createElement("div");

            div.className =
                "alert " + alert.level;

            div.textContent =
                `[${alert.timestamp}] [${alert.level}] ${alert.message}`;

            alertsDiv.appendChild(div);

        });

    } catch (e) {

        console.error(
            "Kunne ikke hente data",
            e
        );

    }
}


/* Oppdaterer dashboardet hvert sekund */

setInterval(
    updateDashboard,
    1000
);

window.onload =
    updateDashboard;

</script>

</head>


<body>


<!-- Toppdelen av dashboardet -->

<div class="top-bar">

    <div>

        <h1>
            SOLAR PARK SCADA & OT SECURITY MONITOR
        </h1>

        <div class="subtitle">

            SCADA-01 |
            OT NETWORK |
            REAL-TIME TELEMETRY |
            INTRUSION DETECTION

        </div>

    </div>


    <div>

        <span class="small">
            SYSTEM STATUS:
        </span>

        <span
            id="status"
            class="status-text compromised">

            COMPROMISED

        </span>

    </div>

</div>



<!-- Måleverdier for solparken -->

<div class="section">

    <div class="section-title">
        SYSTEM TELEMETRY
    </div>


    <div class="overview-display">


        <div class="hero-stat">

            <div class="label">
                PV TEMPERATURE
            </div>

            <div class="value">

                <span id="temperature">
                    23.9
                </span>

                <span class="unit">
                    °C
                </span>

            </div>

        </div>


        <div class="hero-stat">

            <div class="label">
                SOLAR PRODUCTION
            </div>

            <div class="value">

                <span id="power">
                    4.26
                </span>

                <span class="unit">
                    MW
                </span>

            </div>

        </div>

    </div>

</div>



<!-- Viser hvordan komponentene henger sammen -->

<div class="section">

    <div class="section-title">
        OT ARCHITECTURE
    </div>


    <div class="architecture">

        <div class="node">
            PV PANELS
        </div>

        <div class="arrow">
            →
        </div>

        <div class="node">
            INVERTER
        </div>

        <div class="arrow">
            →
        </div>

        <div class="node">
            PLC
        </div>

        <div class="arrow">
            →
        </div>

        <div class="node">
            MODBUS TCP
        </div>

        <div class="arrow">
            →
        </div>

        <div class="node">
            SCADA
        </div>

    </div>

</div>



<!-- Status på de viktigste komponentene -->

<div class="section">

    <div class="section-title">
        COMPONENT STATUS
    </div>


    <div class="component-grid">


        <div class="component-box">

            <h3>
                PV PANELS
            </h3>

            <p>
                Status:
                <span
                    id="pv-status"
                    class="status-text online">

                    ONLINE

                </span>
            </p>

            <p>
                Temperature:
                <strong id="pv-temp">
                    23.9 °C
                </strong>
            </p>

        </div>


        <div class="component-box">

            <h3>
                INVERTER
            </h3>

            <p>
                Status:
                <span
                    id="inverter-status"
                    class="status-text offline">

                    OFFLINE

                </span>
            </p>

            <p>
                Output:
                <strong id="inverter-power">
                    4.26 MW
                </strong>
            </p>

        </div>


        <div class="component-box">

            <h3>
                PLC
            </h3>

            <p>
                Status:
                <span
                    id="plc-status"
                    class="status-text online">

                    ONLINE

                </span>
            </p>

            <p>
                Reg 40001:
                <strong id="plc-value">
                    999
                </strong>
            </p>

            <p class="small">
                IP: 192.168.10.20
            </p>

        </div>


        <div class="component-box">

            <h3>
                SCADA
            </h3>

            <p>
                Status:
                <span
                    id="scada-status"
                    class="status-text online">

                    ONLINE

                </span>
            </p>

            <p class="small">
                SCADA-01
            </p>

        </div>


        <div class="component-box">

            <h3>
                NETWORK
            </h3>

            <p>
                Protocol:
                <strong>
                    Modbus TCP
                </strong>
            </p>

            <p>
                Status:
                <span
                    id="network-status"
                    class="status-text suspicious">

                    SUSPICIOUS

                </span>
            </p>

        </div>


    </div>

</div>



<!-- Logg over sikkerhetshendelser -->

<div class="section">

    <div class="section-title">
        OT SECURITY ALERTS
    </div>


    <div
        class="alert-container"
        id="alerts">

        <p class="small" style="padding:10px;">
            Listening for simulated security events...
        </p>

    </div>

</div>


</body>
</html>


"""

def get_dashboard():
    return HTML
