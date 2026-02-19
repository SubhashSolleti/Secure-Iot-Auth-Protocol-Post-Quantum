const API_BASE = "/api";
const WS_URL = `ws://${window.location.host}/ws/logs`;

// DOM Elements
const logWindow = document.getElementById('log-window');
const serverStatus = document.getElementById('server-status');
const telemetryDisplay = document.getElementById('telemetry-display');
const steps = document.querySelectorAll('.step');

// Stats state
let handshakes = 0;
let resumptions = 0;
let latencies = [];

// WebSocket
let ws;

function connectWS() {
    ws = new WebSocket(WS_URL);

    ws.onmessage = (event) => {
        const log = JSON.parse(event.data);
        renderLog(log);
        processLogEvent(log);
    };

    ws.onclose = () => {
        setTimeout(connectWS, 1000);
    };
}

// Log Rendering
function renderLog(log) {
    const el = document.createElement('div');
    el.className = 'log-entry';

    const time = log.timestamp ? log.timestamp.split('T')[1].split('.')[0] : '--:--:--';
    const sourceClass = log.logger === 'client' ? 'logger-client' : 'logger-server';

    // Highlight key info
    let message = log.event || log.message || JSON.stringify(log);

    el.innerHTML = `
        <span class="ts">${time}</span>
        <span class="logger ${sourceClass}">${log.logger}</span>
        <span class="log-event">${message}</span>
    `;

    // Append extra keys if interesting
    if (log.latency_ms) el.innerHTML += ` <span style="color:#fbbf24">${log.latency_ms}ms</span>`;
    if (log.reason) el.innerHTML += ` <span style="color:#ef4444">${log.reason}</span>`;

    logWindow.appendChild(el);
    logWindow.scrollTop = logWindow.scrollHeight;
}

// Event Processing (Logic to drive the UI visualizer)
function processLogEvent(log) {
    // 1. Highlight Flow Steps
    if (log.event === 'connection_accepted') activateStep('hello');
    if (log.event === 'connected') { document.getElementById('node-client').classList.add('active'); }

    // M1/M2 usually happen too fast to see individually without artificial delay,
    // but we light them up anyway.

    if (log.event === 'handshake_complete') {
        activateStep('m1');
        activateStep('m2');
        activateStep('m4');
        activateStep('m5');
        activateStep('hash');

        // Update stats
        handshakes++;
        document.getElementById('stat-handshakes').innerText = handshakes;
        if (log.latency_ms) {
            latencies.push(log.latency_ms);
            const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;
            document.getElementById('stat-latency').innerText = avg.toFixed(1) + 'ms';
        }

        // Visuals
        document.getElementById('conn-line').classList.add('connected');
    }

    if (log.event === 'session_resumed') {
        resumptions++;
        document.getElementById('stat-resumptions').innerText = resumptions;
        // Skip straight to stream
        steps.forEach(s => s.classList.remove('active'));
    }

    if (log.event === 'sensor_data_received') {
        activateStep('stream');
        renderTelemetry(log.data);
    }

    if (log.event === 'server_listening') {
        serverStatus.innerText = "ONLINE";
        serverStatus.classList.remove('offline');
        serverStatus.classList.add('online');
        document.getElementById('node-server').classList.add('active');
    }
}

function activateStep(stepName) {
    const el = document.querySelector(`.step[data-step="${stepName}"]`);
    if (el) {
        el.classList.add('active');
        setTimeout(() => el.classList.remove('active'), 1500);
    }
}

function renderTelemetry(data) {
    const el = document.createElement('div');
    el.className = 'telemetry-item';
    el.innerHTML = `
        <h4>Packet #${data.seq}</h4>
        <div class="telemetry-val"><span>Temp</span> <span>${data.temperature_c}°C</span></div>
        <div class="telemetry-val"><span>Humidity</span> <span>${data.humidity_pct}%</span></div>
        <div class="telemetry-val"><span>Battery</span> <span>${data.battery_v}V</span></div>
    `;
    telemetryDisplay.prepend(el);
    if (telemetryDisplay.children.length > 20) telemetryDisplay.lastChild.remove();
}

// Controls
document.getElementById('btn-start-server').onclick = async () => {
    await fetch(API_BASE + '/server/start', { method: 'POST' });
};

document.getElementById('btn-stop-server').onclick = async () => {
    await fetch(API_BASE + '/server/stop', { method: 'POST' });
    serverStatus.innerText = "OFFLINE";
    serverStatus.classList.remove('online');
    serverStatus.classList.add('offline');
    document.getElementById('node-server').classList.remove('active');
    document.getElementById('conn-line').classList.remove('connected');
};

document.getElementById('btn-connect-client').onclick = async () => {
    document.getElementById('node-client').classList.add('active');
    await fetch(API_BASE + '/client/start', { method: 'POST' });
    setTimeout(() => {
        document.getElementById('node-client').classList.remove('active');
        document.getElementById('conn-line').classList.remove('connected');
    }, 2000 + (5000)); // ~stream duration
};

document.getElementById('btn-reset-state').onclick = async () => {
    await fetch(API_BASE + '/reset_state', { method: 'POST' });
    alert('Device state & pinned keys reset!');
    handshakes = 0; resumptions = 0; latencies = [];
    document.getElementById('stat-handshakes').innerText = 0;
};

document.getElementById('btn-clear-logs').onclick = () => {
    logWindow.innerHTML = '';
};

// Init
connectWS();
