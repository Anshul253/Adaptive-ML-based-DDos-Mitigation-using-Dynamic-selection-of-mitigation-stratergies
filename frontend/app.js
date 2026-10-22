/* ============================================================
   app.js — AI-Based Adaptive DDoS Mitigation Dashboard Logic
   ============================================================ */

// ──────────────────────────────────────────────────
// Experiment Data (from results/experiment_results.csv)
// ──────────────────────────────────────────────────
const EXPERIMENT_DATA = [
  {mode:'baseline',attack:'udp',severity:'low',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:6.7,avg_rtt_ms:69,throughput_mbps:6.7,mitigation_response_time_sec:0.045,composite_score:50.61},
  {mode:'baseline',attack:'udp',severity:'medium',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:9.6,avg_rtt_ms:97,throughput_mbps:9.6,mitigation_response_time_sec:0.045,composite_score:48.22},
  {mode:'baseline',attack:'udp',severity:'high',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:14.4,avg_rtt_ms:117,throughput_mbps:14.4,mitigation_response_time_sec:0.045,composite_score:46.24},
  {mode:'baseline',attack:'syn',severity:'low',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:6.7,avg_rtt_ms:69,throughput_mbps:6.7,mitigation_response_time_sec:0.045,composite_score:50.61},
  {mode:'baseline',attack:'syn',severity:'medium',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:9.6,avg_rtt_ms:97,throughput_mbps:9.6,mitigation_response_time_sec:0.045,composite_score:48.22},
  {mode:'baseline',attack:'syn',severity:'high',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:14.4,avg_rtt_ms:117,throughput_mbps:14.4,mitigation_response_time_sec:0.045,composite_score:46.24},
  {mode:'baseline',attack:'icmp',severity:'low',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:6.7,avg_rtt_ms:69,throughput_mbps:6.7,mitigation_response_time_sec:0.045,composite_score:50.61},
  {mode:'baseline',attack:'icmp',severity:'medium',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:9.6,avg_rtt_ms:97,throughput_mbps:9.6,mitigation_response_time_sec:0.045,composite_score:48.22},
  {mode:'baseline',attack:'icmp',severity:'high',accuracy:98,precision:97.06,recall:99,f1_score:98.02,attack_packets_served_percent:5,legitimate_packet_loss_percent:42,network_load_percent:14.4,avg_rtt_ms:117,throughput_mbps:14.4,mitigation_response_time_sec:0.045,composite_score:46.24},
  {mode:'adaptive',attack:'udp',severity:'low',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:15,legitimate_packet_loss_percent:3,network_load_percent:8.1,avg_rtt_ms:22,throughput_mbps:8.1,mitigation_response_time_sec:0.001,composite_score:66.09},
  {mode:'adaptive',attack:'udp',severity:'medium',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:3,legitimate_packet_loss_percent:4,network_load_percent:8.64,avg_rtt_ms:16,throughput_mbps:8.64,mitigation_response_time_sec:0.001,composite_score:70.29},
  {mode:'adaptive',attack:'udp',severity:'high',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:1,legitimate_packet_loss_percent:6,network_load_percent:9.28,avg_rtt_ms:12,throughput_mbps:9.28,mitigation_response_time_sec:0.001,composite_score:70.42},
  {mode:'adaptive',attack:'syn',severity:'low',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:15,legitimate_packet_loss_percent:3,network_load_percent:8.1,avg_rtt_ms:22,throughput_mbps:8.1,mitigation_response_time_sec:0.001,composite_score:66.09},
  {mode:'adaptive',attack:'syn',severity:'medium',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:3,legitimate_packet_loss_percent:4,network_load_percent:8.64,avg_rtt_ms:16,throughput_mbps:8.64,mitigation_response_time_sec:0.001,composite_score:70.29},
  {mode:'adaptive',attack:'syn',severity:'high',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:1,legitimate_packet_loss_percent:6,network_load_percent:9.28,avg_rtt_ms:12,throughput_mbps:9.28,mitigation_response_time_sec:0.001,composite_score:70.42},
  {mode:'adaptive',attack:'icmp',severity:'low',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:15,legitimate_packet_loss_percent:3,network_load_percent:8.1,avg_rtt_ms:22,throughput_mbps:8.1,mitigation_response_time_sec:0.001,composite_score:66.09},
  {mode:'adaptive',attack:'icmp',severity:'medium',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:3,legitimate_packet_loss_percent:4,network_load_percent:8.64,avg_rtt_ms:16,throughput_mbps:8.64,mitigation_response_time_sec:0.001,composite_score:70.29},
  {mode:'adaptive',attack:'icmp',severity:'high',accuracy:98,precision:98.98,recall:97,f1_score:97.98,attack_packets_served_percent:1,legitimate_packet_loss_percent:6,network_load_percent:9.28,avg_rtt_ms:12,throughput_mbps:9.28,mitigation_response_time_sec:0.001,composite_score:70.42},
];

// ──────────────────────────────────────────────────
// Adaptive Decision Engine Logic (mirrored from Python)
// ──────────────────────────────────────────────────
const THRESHOLDS = {
  low_pps: 5000, high_pps: 20000,
  low_load: 40, high_load: 75,
  high_conf: 0.85, mod_conf: 0.60
};

function computeDecision(isDDoS, confidence, pps, netLoad, legitRate) {
  if (!isDDoS) return { strategy: 'NO_ACTION', reason: 'Traffic classified as normal flow. No mitigation required.', cls: 'safe' };
  if ((confidence >= THRESHOLDS.high_conf && (pps >= THRESHOLDS.high_pps || netLoad >= THRESHOLDS.high_load)) || (netLoad >= 85 && confidence >= THRESHOLDS.mod_conf)) {
    return { strategy: 'DYNAMIC_BLOCKING', reason: `High attack confidence (${(confidence*100).toFixed(1)}%) with severe intensity (${pps.toLocaleString()} pps) / net load (${netLoad.toFixed(0)}%). Immediate DROP rule installed.`, cls: 'blocking' };
  }
  if (netLoad >= THRESHOLDS.high_load || (pps >= THRESHOLDS.low_pps && netLoad >= THRESHOLDS.low_load)) {
    return { strategy: 'CONTROLLER_MIGRATION', reason: `High congestion (${netLoad.toFixed(0)}%) with medium flood (${pps.toLocaleString()} pps). Rate limiting avoided; redirecting to safe inspection proxy.`, cls: 'migration' };
  }
  if (pps < THRESHOLDS.high_pps && netLoad < THRESHOLDS.high_load) {
    return { strategy: 'RATE_LIMITING', reason: `Moderate attack (${pps.toLocaleString()} pps), low congestion (${netLoad.toFixed(0)}%). Capping flow rate to preserve legitimate traffic.`, cls: 'ratelimit' };
  }
  return { strategy: 'DYNAMIC_BLOCKING', reason: 'Fallback: DDoS detected — applying DROP rule.', cls: 'blocking' };
}

// ──────────────────────────────────────────────────
// Simulation State
// ──────────────────────────────────────────────────
let simRunning = false;
let simInterval = null;
let currentMode = 'adaptive';
let currentAttack = 'udp';
let currentSeverity = 'medium';
let liveChart = null;
let chartLabels = [];
let chartAttack = [], chartLegit = [], chartRTT = [];

// Per-severity simulation parameters
const SIM_PARAMS = {
  low:    { pps: 3500, netLoad: 30, legitPps: 1500, legitLoss: { baseline: 42, adaptive: 3 }, atkServed: { baseline: 5, adaptive: 15 }, rtt: { baseline: 69, adaptive: 22 }, score: { baseline: 50.61, adaptive: 66.09 } },
  medium: { pps: 12000, netLoad: 65, legitPps: 1800, legitLoss: { baseline: 42, adaptive: 4 }, atkServed: { baseline: 5, adaptive: 3 }, rtt: { baseline: 97, adaptive: 16 }, score: { baseline: 48.22, adaptive: 70.29 } },
  high:   { pps: 32000, netLoad: 90, legitPps: 2000, legitLoss: { baseline: 42, adaptive: 6 }, atkServed: { baseline: 5, adaptive: 1 }, rtt: { baseline: 117, adaptive: 12 }, score: { baseline: 46.24, adaptive: 70.42 } },
};

// ──────────────────────────────────────────────────
// Smooth Counter Animation
// ──────────────────────────────────────────────────
function animateCounter(el, target, decimals = 0, duration = 1200) {
  const start = performance.now();
  const startVal = parseFloat(el.textContent) || 0;
  function update(now) {
    const t = Math.min((now - start) / duration, 1);
    const ease = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
    const val = startVal + (target - startVal) * ease;
    el.textContent = val.toFixed(decimals);
    if (t < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// ──────────────────────────────────────────────────
// Live Chart Init
// ──────────────────────────────────────────────────
function initLiveChart() {
  const ctx = document.getElementById('liveChart').getContext('2d');
  if (liveChart) liveChart.destroy();
  chartLabels = []; chartAttack = []; chartLegit = []; chartRTT = [];
  liveChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: chartLabels,
      datasets: [
        { label: 'Attack Traffic (pps)', data: chartAttack, borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)', tension: 0.4, fill: true, pointRadius: 2 },
        { label: 'Legitimate Traffic (pps)', data: chartLegit, borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.08)', tension: 0.4, fill: true, pointRadius: 2 },
        { label: 'RTT (ms)', data: chartRTT, borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.06)', tension: 0.4, fill: false, yAxisID: 'y2', pointRadius: 2 },
      ]
    },
    options: {
      responsive: true, animation: { duration: 250 },
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' }, title: { display: true, text: 'pps', color: '#64748b', font: { size: 10 } } },
        y2: { position: 'right', ticks: { color: '#6366f1', font: { size: 10 } }, grid: { display: false }, title: { display: true, text: 'ms', color: '#6366f1', font: { size: 10 } } },
      }
    }
  });
}

// ──────────────────────────────────────────────────
// Simulation Step
// ──────────────────────────────────────────────────
let simTick = 0;
function simulationStep() {
  const params = SIM_PARAMS[currentSeverity];
  const jitter = () => (Math.random() - 0.5) * 0.12;

  const attackPps = params.pps * (1 + jitter());
  const netLoad = Math.min(100, params.netLoad * (1 + jitter()));
  const legitPps = params.legitPps * (1 + jitter() * 0.5);
  const legitLoss = params.legitLoss[currentMode];
  const atkServed = params.atkServed[currentMode];
  const rtt = params.rtt[currentMode] * (1 + jitter() * 0.2);
  const score = params.score[currentMode];

  const isDDoS = true;
  const confidence = currentSeverity === 'high' ? 0.96 : currentSeverity === 'medium' ? 0.88 : 0.76;
  const decision = currentMode === 'adaptive'
    ? computeDecision(isDDoS, confidence, attackPps, netLoad, legitPps)
    : { strategy: 'DYNAMIC_BLOCKING', reason: 'Baseline mode: Fixed aggressive port blocking applied to all detected DDoS sources.', cls: 'blocking' };

  // Update Metrics
  setMetric('ppsVal', attackPps.toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, ','), 'ppsBar', Math.min(100, (attackPps / 50000) * 100));
  setMetric('netLoadVal', netLoad.toFixed(1) + '%', 'netLoadBar', netLoad);
  setMetric('legitLossVal', legitLoss.toFixed(1) + '%', 'legitLossBar', Math.min(100, legitLoss * 2));
  setMetric('rttVal', rtt.toFixed(1) + ' ms', 'rttBar', Math.min(100, (rtt / 150) * 100));
  setMetric('attackServedVal', atkServed.toFixed(1) + '%', 'attackServedBar', atkServed * 2);
  setMetric('scoreVal', score.toFixed(1), 'scoreBar', score);

  // Decision Banner
  const banner = document.getElementById('decisionBanner');
  const stratEl = document.getElementById('strategyBadge');
  banner.className = 'decision-banner ' + decision.cls;
  document.getElementById('decisionTitle').textContent = `Attack Detected — ${decision.strategy.replace(/_/g,' ')}`;
  document.getElementById('decisionReason').textContent = decision.reason;
  stratEl.textContent = decision.strategy.replace(/_/g,' ');
  stratEl.className = 'strategy-badge ' + decision.strategy;

  // Live Chart
  simTick++;
  if (chartLabels.length > 25) { chartLabels.shift(); chartAttack.shift(); chartLegit.shift(); chartRTT.shift(); }
  chartLabels.push(simTick + 's');
  chartAttack.push(Math.round(attackPps));
  chartLegit.push(Math.round(legitPps * (1 - legitLoss / 100)));
  chartRTT.push(parseFloat(rtt.toFixed(1)));
  liveChart.update();
}

function setMetric(valId, val, barId, pct) {
  document.getElementById(valId).textContent = val;
  document.getElementById(barId).style.width = Math.min(100, pct).toFixed(1) + '%';
}

// ──────────────────────────────────────────────────
// Controls
// ──────────────────────────────────────────────────
function startSimulation() {
  if (simRunning) {
    clearInterval(simInterval);
    simRunning = false;
    document.getElementById('simBtn').innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Start';
    return;
  }
  simRunning = true;
  simTick = 0;
  initLiveChart();
  document.getElementById('simBtn').innerHTML = '⏹ Stop';
  simInterval = setInterval(simulationStep, 1000);
  simulationStep();
}

function setMode(mode) {
  currentMode = mode;
  document.getElementById('modeBaseline').classList.toggle('active', mode === 'baseline');
  document.getElementById('modeAdaptive').classList.toggle('active', mode === 'adaptive');
}

// Toggle button groups
document.querySelectorAll('#attackTypeGroup .btn-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#attackTypeGroup .btn-toggle').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentAttack = btn.dataset.value;
  });
});
document.querySelectorAll('#severityGroup .btn-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#severityGroup .btn-toggle').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentSeverity = btn.dataset.value;
  });
});

// ──────────────────────────────────────────────────
// Comparison Section
// ──────────────────────────────────────────────────
const METRICS_TABLE = [
  { label: 'Legitimate Packet Loss (%)', key: 'legitimate_packet_loss_percent', lower: true },
  { label: 'Attack Packets Served (%)', key: 'attack_packets_served_percent', lower: true },
  { label: 'Network Load (%)', key: 'network_load_percent', lower: true },
  { label: 'Avg RTT / Latency (ms)', key: 'avg_rtt_ms', lower: true },
  { label: 'Throughput (Mbps)', key: 'throughput_mbps', lower: false },
  { label: 'Mitigation Response Time (s)', key: 'mitigation_response_time_sec', lower: true },
  { label: 'Detection F1-Score (%)', key: 'f1_score', lower: false },
  { label: 'Adaptive Performance Score', key: 'composite_score', lower: false },
];

let compCharts = {};

function avg(arr, key) {
  if (!arr.length) return 0;
  return arr.reduce((s, r) => s + r[key], 0) / arr.length;
}

function updateComparison() {
  const atk = document.getElementById('filterAttack').value;
  const sev = document.getElementById('filterSeverity').value;
  const filter = r => (atk === 'all' || r.attack === atk) && (sev === 'all' || r.severity === sev);
  const baseline = EXPERIMENT_DATA.filter(r => r.mode === 'baseline' && filter(r));
  const adaptive = EXPERIMENT_DATA.filter(r => r.mode === 'adaptive' && filter(r));

  // Table
  const tbody = document.getElementById('resultsTableBody');
  tbody.innerHTML = '';
  METRICS_TABLE.forEach(m => {
    const bv = avg(baseline, m.key);
    const av = avg(adaptive, m.key);
    const diff = m.lower ? bv - av : av - bv;
    const better = diff > 0.01;
    const worse = diff < -0.01;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td-metric">${m.label}</td>
      <td class="td-baseline">${bv.toFixed(2)}</td>
      <td class="td-adaptive">${av.toFixed(2)}</td>
      <td class="td-improvement ${better ? 'better' : worse ? 'worse' : 'neutral'}">${diff >= 0 ? '+' : ''}${diff.toFixed(2)}</td>
      <td><span class="badge-better ${better ? 'up' : worse ? 'down' : 'eq'}">${better ? '✅ Better' : worse ? '⚠️ Trade-off' : '— Same'}</span></td>
    `;
    tbody.appendChild(tr);
  });

  // Mini charts
  renderMiniChart('lossChart', 'Legitimate Packet Loss (%)', baseline, adaptive, 'legitimate_packet_loss_percent', '#ef4444', '#10b981');
  renderMiniChart('attackChart', 'Attack Packets Served (%)', baseline, adaptive, 'attack_packets_served_percent', '#f59e0b', '#06b6d4');
  renderMiniChart('rttChart', 'Avg RTT (ms)', baseline, adaptive, 'avg_rtt_ms', '#f87171', '#34d399');
  renderMiniChart('scoreChart', 'Adaptive Score', baseline, adaptive, 'composite_score', '#818cf8', '#22d3ee');
}

function renderMiniChart(id, label, baseline, adaptive, key, bcol, acol) {
  const ctx = document.getElementById(id).getContext('2d');
  if (compCharts[id]) compCharts[id].destroy();
  const labels = baseline.map(r => `${r.attack.toUpperCase()} ${r.severity}`);
  const bdata = baseline.map(r => r[key]);
  const adata = adaptive.map(r => r[key]);
  compCharts[id] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'Baseline', data: bdata, backgroundColor: bcol + '88', borderColor: bcol, borderWidth: 1.5, borderRadius: 4 },
        { label: 'Adaptive', data: adata, backgroundColor: acol + '88', borderColor: acol, borderWidth: 1.5, borderRadius: 4 },
      ]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#94a3b8', font: { size: 10 } } } },
      scales: {
        x: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
      }
    }
  });
}

// ──────────────────────────────────────────────────
// Decision Engine Simulator
// ──────────────────────────────────────────────────
function updateDecision() {
  const confidence = parseFloat(document.getElementById('confSlider').value);
  const pps = parseInt(document.getElementById('ppsSlider').value);
  const netLoad = parseInt(document.getElementById('loadSlider').value);
  const legitRate = parseInt(document.getElementById('legitSlider').value);
  const isDDoS = parseInt(document.getElementById('attackSlider').value) === 1;

  document.getElementById('confVal').textContent = confidence.toFixed(2);
  document.getElementById('ppsSliderVal').textContent = pps.toLocaleString();
  document.getElementById('loadVal').textContent = netLoad;
  document.getElementById('legitVal').textContent = legitRate.toLocaleString();
  document.getElementById('attackDetectedLabel').textContent = isDDoS ? 'Yes' : 'No';

  const dec = computeDecision(isDDoS, confidence, pps, netLoad, legitRate);

  document.getElementById('drStrategy').textContent = dec.strategy.replace(/_/g,' ');
  document.getElementById('drReason').textContent = dec.reason;
  document.getElementById('decisionResultCard').className = 'decision-result-card ' + dec.cls;

  // Bars
  document.getElementById('drConfBar').style.width = (confidence * 100).toFixed(0) + '%';
  document.getElementById('drConfText').textContent = (confidence * 100).toFixed(0) + '%';
  document.getElementById('drPpsBar').style.width = Math.min(100, (pps / 50000) * 100).toFixed(0) + '%';
  document.getElementById('drPpsText').textContent = pps.toLocaleString() + ' pps';
  document.getElementById('drLoadBar').style.width = netLoad + '%';
  document.getElementById('drLoadText').textContent = netLoad + '%';

  // Badge labels
  const confHigh = confidence >= THRESHOLDS.high_conf;
  const ppsHigh = pps >= THRESHOLDS.high_pps;
  const loadHigh = netLoad >= THRESHOLDS.high_load;
  const setB = (id, icon, label, ok) => { document.getElementById(id).textContent = (ok ? '🔴 ' : '🟢 ') + label; };
  setB('drb1', '', 'High Confidence', confHigh);
  setB('drb2', '', 'High Intensity', ppsHigh);
  setB('drb3', '', 'High Congestion', loadHigh);
}

// ──────────────────────────────────────────────────
// Scroll helpers & navbar active link
// ──────────────────────────────────────────────────
function scrollTo(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
}

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    link.classList.add('active');
    const target = link.getAttribute('href').slice(1);
    document.getElementById(target)?.scrollIntoView({ behavior: 'smooth' });
  });
});

// ──────────────────────────────────────────────────
// Init on load
// ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initLiveChart();
  updateComparison();
  updateDecision();
});
