/* ── Intrusion Detection JS ────────────────────────────────── */

let historyChart = null;
let logCount     = 0;
const historyData = { labels: [], normal: [], attack: [] };

const PRESETS = {
  normal:   { srcPort: 52341, dstPort: 443,   pkt: 512,   dur: 1.2, bytes: 1024, conns: 5,  proto: 1, flags: 18 },
  portscan: { srcPort: 12345, dstPort: 22,    pkt: 60,    dur: 0.1, bytes: 60,   conns: 200, proto: 1, flags: 2  },
  dos:      { srcPort: 9999,  dstPort: 80,    pkt: 65535, dur: 0.0, bytes: 99999,conns: 999, proto: 1, flags: 2  },
  ssh:      { srcPort: 43210, dstPort: 22,    pkt: 256,   dur: 0.5, bytes: 512,  conns: 50, proto: 1, flags: 60  },
};

function loadPreset(name) {
  const p = PRESETS[name];
  if (!p) return;
  document.getElementById('srcPort').value    = p.srcPort;
  document.getElementById('dstPort').value    = p.dstPort;
  document.getElementById('packetSize').value = p.pkt;
  document.getElementById('duration').value   = p.dur;
  document.getElementById('byteCount').value  = p.bytes;
  document.getElementById('connCount').value  = p.conns;
  document.getElementById('protocol').value   = p.proto;
  document.getElementById('flags').value      = p.flags;
}

function randomizeInputs() {
  document.getElementById('srcPort').value    = rnd(1024, 65535);
  document.getElementById('dstPort').value    = rnd(20, 9000);
  document.getElementById('packetSize').value = rnd(60, 1500);
  document.getElementById('duration').value   = (Math.random() * 10).toFixed(1);
  document.getElementById('byteCount').value  = rnd(60, 100000);
  document.getElementById('connCount').value  = rnd(1, 500);
  document.getElementById('protocol').value   = rnd(0, 1);
  document.getElementById('flags').value      = rnd(0, 63);
}

function rnd(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }

async function detectIntrusion() {
  const payload = {
    src_port:          +document.getElementById('srcPort').value,
    dst_port:          +document.getElementById('dstPort').value,
    packet_size:       +document.getElementById('packetSize').value,
    duration:          +document.getElementById('duration').value,
    byte_count:        +document.getElementById('byteCount').value,
    connection_count:  +document.getElementById('connCount').value,
    protocol:          +document.getElementById('protocol').value,
    flags:             +document.getElementById('flags').value,
  };

  try {
    const res  = await fetch('/api/detect-intrusion', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); return; }

    renderVerdict(data);
    updateHistoryChart(data);
    addLogRow(data, payload);
  } catch (e) {
    alert('Request failed: ' + e.message);
  }
}

function renderVerdict(data) {
  const card    = document.getElementById('verdictCard');
  const isAttack = data.prediction === 'ATTACK';

  card.innerHTML = `
    <div class="verdict-result">
      <div class="verdict-icon">${isAttack ? '⚠️' : '✅'}</div>
      <div class="verdict-label ${isAttack ? 'attack' : 'normal'}">${data.prediction}</div>
      <div class="severity-chip severity-${data.severity}">${data.severity} SEVERITY</div>
      <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:0.5rem">
        Confidence: <strong style="color:var(--text-primary)">${data.confidence}%</strong>
      </p>
      ${data.rule_triggered ? `<p class="verdict-rule"><i class="fas fa-triangle-exclamation"></i> ${data.rule_triggered}</p>` : ''}
      <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin-top:0.75rem;font-size:0.75rem;color:var(--text-muted)">
        <span>Protocol: <strong style="color:var(--text-primary)">${data.features.protocol}</strong></span>
        <span>Dst: <strong style="color:var(--text-primary)">${data.features.dst_port}</strong></span>
        <span>Pkt: <strong style="color:var(--text-primary)">${data.features.packet_size}B</strong></span>
      </div>
    </div>
  `;
  card.style.borderColor = isAttack ? 'rgba(239,68,68,0.4)' : 'rgba(16,185,129,0.3)';

  // Confidence meter
  const confVal = document.getElementById('confValue');
  const confBar = document.getElementById('confBar');
  if (confVal) confVal.textContent = data.confidence.toFixed(1) + '%';
  if (confBar) {
    confBar.style.width = data.confidence + '%';
    confBar.style.background = isAttack
      ? 'linear-gradient(90deg, #f59e0b, #ef4444)'
      : 'linear-gradient(90deg, #10b981, #00d4ff)';
  }
}

function updateHistoryChart(data) {
  const now = new Date().toLocaleTimeString('en-US', { hour12: false });
  historyData.labels.push(now);
  historyData.normal.push(data.prediction === 'NORMAL' ? data.confidence : 0);
  historyData.attack.push(data.prediction === 'ATTACK' ? data.confidence : 0);

  // Keep last 20 points
  if (historyData.labels.length > 20) {
    historyData.labels.shift();
    historyData.normal.shift();
    historyData.attack.shift();
  }

  const ctx = document.getElementById('intrusionChart')?.getContext('2d');
  if (!ctx) return;

  if (historyChart) {
    historyChart.data.labels              = historyData.labels;
    historyChart.data.datasets[0].data   = historyData.normal;
    historyChart.data.datasets[1].data   = historyData.attack;
    historyChart.update('none');
  } else {
    historyChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: historyData.labels,
        datasets: [
          {
            label: 'Normal confidence %',
            data: historyData.normal,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16,185,129,0.08)',
            fill: true, tension: 0.4, pointRadius: 5,
            pointBackgroundColor: '#10b981',
          },
          {
            label: 'Attack confidence %',
            data: historyData.attack,
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239,68,68,0.08)',
            fill: true, tension: 0.4, pointRadius: 5,
            pointBackgroundColor: '#ef4444',
          }
        ]
      },
      options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12 } } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' } },
          y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
      }
    });
  }

  const countEl = document.getElementById('historyCount');
  if (countEl) countEl.textContent = historyData.labels.length + ' analyses run';
}

function addLogRow(data, payload) {
  logCount++;
  const tbody = document.getElementById('logBody');
  const isAttack = data.prediction === 'ATTACK';

  const row = document.createElement('tr');
  row.style.animation = 'fade-in 0.3s ease';
  row.innerHTML = `
    <td style="color:var(--text-muted)">${logCount}</td>
    <td>${new Date().toLocaleTimeString()}</td>
    <td>${payload.src_port}</td>
    <td>${payload.dst_port}</td>
    <td>${payload.packet_size}</td>
    <td>${data.features.protocol}</td>
    <td class="verdict-cell ${isAttack ? 'attack' : 'normal'}">${data.prediction}</td>
    <td>${data.confidence.toFixed(1)}%</td>
  `;
  const oldEmpty = tbody.querySelector('td[colspan]');
  if (oldEmpty) tbody.innerHTML = '';
  tbody.insertBefore(row, tbody.firstChild);

  // Keep max 50 rows
  while (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
}

function clearLog() {
  logCount = 0;
  document.getElementById('logBody').innerHTML =
    '<tr><td colspan="8" style="text-align:center;color:var(--text-muted)">No analyses yet</td></tr>';
}