/* ── Dashboard Charts & Live Data ──────────────────────────── */

/* Build 12-point fake activity timeline */
const labels = Array.from({ length: 12 }, (_, i) => {
  const d = new Date();
  d.setMinutes(d.getMinutes() - (11 - i) * 5);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
});

const rnd = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const intrusionData = labels.map(() => rnd(0, 3));
const anomalyData   = labels.map(() => rnd(0, 8));

/* Activity Line Chart */
const actCtx = document.getElementById('activityChart')?.getContext('2d');
if (actCtx) {
  new Chart(actCtx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Intrusions',
          data: intrusionData,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,0.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointBackgroundColor: '#ef4444',
          pointHoverRadius: 6,
        },
        {
          label: 'Anomalies',
          data: anomalyData,
          borderColor: '#f59e0b',
          backgroundColor: 'rgba(245,158,11,0.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointBackgroundColor: '#f59e0b',
          pointHoverRadius: 6,
        }
      ]
    },
    options: {
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true, ticks: { precision: 0 } }
      },
      animation: { duration: 800, easing: 'easeInOutQuart' }
    }
  });
}

/* Scan Distribution Doughnut */
const pieCtx = document.getElementById('pieChart')?.getContext('2d');
const scans    = parseInt(document.getElementById('statScans')?.textContent) || 0;
const intrusions = parseInt(document.getElementById('statIntrusions')?.textContent) || 0;
const anomalies  = parseInt(document.getElementById('statAnomalies')?.textContent) || 0;
const images     = parseInt(document.getElementById('statImages')?.textContent) || 0;
const normalScans = Math.max(0, scans - intrusions - anomalies);

if (pieCtx) {
  new Chart(pieCtx, {
    type: 'doughnut',
    data: {
      labels: ['Normal', 'Intrusions', 'Anomalies', 'Images'],
      datasets: [{
        data: [normalScans || 1, intrusions, anomalies, images],
        backgroundColor: [
          'rgba(16,185,129,0.7)',
          'rgba(239,68,68,0.7)',
          'rgba(245,158,11,0.7)',
          'rgba(37,99,235,0.7)',
        ],
        borderColor: [
          '#10b981', '#ef4444', '#f59e0b', '#3b82f6'
        ],
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12 } }
      },
      cutout: '65%',
      animation: { animateRotate: true, duration: 1000 }
    }
  });
}

/* Live refresh analytics counters */
async function refreshCounters() {
  try {
    const res = await fetch('/api/analytics');
    const data = await res.json();
    setEl('statScans',      data.total_scans);
    setEl('statIntrusions', data.intrusions_detected);
    setEl('statAnomalies',  data.anomalies_found);
    setEl('statImages',     data.images_analyzed);

    // Alert feed
    const feed = document.getElementById('dashAlertFeed');
    if (feed && data.alerts?.length) {
      feed.innerHTML = data.alerts.slice(0, 8).map(a => `
        <div class="alert-item ${a.type}">
          <span class="alert-time">${a.time}</span>
          <span class="alert-msg">${a.msg}</span>
          <span class="alert-type-badge ${a.type}">${a.type.toUpperCase()}</span>
        </div>
      `).join('');
    } else if (feed) {
      feed.innerHTML = `
        <div class="no-alerts-msg">
          <i class="fas fa-shield-check"></i>
          <p>No alerts detected. System is secure.</p>
        </div>`;
    }
  } catch (_) {}
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) {
    // Counter animation
    const current = parseInt(el.textContent) || 0;
    if (current !== val) animateCounter(el, current, val);
  }
}

function animateCounter(el, from, to) {
  const dur = 600;
  const start = performance.now();
  function step(ts) {
    const progress = Math.min((ts - start) / dur, 1);
    el.textContent = Math.round(from + (to - from) * progress);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// Refresh every 10s
refreshCounters();
setInterval(refreshCounters, 10000);