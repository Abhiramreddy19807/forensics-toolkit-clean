/* ── App-wide JS (sidebar, topbar, alerts) ─────────────────── */

/* Live clock */
function updateClock() {
  const el = document.getElementById('liveTime');
  if (el) el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
}
updateClock();
setInterval(updateClock, 1000);

/* Sidebar toggle */
const sidebar     = document.getElementById('sidebar');
const mainWrapper = document.getElementById('mainWrapper');
const toggleBtn   = document.getElementById('sidebarToggle');
const overlay     = document.getElementById('sidebarOverlay');

toggleBtn?.addEventListener('click', () => {
  const isMobile = window.innerWidth <= 768;
  if (isMobile) {
    sidebar.classList.toggle('mobile-open');
    overlay.classList.toggle('active');
  } else {
    sidebar.classList.toggle('collapsed');
    mainWrapper?.classList.toggle('expanded');
  }
});

document.getElementById('mobMenuBtn')?.addEventListener('click', () => {
  sidebar?.classList.toggle('mobile-open');
  overlay?.classList.toggle('active');
});

overlay?.addEventListener('click', () => {
  sidebar?.classList.remove('mobile-open');
  overlay.classList.remove('active');
});

/* Alert panel toggle */
function toggleAlertPanel() {
  document.getElementById('alertPanel')?.classList.toggle('open');
}

/* Poll analytics and update badge/panel */
async function fetchAlerts() {
  try {
    const res = await fetch('/api/analytics');
    if (!res.ok) return;
    const data = await res.json();

    // Update notification count
    const count = data.alerts?.length || 0;
    const badge = document.getElementById('alertBadge');
    const notif  = document.getElementById('notifCount');
    if (count > 0) {
      if (badge) { badge.textContent = count; badge.style.display = 'inline'; }
      if (notif)  { notif.textContent = count; notif.style.display = 'block'; }
    } else {
      if (badge) badge.style.display = 'none';
      if (notif)  notif.style.display = 'none';
    }

    // Populate topbar alert list
    const list = document.getElementById('alertList');
    if (list && data.alerts) {
      if (data.alerts.length === 0) {
        list.innerHTML = '<p class="no-alerts">No alerts yet.</p>';
      } else {
        list.innerHTML = data.alerts.slice(0, 10).map(a => `
          <div class="alert-item ${a.type}" style="margin-bottom:0.4rem">
            <span class="alert-time">${a.time}</span>
            <span class="alert-msg">${a.msg}</span>
          </div>
        `).join('');
      }
    }
  } catch (_) { /* silent */ }
}

// Poll every 15 s
fetchAlerts();
setInterval(fetchAlerts, 15000);

/* Chart.js global defaults */
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = '#94a3b8';
  Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
  Chart.defaults.font.family = "'Rajdhani', sans-serif";
  Chart.defaults.font.size = 12;
}

/* Utility: format numbers */
function fmt(n, decimals = 2) {
  return Number(n).toFixed(decimals);
}