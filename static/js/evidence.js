/* ── Evidence Analyzer JS ──────────────────────────────────── */

let anomalyChartInstance = null;
let allRecords = [];

/* Drag-and-drop upload zone */
const zone = document.getElementById('uploadZone');
const fileInput = document.getElementById('evidenceFile');

zone?.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
zone?.addEventListener('dragleave', () => zone.classList.remove('dragover'));
zone?.addEventListener('drop', e => {
  e.preventDefault(); zone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});
zone?.addEventListener('click', () => fileInput?.click());

fileInput?.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

function setFile(file) {
  document.getElementById('selectedFileName').textContent = file.name;
  document.getElementById('fileSelected').style.display = 'flex';
}

function clearFile() {
  fileInput.value = '';
  document.getElementById('fileSelected').style.display = 'none';
}

async function runAnalysis() {
  const btn = document.getElementById('analyzeBtn');
  const loading = document.getElementById('evidenceLoading');
  const results = document.getElementById('resultsSection');

  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing…';
  loading.style.display = 'flex';
  results.style.display = 'none';

  const formData = new FormData();
  if (fileInput?.files[0]) formData.append('file', fileInput.files[0]);

  try {
    const res  = await fetch('/api/analyze-evidence', { method: 'POST', body: formData });
    const data = await res.json();

    if (data.error) { alert('Error: ' + data.error); return; }

    allRecords = data.records;
    renderSummary(data);
    renderTable(data.records, data.columns);
    renderAnomalyChart(data.records);
    results.style.display = 'block';
    results.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    alert('Request failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-play"></i> Run Analysis';
    loading.style.display = 'none';
  }
}

function renderSummary(data) {
  document.getElementById('totalRecords').textContent = data.total;
  document.getElementById('anomalyCount').textContent = data.anomalies;
  document.getElementById('normalCount').textContent  = data.total - data.anomalies;
  const rate = data.total > 0 ? ((data.anomalies / data.total) * 100).toFixed(1) : '0.0';
  document.getElementById('detectionRate').textContent = rate + '%';
}

function renderTable(records, columns) {
  const head = document.getElementById('tableHead');
  const body = document.getElementById('tableBody');

  const allCols = ['record_id', ...columns, 'anomaly_score', 'status'];
  head.innerHTML = '<tr>' + allCols.map(c =>
    `<th>${c.replace(/_/g,' ').toUpperCase()}</th>`
  ).join('') + '</tr>';

  body.innerHTML = records.map(r => `
    <tr>
      <td>${r.record_id}</td>
      ${columns.map(c => `<td>${fmt(r[c], 2)}</td>`).join('')}
      <td>${fmt(r.anomaly_score, 4)}</td>
      <td>
        <span class="status-badge ${r.status.toLowerCase()}">
          ${r.status}
        </span>
      </td>
    </tr>
  `).join('');

  document.getElementById('tableFooter').textContent =
    `Showing ${records.length} records`;
}

function renderAnomalyChart(records) {
  const ctx = document.getElementById('anomalyChart')?.getContext('2d');
  if (!ctx) return;

  if (anomalyChartInstance) anomalyChartInstance.destroy();

  const labels  = records.map(r => `#${r.record_id}`);
  const scores  = records.map(r => r.anomaly_score);
  const colors  = records.map(r => r.status === 'ANOMALY' ? '#ef4444' : '#10b981');
  const bgColors = records.map(r => r.status === 'ANOMALY' ? 'rgba(239,68,68,0.6)' : 'rgba(16,185,129,0.6)');

  anomalyChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Anomaly Score',
        data: scores,
        backgroundColor: bgColors,
        borderColor: colors,
        borderWidth: 1,
        borderRadius: 3,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            afterLabel: (ctx2) => {
              const rec = records[ctx2.dataIndex];
              return `Status: ${rec.status}`;
            }
          }
        }
      },
      scales: {
        x: { ticks: { maxTicksLimit: 20 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' } }
      },
      animation: { duration: 600 }
    }
  });
}

function filterTable() {
  const q      = document.getElementById('tableSearch').value.toLowerCase();
  const status = document.getElementById('statusFilter').value;
  let filtered = allRecords;

  if (status) filtered = filtered.filter(r => r.status === status);
  if (q)      filtered = filtered.filter(r =>
    Object.values(r).some(v => String(v).toLowerCase().includes(q))
  );

  const body = document.getElementById('tableBody');
  body.innerHTML = filtered.length === 0
    ? '<tr><td colspan="20" style="text-align:center;color:var(--text-muted)">No matching records</td></tr>'
    : filtered.map(r => {
        const keys = Object.keys(r).filter(k => k !== 'record_id' && k !== 'status' && k !== 'anomaly_score');
        return `
          <tr>
            <td>${r.record_id}</td>
            ${keys.map(k => `<td>${fmt(r[k], 2)}</td>`).join('')}
            <td>${fmt(r.anomaly_score, 4)}</td>
            <td><span class="status-badge ${r.status.toLowerCase()}">${r.status}</span></td>
          </tr>
        `;
      }).join('');

  document.getElementById('tableFooter').textContent =
    `Showing ${filtered.length} of ${allRecords.length} records`;
}

function clearResults() {
  document.getElementById('resultsSection').style.display = 'none';
  clearFile();
  allRecords = [];
}

function fmt(n, d) { return Number(n).toFixed(d); }
