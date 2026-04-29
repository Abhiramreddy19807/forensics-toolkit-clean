/* ── Image Forgery Detection JS ────────────────────────────── */

const imgInput   = document.getElementById('imageFile');
const analyzeBtn = document.getElementById('analyzeImgBtn');
const dropArea   = document.getElementById('imgDropArea');
const previewArea = document.getElementById('imgPreviewArea');
const imgPreview  = document.getElementById('imgPreview');
const imgMeta     = document.getElementById('imgMeta');
const imgZone     = document.getElementById('imgUploadZone');

/* Drag and drop */
imgZone?.addEventListener('dragover', e => { e.preventDefault(); imgZone.classList.add('dragover'); });
imgZone?.addEventListener('dragleave', () => imgZone.classList.remove('dragover'));
imgZone?.addEventListener('drop', e => {
  e.preventDefault(); imgZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) {
    imgInput.files = e.dataTransfer.files;
    showPreview(file);
  }
});

function previewImage(event) {
  const file = event.target.files[0];
  if (!file) return;
  showPreview(file);
}

function showPreview(file) {
  const reader = new FileReader();
  reader.onload = e => {
    imgPreview.src = e.target.result;
    imgMeta.textContent = `${file.name} · ${formatSize(file.size)} · ${file.type}`;
    dropArea.style.display    = 'none';
    previewArea.style.display = 'block';
    analyzeBtn.disabled = false;
  };
  reader.readAsDataURL(file);
}

function formatSize(bytes) {
  if (bytes < 1024)         return bytes + ' B';
  if (bytes < 1024 * 1024)  return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function clearImage() {
  imgInput.value = '';
  dropArea.style.display    = 'block';
  previewArea.style.display = 'none';
  analyzeBtn.disabled = true;
  document.getElementById('imgResultsSection').style.display = 'none';
  document.getElementById('imgHashBanner').style.display = 'none';
  const metaPanel = document.getElementById('metaPanel');
  if (metaPanel) metaPanel.style.display = 'none';
  imgZone.classList.remove('dragover');
}

async function analyzeImage() {
  if (!imgInput.files[0]) return;

  const loading = document.getElementById('imgLoading');
  const results = document.getElementById('imgResultsSection');

  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing…';
  loading.style.display = 'flex';
  results.style.display  = 'none';

  const form = new FormData();
  form.append('image', imgInput.files[0]);

  // Attach case_id if selected
  const caseSelect = document.getElementById('imgCaseSelect');
  if (caseSelect && caseSelect.value) {
    form.append('case_id', caseSelect.value);
  }

  try {
    const res  = await fetch('/api/analyze-image', { method: 'POST', body: form });
    const data = await res.json();

    if (data.error) { alert('Error: ' + data.error); return; }

    renderResults(data);
    renderHashBanner(data);
    renderMetadata(data.metadata);
    results.style.display = 'block';
    results.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    alert('Request failed: ' + e.message);
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = '<i class="fas fa-microscope"></i> Analyze Image';
    loading.style.display = 'none';
  }
}

function renderHashBanner(data) {
  const banner = document.getElementById('imgHashBanner');
  if (!banner || !data.evidence_id) return;
  document.getElementById('imgEvidenceId').textContent  = data.evidence_id;
  document.getElementById('imgHashMD5').textContent     = data.hashes?.md5    || '—';
  document.getElementById('imgHashSHA256').textContent  = data.hashes?.sha256 || '—';
  banner.style.display = 'block';
}

function renderMetadata(meta) {
  const panel = document.getElementById('metaPanel');
  const grid  = document.getElementById('metaGrid');
  if (!panel || !grid || !meta) return;

  const items = [];

  if (meta.dimensions) items.push(['Dimensions', meta.dimensions]);
  if (meta.format)     items.push(['Format', meta.format]);
  if (meta.mode)       items.push(['Color Mode', meta.mode]);
  if (meta.size_human) items.push(['File Size', meta.size_human]);

  if (meta.gps) {
    items.push(['GPS Latitude',  meta.gps.latitude]);
    items.push(['GPS Longitude', meta.gps.longitude]);
  }

  const SHOW_TAGS = ['Make','Model','Software','DateTime','DateTimeOriginal',
                     'ExifVersion','Flash','FocalLength','ISOSpeedRatings',
                     'ExposureTime','FNumber','LensModel'];
  for (const tag of SHOW_TAGS) {
    if (meta.exif?.[tag]) items.push([tag, meta.exif[tag]]);
  }

  if (!items.length) { panel.style.display = 'none'; return; }

  grid.innerHTML = items.map(([k, v]) => `
    <div style="background:var(--bg-input);border:1px solid var(--border);
                border-radius:8px;padding:0.5rem 0.75rem">
      <span style="font-size:0.68rem;color:var(--text-muted);letter-spacing:0.06em;
                   display:block;margin-bottom:2px">${k.toUpperCase()}</span>
      <span style="color:var(--text-primary);font-family:var(--font-mono);
                   font-size:0.8rem;word-break:break-all">${v}</span>
    </div>
  `).join('');

  panel.style.display = 'block';
}

function renderResults(data) {
  const banner = document.getElementById('imgVerdictBanner');
  const iconEl = document.getElementById('verdictIcon');
  const textEl = document.getElementById('verdictText');
  const subEl  = document.getElementById('verdictSub');

  iconEl.textContent = data.tampering_score >= 65 ? '🔴'
                     : data.tampering_score >= 35 ? '🟡' : '🟢';
  textEl.textContent  = data.verdict;
  textEl.style.color  = data.verdict_color;
  subEl.textContent   = `Tampering score: ${data.tampering_score}% · ${data.dimensions} · ${data.format}`;
  banner.style.borderColor = data.verdict_color + '44';

  animateGauge(data.tampering_score);

  document.getElementById('metELA').textContent     = data.metrics.ela_score.toFixed(3);
  document.getElementById('metEdge').textContent    = data.metrics.edge_density.toFixed(2) + '%';
  document.getElementById('metNoise').textContent   = data.metrics.noise_variance.toFixed(1);
  document.getElementById('metEntropy').textContent = data.metrics.entropy.toFixed(3);

  document.getElementById('originalImg').src = 'data:image/jpeg;base64,' + data.original_image;
  document.getElementById('elaImg').src       = 'data:image/png;base64,'  + data.ela_image;
}

function animateGauge(score) {
  const fill    = document.getElementById('gaugeFill');
  const scoreEl = document.getElementById('gaugeScore');
  if (!fill || !scoreEl) return;

  const arcLen = 251.2;
  const target = (score / 100) * arcLen;
  let current  = 0;
  let displayScore = 0;
  const step      = target / 40;
  const scoreStep = score / 40;

  const interval = setInterval(() => {
    current      = Math.min(current + step, target);
    displayScore = Math.min(displayScore + scoreStep, score);
    fill.setAttribute('stroke-dasharray', `${current.toFixed(1)} ${arcLen}`);
    scoreEl.textContent = displayScore.toFixed(1) + '%';
    if (current >= target) clearInterval(interval);
  }, 16);
}