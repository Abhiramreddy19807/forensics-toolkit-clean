/* ── Image Forgery Detection JS ────────────────────────────── */

const imgInput  = document.getElementById('imageFile');
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
    dropArea.style.display   = 'none';
    previewArea.style.display = 'block';
    analyzeBtn.disabled = false;
  };
  reader.readAsDataURL(file);
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function clearImage() {
  imgInput.value = '';
  dropArea.style.display    = 'block';
  previewArea.style.display = 'none';
  analyzeBtn.disabled = true;
  document.getElementById('imgResultsSection').style.display = 'none';
  imgZone.classList.remove('dragover');
}

async function analyzeImage() {
  if (!imgInput.files[0]) return;

  const loading = document.getElementById('imgLoading');
  const results  = document.getElementById('imgResultsSection');

  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing…';
  loading.style.display = 'flex';
  results.style.display  = 'none';

  const form = new FormData();
  form.append('image', imgInput.files[0]);

  try {
    const res  = await fetch('/api/analyze-image', { method: 'POST', body: form });
    const data = await res.json();

    if (data.error) { alert('Error: ' + data.error); return; }

    renderResults(data);
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

function renderResults(data) {
  // Verdict banner
  const banner  = document.getElementById('imgVerdictBanner');
  const iconEl  = document.getElementById('verdictIcon');
  const textEl  = document.getElementById('verdictText');
  const subEl   = document.getElementById('verdictSub');

  iconEl.textContent = data.tampering_score >= 65 ? '🔴' : data.tampering_score >= 35 ? '🟡' : '🟢';
  textEl.textContent  = data.verdict;
  textEl.style.color  = data.verdict_color;
  subEl.textContent   = `Tampering score: ${data.tampering_score}% · ${data.dimensions} · ${data.format}`;
  banner.style.borderColor = data.verdict_color + '44';

  // Gauge animation
  animateGauge(data.tampering_score);

  // Metrics
  document.getElementById('metELA').textContent     = data.metrics.ela_score.toFixed(3);
  document.getElementById('metEdge').textContent    = data.metrics.edge_density.toFixed(2) + '%';
  document.getElementById('metNoise').textContent   = data.metrics.noise_variance.toFixed(1);
  document.getElementById('metEntropy').textContent = data.metrics.entropy.toFixed(3);

  // Images
  document.getElementById('originalImg').src = 'data:image/jpeg;base64,' + data.original_image;
  document.getElementById('elaImg').src       = 'data:image/png;base64,'  + data.ela_image;
}

function animateGauge(score) {
  const fill = document.getElementById('gaugeFill');
  const scoreEl = document.getElementById('gaugeScore');
  if (!fill || !scoreEl) return;

  // SVG arc: total arc = 251.2 units (180deg semicircle, r=80)
  const arcLen = 251.2;
  const target = (score / 100) * arcLen;

  let current = 0;
  const step = target / 40;
  let displayScore = 0;
  const scoreStep = score / 40;

  const interval = setInterval(() => {
    current      = Math.min(current + step, target);
    displayScore = Math.min(displayScore + scoreStep, score);
    fill.setAttribute('stroke-dasharray', `${current.toFixed(1)} ${arcLen}`);
    scoreEl.textContent = displayScore.toFixed(1) + '%';
    if (current >= target) clearInterval(interval);
  }, 16);
}
