/* ── Login Page JS ─────────────────────────────────────────── */

// Generate floating particles
(function generateParticles() {
  const container = document.getElementById('particles');
  if (!container) return;
  for (let i = 0; i < 25; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + 'vw';
    p.style.animationDuration = (8 + Math.random() * 12) + 's';
    p.style.animationDelay = (Math.random() * 10) + 's';
    p.style.width = p.style.height = (1 + Math.random() * 2) + 'px';
    container.appendChild(p);
  }
})();

// Toggle password visibility
function togglePw() {
  const input = document.getElementById('password');
  const icon  = document.getElementById('eyeIcon');
  if (input.type === 'password') {
    input.type = 'text';
    icon.className = 'fas fa-eye-slash';
  } else {
    input.type = 'password';
    icon.className = 'fas fa-eye';
  }
}

// Animate login button on submit
document.getElementById('loginForm')?.addEventListener('submit', function () {
  const btn = document.getElementById('loginBtn');
  if (btn) {
    btn.innerHTML = '<span class="btn-text"><i class="fas fa-spinner fa-spin"></i> Authenticating…</span>';
    btn.disabled = true;
  }
});

// Demo credential quick-fill
document.querySelectorAll('.demo-creds code').forEach(el => {
  el.style.cursor = 'pointer';
  el.title = 'Click to fill';
  el.addEventListener('click', () => {
    const parts = el.textContent.split(' / ');
    if (parts.length === 2) {
      document.getElementById('username').value = parts[0].trim();
      document.getElementById('password').value = parts[1].trim();
    }
  });
});