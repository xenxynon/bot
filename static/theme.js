// ── Theme management — loaded by both login and explorer ──────────────────────

(function () {
  const root = document.documentElement;

  function getTheme() {
    const saved = localStorage.getItem('fs-theme');
    if (saved) return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(t) {
    root.setAttribute('data-theme', t);
    const btn = document.getElementById('theme-btn');
    if (btn) btn.textContent = t === 'dark' ? '◑' : '◐';
  }

  function toggleTheme() {
    const cur = root.getAttribute('data-theme') || getTheme();
    const next = cur === 'dark' ? 'light' : 'dark';
    localStorage.setItem('fs-theme', next);
    applyTheme(next);
  }

  // apply immediately to avoid flash
  applyTheme(getTheme());

  // expose globally
  window.toggleTheme = toggleTheme;
})();
