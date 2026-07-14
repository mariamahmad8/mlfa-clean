(() => {
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = meta ? meta.content : '';
  if (!csrfToken || typeof window.fetch !== 'function') return;

  const originalFetch = window.fetch.bind(window);
  const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);

  window.fetch = (input, init = {}) => {
    const requestMethod = input instanceof Request ? input.method : 'GET';
    const method = String(init.method || requestMethod).toUpperCase();
    const requestUrl = input instanceof Request ? input.url : input;
    const url = new URL(requestUrl, window.location.href);

    if (url.origin === window.location.origin && !safeMethods.has(method)) {
      const headers = new Headers(input instanceof Request ? input.headers : undefined);
      new Headers(init.headers || {}).forEach((value, key) => headers.set(key, value));
      headers.set('X-CSRF-Token', csrfToken);
      init = { ...init, headers };
    }

    return originalFetch(input, init);
  };
})();

// Header user-menu dropdown — click chip to open, click outside / Esc to close.
window.toggleUserMenu = function(e) {
  e.stopPropagation();
  const menu = e.currentTarget.closest('.user-menu');
  if (!menu) return;
  const opening = !menu.classList.contains('open');
  document.querySelectorAll('.user-menu.open').forEach(m => m.classList.remove('open'));
  if (opening) menu.classList.add('open');
};
document.addEventListener('click', (e) => {
  if (!e.target.closest('.user-menu')) {
    document.querySelectorAll('.user-menu.open').forEach(m => m.classList.remove('open'));
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.user-menu.open').forEach(m => m.classList.remove('open'));
  }
});
