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
