(function() {
  // 1) Inject CSS immediately into <head>
  const css = `
    #loading-overlay {
      position: fixed;
      inset: 0;
      /* stronger black so the white‑flash is truly hidden */
      background: rgba(0,0,0,0.85);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 9999;
    }
    #loading-overlay .spinner {
      border: 4px solid rgba(255,255,255,0.3);
      border-top-color: white;
      border-radius: 50%;
      width: 3rem;
      height: 3rem;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg) } }
  `;
  const styleTag = document.createElement('style');
  styleTag.textContent = css;
  document.head.appendChild(styleTag);

  // 2) Overlay injection helper
  function insertOverlay() {
    if (document.getElementById('loading-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'loading-overlay';
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    overlay.appendChild(spinner);
    document.body.insertBefore(overlay, document.body.firstChild);
  }

  if (document.body) {
    insertOverlay();
  } else {
    window.addEventListener('DOMContentLoaded', insertOverlay);
  }

  // 3) Track pending fetches
  window.__pendingFetches = [];
  const _origFetch = window.fetch;
  window.fetch = function(...args) {
    const p = _origFetch.apply(this, args);
    window.__pendingFetches.push(p);
    p.finally(() => {
      window.__pendingFetches =
        window.__pendingFetches.filter(x => x !== p);
    });
    return p;
  };

  // 4) Remove overlay once window & fetches settle
  function hideLoader() {
    const o = document.getElementById('loading-overlay');
    if (o) o.remove();
  }

  window.addEventListener('load', () => {
    if (window.__pendingFetches.length) {
      Promise.allSettled(window.__pendingFetches).then(hideLoader);
    } else {
      hideLoader();
    }
  });
})();
