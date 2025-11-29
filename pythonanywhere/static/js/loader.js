(function() {
  // 1) Inject CSS overlay immediately
  const css = `
    #loading-overlay {
      position: fixed;
      inset: 0;
      background: #2c2c2c;
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

  // 3) Track pending fetches, ignoring lazy iframes
  window.__pendingFetches = [];
  const _origFetch = window.fetch;
  window.fetch = function(...args) {
    let isInsideLazyIframe = false;
    try {
      // Detect if this fetch originates from a lazy iframe
      isInsideLazyIframe = window.frameElement?.hasAttribute('data-lazy');
    } catch(e) {
      // Cross-origin frames may throw
      isInsideLazyIframe = false;
    }

    const p = _origFetch.apply(this, args);

    if (!isInsideLazyIframe) {
      window.__pendingFetches.push(p);
      p.finally(() => {
        window.__pendingFetches = window.__pendingFetches.filter(x => x !== p);
      });
    }

    return p;
  };

  // 4) Track non-lazy iframes
  function getIframePromises() {
    const iframes = Array.from(document.querySelectorAll('iframe'))
      .filter(f => !f.hasAttribute('data-lazy'));

    return iframes.map(f => new Promise(resolve => {
      // iframe already loaded
      if (f.complete || f.contentWindow?.document.readyState === 'complete') {
        resolve();
      } else {
        f.addEventListener('load', () => resolve());
        f.addEventListener('error', () => resolve());
      }
    }));
  }

  // 5) Remove overlay once page + fetches + non-lazy iframes are ready
  function hideLoader() {
    const o = document.getElementById('loading-overlay');
    if (o) o.remove();
  }

  window.addEventListener('load', () => {
    const iframePromises = getIframePromises();
    const allPromises = [...window.__pendingFetches, ...iframePromises];

    if (allPromises.length) {
      Promise.allSettled(allPromises).then(hideLoader);
    } else {
      hideLoader();
    }
  });
})();
