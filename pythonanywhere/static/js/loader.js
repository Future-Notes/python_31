(function() {
  // --- 1) Inject CSS overlay immediately ---
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

  // --- 2) Overlay injection helper ---
  function insertOverlay() {
    if (document.getElementById('loading-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'loading-overlay';
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    overlay.appendChild(spinner);
    document.body.insertBefore(overlay, document.body.firstChild);
  }

  if (document.body) insertOverlay();
  else window.addEventListener('DOMContentLoaded', insertOverlay);

  // --- 3) Patch fetch globally with automatic retry ---
  const _origFetch = window.fetch;
  window.__pendingFetches = [];

  window.fetch = async function(input, init = {}) {
    const clonedInit = structuredClone(init); // safe clone for retry
    let retries = 2;
    let delays = [1500, 800]; // ms delays for first and second retry

    let attempt = 0;
    while (true) {
      const p = _origFetch.apply(this, [input, init]);

      if (!window.frameElement?.hasAttribute?.('data-lazy')) {
        window.__pendingFetches.push(p);
        p.finally(() => {
          window.__pendingFetches = window.__pendingFetches.filter(x => x !== p);
        });
      }

      const res = await p;

      // Attempt retry if schema update message detected
      let data = null;
      try { data = await res.clone().json(); } catch(e){}

      if (res.status === 500 &&
          data?.message === "Database schema updated. Please retry your request." &&
          attempt < retries) {

        console.warn(`Database schema updated detected, retrying fetch in ${delays[attempt]}ms...`);
        await new Promise(r => setTimeout(r, delays[attempt]));
        attempt++;
        init = structuredClone(clonedInit); // reset init for exact retry
        continue; // retry
      }

      // If retries exhausted and still schema update, alert user
      if (res.status === 500 &&
          data?.message === "Database schema updated. Please retry your request." &&
          attempt >= retries) {
        alert("Database schema updated. Please retry your last action manually.");
      }

      return res; // return response
    }
  };

  // --- 4) Track non-lazy iframes ---
  function getIframePromises() {
    return Array.from(document.querySelectorAll('iframe'))
      .filter(f => !f.hasAttribute('data-lazy'))
      .map(f => new Promise(resolve => {
        if (f.complete || f.contentWindow?.document.readyState === 'complete') resolve();
        else {
          f.addEventListener('load', () => resolve());
          f.addEventListener('error', () => resolve());
        }
      }));
  }

  // --- 5) Remove overlay once page + fetches + non-lazy iframes are ready ---
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
