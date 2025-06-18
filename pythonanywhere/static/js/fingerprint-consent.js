// static/js/fingerprint-consent.js
(function() {
  const STORAGE_KEY = 'cookieConsent';
  const IDENTIFY_URL = '/api/identify';  // your Flask endpoint

  document.addEventListener('DOMContentLoaded', () => {
    const consent = localStorage.getItem(STORAGE_KEY);
    if (consent === 'yes') {
      sendFingerprint();
    } else if (consent !== 'no') {
      showConsentBanner();
    }
    // if 'no', do nothing
  });

  function showConsentBanner() {
    const banner = document.createElement('div');
    banner.id = 'consent-banner';
    Object.assign(banner.style, {
      position: 'fixed', bottom: '0', left: '0', right: '0',
      background: '#2c3e50', color: '#ecf0f1', padding: '1em',
      textAlign: 'center', zIndex: 10000, fontFamily: 'sans-serif'
    });
    banner.innerHTML = `
      <strong>Did someone say... Cookies?</strong>
      <p>We use cookies (and a tiny bit of browser‐fingerprinting) to keep you secure and remember your choices.</p>
      <button id="consent-yes" style="margin-right:1em;">Yes, I’m cool with that 🍪</button>
      <button id="consent-no">No thanks</button>
    `;
    document.body.appendChild(banner);

    document.getElementById('consent-yes').addEventListener('click', () => {
      localStorage.setItem(STORAGE_KEY, 'yes');
      document.body.removeChild(banner);
      sendFingerprint();
    });

    document.getElementById('consent-no').addEventListener('click', () => {
      localStorage.setItem(STORAGE_KEY, 'no');
      document.body.removeChild(banner);
    });
  }

  function sendFingerprint() {
    // load FingerprintJS CDN
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js';
    script.onload = () => {
      FingerprintJS.load().then(fp => fp.get()).then(result => {
        const visitorId = result.visitorId;
        // send it to backend
        fetch(IDENTIFY_URL, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          credentials: 'include',
          body: JSON.stringify({ visitorId })
        }).catch(err => {
          console.error('Fingerprint send failed:', err);
        });
      });
    };
    document.head.appendChild(script);
  }
})();
