(function() {
  // ——— CONFIG ———
  const FETCH_INTERVAL_MS = 30_000;
  const BELL_ROUTES = [
    '/index',
    '/group-notes',
    '/scheduler-page',
    '/todo_page'
    // ... other routes
  ];

  // ——— STATE ———
  let notifications = [];

  // ——— AUTO-LOGIN HELPERS ———
  let autoLoginPromise = null;
  async function attemptAutoLoginSilently() {
    if (autoLoginPromise) return autoLoginPromise;
    autoLoginPromise = (async () => {
      try {
        const res = await fetch("/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
          credentials: 'include'
        });
        return res.ok;
      } catch {
        return false;
      }
    })();
    autoLoginPromise.finally(() => { autoLoginPromise = null; });
    return autoLoginPromise;
  }

  async function authenticatedFetch(url, options = {}) {
    let response = await fetch(url, {
      ...options,
      credentials: 'include'
    });
    if (response.status === 401 && !options._retried) {
      const loggedIn = await attemptAutoLoginSilently();
      if (loggedIn) {
        return fetch(url, {
          ...options,
          _retried: true
        });
      }
    }
    return response;
  }

  // ——— API CALLS ———
  async function fetchUnseen() {
    const res = await authenticatedFetch('/notifications');
    if (!res.ok) throw new Error('Failed to fetch notifications');
    const { notifications: list = [] } = await res.json();
    return list;
  }

  async function markSeen(id) {
    const res = await authenticatedFetch(`/notifications/${id}`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to mark notification seen');
    return res.json();
  }

  async function markNotified(id) {
    const res = await authenticatedFetch(`/notifications/notified/${id}`, {
      method: 'POST'
    });
    if (!res.ok) console.warn('Failed to mark notification notified:', id);
  }

  async function markSeenBulk(ids) {
    if (!ids.length) return;
    const res = await authenticatedFetch('/notifications/seen', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    });
    if (!res.ok) throw new Error('Failed to bulk‐mark notifications seen');
    return res.json();
  }

  async function initPush(force = false) {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      console.warn('Push not supported');
      return;
    }
    try {
      const reg = await navigator.serviceWorker.register('/sw.js');
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') return;

      // Check if we already have a valid subscription
      let existing = await reg.pushManager.getSubscription();
      
      // Only create new subscription if forced or doesn't exist
      if (existing && !force) return existing;
      
      if (existing && force) {
        await existing.unsubscribe();
        existing = null;
      }

      if (!existing) {
        const keyRes = await authenticatedFetch('/api/vapid_public_key');
        if (!keyRes.ok) throw new Error('Could not load VAPID key');
        const { publicKey } = await keyRes.json();
        const keyBuf = urlBase64ToUint8Array(publicKey);

        existing = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: keyBuf
        });
      }

      // Save to backend
      await authenticatedFetch('/api/save-subscription', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(existing)
      });

      return existing;
    } catch (e) {
      console.error('Push init failed', e);
    }
  }

  window.pushSubscription = {
    init: initPush,
    forceRenew: () => initPush(true)
  };

  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const b64 = (base64String + padding)
      .replace(/-/g, '+').replace(/_/g, '/');
    const raw = window.atob(b64);
    return new Uint8Array([...raw].map(c => c.charCodeAt(0)));
  }

  // ——— RENDERER ———
  function renderNotifications(menu, items) {
    menu.innerHTML = '';

    if (items.length) {
      const bulkBtn = document.createElement('button');
      bulkBtn.id = 'mark-all-btn';
      bulkBtn.textContent = `Mark all as read (${items.length})`;
      Object.assign(bulkBtn.style, {
        display: 'block',
        width: '100%',
        padding: '8px',
        border: 'none',
        background: 'var(--btn-color)',
        cursor: 'pointer',
        textAlign: 'center',
        fontWeight: 'bold',
        marginBottom: '4px'
      });
      bulkBtn.addEventListener('click', async () => {
        bulkBtn.disabled = true;
        try {
          const ids = items.map(n => n.id);
          await markSeenBulk(ids);
          notifications = await fetchUnseen();
          renderNotifications(menu, notifications);
        } catch (err) {
          console.error(err);
        } finally {
          bulkBtn.disabled = false;
        }
      });
      menu.appendChild(bulkBtn);
    }

    if (!items.length) {
      const empty = document.createElement('div');
      empty.textContent = 'No new notifications';
      Object.assign(empty.style, {
        padding: '8px 16px',
        color: '#666',
        textAlign: 'center'
      });
      menu.appendChild(empty);
      return;
    }

    items.forEach(n => {
      const row = document.createElement('div');
      row.className = 'notif-item';
      Object.assign(row.style, {
        padding: '8px 16px',
        cursor: 'pointer',
        borderBottom: '1px solid #eee'
      });
      row.innerHTML = `<strong>${n.title}</strong><br><small>${n.text}</small>`;
      row.addEventListener('click', async () => {
        try {
          await markSeen(n.id);
          notifications = notifications.filter(x => x.id !== n.id);
        } catch (err) {
          console.error(err);
        }
        window.location.href = n.module;
      });
      menu.appendChild(row);
    });
  }

  // ——— CORE UPDATER ———
  async function updateNotifications() {
    try {
      const unseen = await fetchUnseen();
      notifications = unseen;

      // Update UI only - notifications handled by service worker
      const dot = document.getElementById('notif-dot');
      if (dot) dot.style.display = unseen.length ? 'block' : 'none';
    } catch (err) {
      console.error('Notification update error:', err);
    }
  }

  // ——— BELL + MENU UI ———
  function initBellUI() {
    const header = document.querySelector('header');
    if (!header) return;

    if (!['relative','absolute','fixed'].includes(getComputedStyle(header).position)) {
      header.style.position = 'relative';
    }

    let iconsContainer = document.getElementById('header-icons');
    if (!iconsContainer) {
      iconsContainer = document.createElement('div');
      iconsContainer.id = 'header-icons';
      Object.assign(iconsContainer.style, {
        position: 'absolute',
        top: '50%',
        right: '0.5rem',
        transform: 'translateY(-50%)',
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
        zIndex: 1000
      });
      header.appendChild(iconsContainer);
    }

    const pic = document.getElementById('profile-pic');
    if (pic) {
      Object.assign(pic.style, {
        position: 'static',
        transform: 'none',
        margin: 0,
        zIndex: 'auto'
      });
      iconsContainer.appendChild(pic);
    }

    const btn = document.createElement('button');
    btn.id = 'notif-bell';
    btn.innerHTML = '🔔<span id="notif-dot"></span>';
    Object.assign(btn.style, {
      position: 'relative',
      fontSize: '1.5rem',
      background: 'none',
      border: 'none',
      cursor: 'pointer',
      padding: 0,
      margin: 0,
      zIndex: 1001
    });
    iconsContainer.insertBefore(btn, iconsContainer.firstChild);

    const dot = document.getElementById('notif-dot');
    Object.assign(dot.style, {
      position: 'absolute',
      top: '4px',
      right: '0',
      width: '8px',
      height: '8px',
      borderRadius: '50%',
      background: 'red',
      display: 'none'
    });

    const menu = document.createElement('div');
    menu.id = 'notif-menu';
    Object.assign(menu.style, {
      position: 'absolute',
      top: '2.5rem',
      right: '1rem',
      width: '280px',
      maxHeight: '320px',
      overflowY: 'auto',
      background: 'var(--bg-color)',
      border: '1px solid #ccc',
      borderRadius: '4px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
      zIndex: 1002,
      display: 'none',
      padding: '8px 0'
    });
    document.body.appendChild(menu);

    btn.addEventListener('click', async () => {
      try {
        notifications = await fetchUnseen();
        renderNotifications(menu, notifications);
        dot.style.display = 'none';
        menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
      } catch (err) {
        console.error(err);
      }
    });

    document.addEventListener('click', e => {
      if (!btn.contains(e.target) && !menu.contains(e.target)) {
        menu.style.display = 'none';
      }
    });
  }

  // ——— BOOTSTRAP ———
  document.addEventListener('DOMContentLoaded', () => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission().catch(console.error);
    }

    // ←─── handle “notification-seen” messages from SW ───→
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.addEventListener('message', event => {
        if (event.data.type === 'notification-seen') {
          const id = event.data.id;
          // remove from local list
          notifications = notifications.filter(n => n.id !== id);
          // update dot
          const dot = document.getElementById('notif-dot');
          if (dot) dot.style.display = notifications.length ? 'block' : 'none';
          // re-render menu if open
          const menu = document.getElementById('notif-menu');
          if (menu && menu.style.display === 'block') {
            renderNotifications(menu, notifications);
          }
        }
        if (event.data.type === 'push-subscription-updated') {
          // Renew subscription in backend
          initPush().catch(console.error);
        }
      });
    }

    // Clear notifications when page becomes visible
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        updateNotifications();
      }
    });

    initPush();
    const path = window.location.pathname;
    if (BELL_ROUTES.some(route => path === route || path.startsWith(route + '/'))) {
      initBellUI();
    }
    updateNotifications();
    setInterval(updateNotifications, FETCH_INTERVAL_MS);
  });
})();