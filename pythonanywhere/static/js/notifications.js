// notifications.js
(function() {
  // ——— CONFIG ———
  const FETCH_INTERVAL_MS = 30_000;
  const BELL_ROUTES = [
    '/index', '/group-notes', '/scheduler-page', '/todo-page' 
    // ... other routes
  ];

  // ——— INDEXEDDB CONFIG ———
  const DB_NAME = 'NotificationDB';
  const STORE_NAME = 'seenNotifications';
  const ITEM_KEY = 'seenSet';

  // ——— STATE ———
  let notifications = [];
  let seenSet = new Set();
  let autoLoginPromise = null; // Track login attempts

  // ——— AUTO-LOGIN HELPERS ———
  async function attemptAutoLoginSilently() {
    if (autoLoginPromise) return autoLoginPromise; // Dedupe requests
    
    autoLoginPromise = (async () => {
      try {
        const res = await fetch("/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
          credentials: 'include'
        });
        return res.ok;
      } catch (e) {
        return false;
      }
    })();

    // Reset after completion
    autoLoginPromise.finally(() => {
      autoLoginPromise = null;
    });

    return autoLoginPromise;
  }

  async function authenticatedFetch(url, options = {}) {
    let response = await fetch(url, {
      ...options,
      credentials: 'include'
    });

    // Handle 401 with single auto-login retry
    if (response.status === 401 && !options._retried) {
      const loggedIn = await attemptAutoLoginSilently();
      if (loggedIn) {
        return fetch(url, {
          ...options,
          _retried: true // Prevent infinite loops
        });
      }
    }
    return response;
  }

  // ——— INDEXEDDB HELPERS ———
  async function initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 2);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
    });
  }

  async function loadNotifiedSet() {
    try {
      const db = await initDB();
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(ITEM_KEY);
      return new Promise((resolve) => {
        request.onsuccess = () => {
          const data = request.result || [];
          seenSet = new Set(data);
          resolve(seenSet);
        };
        request.onerror = () => resolve(seenSet);
      });
    } catch (e) {
      console.error('IDB load error', e);
      return seenSet;
    }
  }

  async function saveNotifiedSet() {
    try {
      const db = await initDB();
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.put(Array.from(seenSet), ITEM_KEY);
      return new Promise((resolve) => {
        tx.oncomplete = resolve;
      });
    } catch (e) {
      console.error('IDB save error', e);
    }
  }

  // ——— API CALLS ———
  async function fetchVapidKey() {
    const res = await authenticatedFetch('/api/vapid_public_key');
    if (!res.ok) throw new Error('Could not load VAPID key');
    const { publicKey } = await res.json();
    return publicKey;
  }

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

  async function markSeenBulk(ids) {
    if (!ids.length) return;
    const res = await authenticatedFetch('/notifications/seen', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ids })
    });
    if (!res.ok) throw new Error('Failed to bulk‐mark notifications seen');
    return res.json();
  }

  // ——— PUSH SUBSCRIPTION ———
  async function initPush() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      console.warn('Push not supported');
      return;
    }
    try {
      const reg = await navigator.serviceWorker.register('/static/sw.js');
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') return;

      const existing = await reg.pushManager.getSubscription();
      if (existing) return;

      const keyB64 = await fetchVapidKey();
      const keyBuf = urlBase64ToUint8Array(keyB64);

      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: keyBuf
      });

      await authenticatedFetch('/api/save-subscription', {
        method:'POST',
        headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify(sub)
      });
    } catch (e) {
      console.error('Push init failed', e);
    }
  }

  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const b64 = (base64String + padding)
      .replace(/\-/g, '+').replace(/_/g, '/');
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
        display: 'block', width: '100%', padding: '8px', border: 'none',
        background: 'var(--btn-color)', cursor: 'pointer',
        textAlign: 'center', fontWeight: 'bold', marginBottom: '4px'
      });
      bulkBtn.addEventListener('click', async () => {
        bulkBtn.disabled = true;
        try {
          const ids = items.map(n => n.id);
          await markSeenBulk(ids);
          const fresh = await fetchUnseen();
          notifications = fresh;
          renderNotifications(menu, fresh);
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
        padding: '8px 16px', color: '#666', textAlign: 'center'
      });
      menu.appendChild(empty);
      return;
    }

    items.forEach(n => {
      const row = document.createElement('div');
      row.className = 'notif-item';
      Object.assign(row.style, {
        padding: '8px 16px', cursor: 'pointer', borderBottom: '1px solid #eee'
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

      const toShow = unseen.filter(n => !seenSet.has(n.id));
      
      if (toShow.length && window.Notification && Notification.permission === 'granted') {
        toShow.forEach(n => {
          const toast = new Notification(n.title, {
            body: n.text,
            icon: '/static/notification-icon.jpg',
            tag: `notif-${n.id}`,
            renotify: true
          });
          toast.onclick = () => {
            window.focus();
            window.location.href = n.module;
          };
          seenSet.add(n.id);
        });
        await saveNotifiedSet();
      }

      const dot = document.getElementById('notif-dot');
      if (dot) dot.style.display = unseen.length ? 'block' : 'none';
    } catch (err) {
      console.error('Notification update error:', err);
    }
  }

  // ——— MESSAGE HANDLER FOR SERVICE WORKER UPDATES ———
  function setupServiceWorkerMessaging() {
    navigator.serviceWorker.addEventListener('message', event => {
      if (event.data.type === 'notification-seen') {
        const id = event.data.id;
        if (!seenSet.has(id)) {
          seenSet.add(id);
          saveNotifiedSet();
          
          notifications = notifications.filter(n => n.id !== id);
          const dot = document.getElementById('notif-dot');
          if (dot) dot.style.display = notifications.length ? 'block' : 'none';
          
          const menu = document.getElementById('notif-menu');
          if (menu && menu.style.display === 'block') {
            renderNotifications(menu, notifications);
          }
        }
      }
    });
  }

  // ——— BELL+MENU INIT ———
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
        top:      '50%',
        right:    '0.5rem',
        transform:'translateY(-50%)',
        display:  'flex',
        alignItems:'center',
        gap:      '1rem',
        zIndex:   1000
      });
      header.appendChild(iconsContainer);
    }

    const pic = document.getElementById('profile-pic');
    if (pic) {
      Object.assign(pic.style, {
        position: 'static',
        transform:'none',
        margin:   0,
        zIndex:   'auto'
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
      border:    'none',
      cursor:    'pointer',
      padding:   0,
      margin:    0,
      zIndex:    1001
    });
    iconsContainer.insertBefore(btn, iconsContainer.firstChild);

    const dot = document.getElementById('notif-dot');
    Object.assign(dot.style, {
      position:   'absolute',
      top:        '4px',
      right:      '0',
      width:      '8px',
      height:     '8px',
      borderRadius:'50%',
      background: 'red',
      display:    'none'
    });

    const menu = document.createElement('div');
    menu.id = 'notif-menu';
    Object.assign(menu.style, {
      position:    'absolute',
      top:         '2.5rem',
      right:       '1rem',
      width:       '280px',
      maxHeight:   '320px',
      overflowY:   'auto',
      background:  'var(--bg-color)',
      border:      '1px solid #ccc',
      borderRadius:'4px',
      boxShadow:   '0 2px 8px rgba(0,0,0,0.15)',
      zIndex:      1002,
      display:     'none',
      padding:     '8px 0'
    });
    document.body.appendChild(menu);

    btn.addEventListener('click', async () => {
      try {
        const fresh = await fetchUnseen();
        notifications = fresh;
        renderNotifications(menu, fresh);
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

  // ——— HEADLESS POLLING INIT ———
  function initHeadless() {
    updateNotifications();
    setInterval(updateNotifications, FETCH_INTERVAL_MS);
  }

  // ——— BOOTSTRAP ———
  document.addEventListener('DOMContentLoaded', async () => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission().catch(console.error);
    }

    await loadNotifiedSet();

    if ('serviceWorker' in navigator) {
      setupServiceWorkerMessaging();
    }

    initPush();

    const path = window.location.pathname;
    const showBell = BELL_ROUTES.some(route =>
      path === route || path.startsWith(route + '/')
    );
    if (showBell) {
      initBellUI();
    }

    initHeadless();
  });
})();