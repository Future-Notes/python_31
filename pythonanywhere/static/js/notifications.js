// notifications.js
(function() {
  // ——— CONFIG ———
  const FETCH_INTERVAL_MS = 30_000;  // poll every 30s
  const STORAGE_KEY = 'seenDesktopNotifs'; // localStorage key

  // ——— STATE ———
  let notifications = [];

  // Retrieve set of IDs we've already notified on
  function loadNotifiedSet() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch {
      return new Set();
    }
  }

  // Persist updated set back to storage
  function saveNotifiedSet(set) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...set]));
    } catch {
      // silently fail
    }
  }

  // ——— UTILITIES ———
  function getSessionKey() {
    return sessionStorage.getItem("session_key");
  }

  async function fetchUnseen() {
    const token = getSessionKey();
    const res = await fetch('/notifications', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to fetch notifications');
    const data = await res.json();
    return data.notifications || [];
  }

  async function markSeen(id) {
    const token = getSessionKey();
    const res = await fetch(`/notifications/${id}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to mark notification seen');
    return res.json();
  }

  async function markSeenBulk(ids) {
    if (!ids.length) return;
    const token = getSessionKey();
    const res = await fetch('/notifications/seen', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ ids })
    });
    if (!res.ok) throw new Error('Failed to mark notifications seen');
    return res.json();
  }

  // ——— UI RENDERING ———
  function renderNotifications(menu, items) {
    menu.innerHTML = ''; // clear existing

    if (items.length > 0) {
      // Bulk "Mark all as read"
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
          const refreshed = await fetchUnseen();
          renderNotifications(menu, refreshed);
        } catch (err) {
          console.error(err);
        } finally {
          bulkBtn.disabled = false;
        }
      });
      menu.appendChild(bulkBtn);
    }

    if (items.length === 0) {
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
      row.innerHTML = `
        <strong>${n.title}</strong><br>
        <small>${n.text}</small>
      `;
      row.addEventListener('click', async () => {
        try { await markSeen(n.id); }
        catch (err) { console.error(err); }
        window.location.href = n.module;
      });
      menu.appendChild(row);
    });
  }

  // ——— NOTIFICATION & POLLING ———
  async function updateNotifications() {
    try {
      const unseen = await fetchUnseen();
      notifications = unseen;

      // Desktop notifications only for IDs not yet notified
      if (window.Notification && Notification.permission === 'granted') {
        const notifiedSet = loadNotifiedSet();
        const toNotify = unseen.filter(n => !notifiedSet.has(n.id));

        toNotify.forEach(n => {
          const notif = new Notification(n.title, {
            body: n.text,
            icon: '/path/to/bell-icon.png',  // replace with your icon
            tag: `notif-${n.id}`,
            renotify: true
          });
          notif.onclick = () => {
            window.focus();
            window.location.href = n.module;
          };
          // mark as sent
          notifiedSet.add(n.id);
        });

        // persist updates
        saveNotifiedSet(notifiedSet);
      }

      // update red dot and menu
      document.getElementById('notif-dot').style.display =
        unseen.length > 0 ? 'block' : 'none';

    } catch (err) {
      console.error('Error fetching notifications:', err);
    }
  }

  // ——— INITIALIZATION ———
  document.addEventListener('DOMContentLoaded', () => {
    // 1) Ask for desktop-notification permission up front
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
        .then(perm => console.log('Notification permission:', perm))
        .catch(console.error);
    }

    // 2) Prepare header container
    const header = document.querySelector('header');
    header.style.position = header.style.position || 'relative';

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

    // 3) Move profile picture into iconsContainer
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

    // 4) Create the bell button + red dot
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

    // 5) Create dropdown menu container
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

    // 6) Bell click toggles dropdown
    btn.addEventListener('click', () => {
      const isOpen = menu.style.display === 'block';
      if (isOpen) {
        menu.style.display = 'none';
      } else {
        renderNotifications(menu, notifications);
        menu.style.display = 'block';
        dot.style.display = 'none';
      }
    });

    // 7) Click outside to close menu
    document.addEventListener('click', e => {
      if (!btn.contains(e.target) && !menu.contains(e.target)) {
        menu.style.display = 'none';
      }
    });

    // 8) Start polling
    updateNotifications();
    setInterval(updateNotifications, FETCH_INTERVAL_MS);
  });
})();
