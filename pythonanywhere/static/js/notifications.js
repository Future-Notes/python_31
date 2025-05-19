// notifications.js

(function() {
  // ——— CONFIG ———
  const FETCH_INTERVAL_MS = 30_000;  // poll every 30s

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

  // ——— BUILD UI ———
  function createBellButton() {
    // Add a container around the bell if not already present
    const header = document.querySelector('header');
    const btn = document.createElement('button');
    btn.id    = 'notif-bell';
    btn.innerHTML = '🔔<span id="notif-dot"></span>';
    btn.style.position = 'relative';
    btn.style.fontSize = '1.5rem';
    btn.style.background = 'none';
    btn.style.border = 'none';
    btn.style.cursor = 'pointer';
    btn.title = 'Notifications';
    header.appendChild(btn);

    // Red dot
    const dot = document.getElementById('notif-dot');
    dot.style.position = 'absolute';
    dot.style.top = '4px';
    dot.style.right = '0';
    dot.style.width = '8px';
    dot.style.height = '8px';
    dot.style.borderRadius = '50%';
    dot.style.background = 'red';
    dot.style.display = 'none';

    return btn;
  }

  function createDropdownContainer() {
    const menu = document.createElement('div');
    menu.id = 'notif-menu';
    Object.assign(menu.style, {
      position: 'absolute',
      top: '2.5rem',
      right: '1rem',
      width: '280px',
      maxHeight: '320px',
      overflowY: 'auto',
      background: '#fff',
      border: '1px solid #ccc',
      borderRadius: '4px',
      boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
      zIndex: 1000,
      display: 'none',
      padding: '8px 0'
    });
    document.body.appendChild(menu);
    return menu;
  }

  function renderNotifications(menu, items) {
    menu.innerHTML = ''; // clear
    if (items.length === 0) {
      const empty = document.createElement('div');
      empty.textContent = 'No new notifications';
      empty.style.padding = '8px 16px';
      empty.style.color = '#666';
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
      // click → mark seen + redirect
      row.addEventListener('click', async () => {
        try {
          await markSeen(n.id);
        } catch (err) {
          console.error(err);
        }
        window.location.href = n.module;
      });
      menu.appendChild(row);
    });
  }

  // ——— MAIN INIT ———
  document.addEventListener('DOMContentLoaded', () => {
    const bell = createBellButton();
    const menu = createDropdownContainer();
    let notifications = [];

    async function updateNotifications() {
      try {
        const unseen = await fetchUnseen();
        notifications = unseen;
        document.getElementById('notif-dot').style.display =
          unseen.length > 0 ? 'block' : 'none';
      } catch (err) {
        console.error('Error fetching notifications:', err);
      }
    }

    // Poll every interval
    updateNotifications();
    setInterval(updateNotifications, FETCH_INTERVAL_MS);

    // Toggle menu on bell click
    bell.addEventListener('click', () => {
      const isOpen = menu.style.display === 'block';
      if (isOpen) {
        menu.style.display = 'none';
      } else {
        renderNotifications(menu, notifications);
        menu.style.display = 'block';
        // hide red dot once opened
        document.getElementById('notif-dot').style.display = 'none';
      }
    });

    // Close menu if clicking outside
    document.addEventListener('click', (e) => {
      if (!bell.contains(e.target) && !menu.contains(e.target)) {
        menu.style.display = 'none';
      }
    });
  });
})();
