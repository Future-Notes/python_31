const DB_NAME = 'NotificationDB';
const STORE_NAME = 'seenNotifications';
const ITEM_KEY = 'seenSet';
const VAPID_KEY_B64 = 'BGcLDjMs3BA--QdukrxV24URwXLHYyptr6TZLR-j79YUfDDlN8nohDeErLxX08i86khPPCz153Ygc3DrC7w1ZJk';

// IDB Helper with Transaction Completion Wait
async function idbOperation(operation) {
  return new Promise((resolve) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onerror = () => resolve();
    request.onsuccess = () => {
      const db = request.result;
      operation(db, resolve);
    };
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

async function addToSeenSet(id) {
  await idbOperation((db, resolve) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    
    const getRequest = store.get(ITEM_KEY);
    getRequest.onsuccess = () => {
      const currentSet = getRequest.result || [];
      if (!currentSet.includes(id)) {
        const newSet = [...currentSet, id];
        store.put(newSet, ITEM_KEY);
        
        self.clients.matchAll().then(clients => {
          clients.forEach(c =>
            c.postMessage({ type: 'notification-seen', id: data.id })
          );
        });
      }
      tx.oncomplete = resolve;
    };
  });
}

self.addEventListener('push', event => {
  let data = { id: null, title: 'Notification', body: '', url: '/' };
  if (event.data) {
    try { data = event.data.json(); }
    catch {/* ignore malformed */}
  }

  event.waitUntil(
    (async () => {
      // Check if any client page is visible
      const clients = await self.clients.matchAll({ type: 'window' });
      const isAppVisible = clients.some(client => 
        client.visibilityState === 'visible'
      );

      // Skip notification if app is visible
      if (isAppVisible) return;

      // Show notification if app isn't visible
      await self.registration.showNotification(data.title, {
        body: data.body,
        icon: '/static/notification-icon.jpg',
        data: data.url
      });

      // Mark as notified in backend
      if (data.id) {
        // Add timeout to prevent hung requests
        await Promise.race([
          fetch(`/notifications/notified/${data.id}`, {
            method: 'POST',
            credentials: 'include',
            headers: {'Content-Type':'application/json'}
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout')), 5000)
          )
        ]).catch(() => {});
      }
    })()
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data;
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(list => {
        for (const client of list) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }
        return clients.openWindow(url);
      })
  );
});

// 🔄 handle subscription expiration/rotation
self.addEventListener('pushsubscriptionchange', event => {
  event.waitUntil(
    (async () => {
      const oldSubscription = event.oldSubscription;
      const newSubscription = await self.registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlB64ToUint8Array(VAPID_KEY_B64)
      });

      // Notify clients to update backend
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'push-subscription-updated',
          subscription: newSubscription
        });
      });

      // Optional: Direct update from SW
      try {
        await fetch('/api/update-subscription', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Device-Id': 'direct-from-sw' // Special header for SW requests
          },
          body: JSON.stringify({
            old: oldSubscription.toJSON(),
            new: newSubscription.toJSON()
          })
        });
      } catch (e) {
        console.error('SW direct update failed', e);
      }
    })()
  );
});