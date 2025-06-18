// static/sw.js
const DB_NAME = 'NotificationDB';
const STORE_NAME = 'seenNotifications';
const ITEM_KEY = 'seenSet';

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
        
        // Notify all clients about the update
        self.clients.matchAll().then(clients => {
          clients.forEach(client => {
            client.postMessage({ type: 'notification-seen', id });
          });
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

  const options = {
    body: data.body,
    icon: '/static/notification-icon.jpg',
    data: data.url
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
      .then(() => {
        if (data.id) {
          return addToSeenSet(data.id);
        }
      })
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
  console.warn('[SW] pushsubscriptionchange');
  // ← replace this with the same VAPID key you fetch in the client:
  const VAPID_KEY_B64 = '<YOUR_VAPID_PUBLIC_KEY>';

  // helper (you can hoist this above if you like)
  function urlB64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const b64     = (base64String + padding)
      .replace(/-/g, '+').replace(/_/g, '/');
    const raw     = atob(b64);
    return new Uint8Array([...raw].map(c => c.charCodeAt(0)));
  }

  event.waitUntil(
    // try to clean up old sub if it exists
    (event.subscription
      ? event.subscription.unsubscribe().catch(() => {})
      : Promise.resolve()
    )
    .then(() => {
      // re‑subscribe with your VAPID key
      return self.registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlB64ToUint8Array(VAPID_KEY_B64)
      });
    })
    .then(newSub => {
      // tell all open pages about the new subscription
      return self.clients.matchAll().then(clients => {
        clients.forEach(client => {
          client.postMessage({
            type:         'push-subscription-updated',
            subscription: newSub
          });
        });
      });
    })
  );
});