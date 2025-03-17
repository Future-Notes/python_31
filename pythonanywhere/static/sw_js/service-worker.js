// service-worker.js

// Install event: perform setup tasks if needed.
self.addEventListener('install', event => {
  console.log('Service Worker installing.');
  self.skipWaiting();
});

// Activate event: cleanup tasks if necessary.
self.addEventListener('activate', event => {
  console.log('Service Worker activated.');
});

// Listen for push events (triggered from your Flask backend)
self.addEventListener('push', event => {
  console.log('Push event received:', event);
  let data = {};
  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data = { title: 'Notification', body: event.data.text() };
    }
  }
  const title = data.title || 'Upcoming Task';
  const options = {
    body: data.body || 'You have an upcoming task!',
    icon: data.icon || '/static/notification-icon.jpg', // Update with your icon path
    badge: data.badge || '/static/notification-badge.jpg'
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// Handle notification click events.
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if (client.url && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow('/scheduler-page');
      }
    })
  );
});
