const CACHE_NAME = 'my-cache-v4';

// List of all pages to cache
const pagesToCache = [
  '/', '/index', '/login_page', '/signup_page', '/account_page', '/admin_page',
  '/group-notes', '/setup', '/pws', '/battle', '/spectate_callback', '/spectate',
  '/bot-info', '/leaderboard', '/static/ocean2.jpg', '/static/zeeslag.png'
];

// Install Service Worker and cache pages + images
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      try {
        await cache.addAll(pagesToCache);
        console.log('Pages cached successfully.');
      } catch (error) {
        console.error('Failed to cache pages:', error);
      }
    })
  );
});

// Cache new requests dynamically (HTML + images)
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);
  
  // Match all HTML pages and images
  const shouldCache = pagesToCache.includes(url.pathname) || /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(url.pathname);

  if (shouldCache) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse; // Serve from cache
        }
        return fetch(event.request).then((networkResponse) => {
          return caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, networkResponse.clone()); // Cache new response
            return networkResponse;
          });
        });
      })
    );
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (url.pathname === '/test-session') {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        return cachedResponse || fetch(event.request).then((networkResponse) => {
          return caches.open('my-cache-v4').then((cache) => {
            cache.put(event.request, networkResponse.clone());
            return networkResponse;
          });
        });
      })
    );
  }
});


// Remove old caches when updating
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((cache) => cache !== CACHE_NAME)
          .map((cache) => caches.delete(cache))
      );
    })
  );
});
