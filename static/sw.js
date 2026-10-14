// Security Guardian Lite - PWA Service Worker
const CACHE_NAME = 'guardian-lite-v1';
const STATIC_ASSETS = [
  '/mobile',
  '/static/manifest.json',
  '/static/css/mobile.css',
  '/static/js/mobile.js',
  '/static/js/fingerprint.js',
  '/static/img/icon-192.png',
  '/static/img/icon-512.png',
  '/static/img/logo.svg',
  '/static/img/favicon.svg',
  '/static/img/favicon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('PWA cache pre-fetch warning:', err);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Never cache or intercept SSE stream or dynamic API calls
  if (event.request.url.includes('/api/')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).catch(() => {
        if (event.request.mode === 'navigate') {
          return caches.match('/mobile');
        }
      });
    })
  );
});
