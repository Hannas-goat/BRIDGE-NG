// Deliberately minimal: this app is actively edited and already sends "no-cache, must-revalidate"
// on every static response (see serve_static in server.py), so this service worker exists only to
// satisfy the browser's installability requirement for "Add to Home Screen" — it does not cache
// or serve anything offline, every request just passes straight through to the network.
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
