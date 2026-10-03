// DOBE Scan — Service Worker for push notifications (iOS + Android)

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Handle incoming push
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: 'DOBE Scan', body: 'New token detected' };
  }

  const title = data.title || 'DOBE Scan';
  const options = {
    body: data.body || 'New token matched your filters',
    icon: data.icon || '/icon-192.png',
    badge: '/icon-192.png',
    tag: data.tag || 'dobe-token',
    data: { url: data.url || '/screener' },
    vibrate: [200, 100, 200],
    requireInteraction: false,
    silent: false
  };

  event.waitUntil(
    self.registration.showNotification(title, options).catch(() => {})
  );
});

// Handle notification click — works for home-screen (standalone) iOS & Android
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || '/screener';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Prefer already open screener window
      for (const client of clientList) {
        if (client.url && client.url.includes('/screener') && 'focus' in client) {
          client.navigate(targetUrl).catch(() => {});
          return client.focus();
        }
      }
      // Open new window / focus existing
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});
