const CACHE_NAME = 'vue-pwa-cache-v1';
const urlsToCache = ['/', '/main', '/inbox', '/auction', '/settings', '/index.html', '/EULA.html', '/privacy_policy.html', '/terms_of_service.html', '/assets/logo.png', '/assets/placeholder-avatar.png','/favicon.ico'];

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
});

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    event.respondWith(
      fetch(event.request).catch(() => {
        return saveRequestForLater(event.request);
      })
    );
  } else {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        return cachedResponse || fetch(event.request);
      })
    );
  }
});

// Save failed requests
function saveRequestForLater(request) {
  return request.clone().text().then((body) => {
    const requestData = {
      url: request.url,
      method: request.method,
      body: body,
      headers: Array.from(request.headers.entries()),
    };
    return idbKeyval.set('pendingRequests', requestData); // Store in IndexedDB
  });
}

// Listen for online event to retry requests
self.addEventListener('online', () => {
  idbKeyval.get('pendingRequests').then((requests) => {
    requests.forEach((requestData) => {
      fetch(requestData.url, {
        method: requestData.method,
        body: requestData.body,
        headers: new Headers(requestData.headers),
      }).then(() => idbKeyval.del('pendingRequests')); // Remove after successful send
    });
  });
});
