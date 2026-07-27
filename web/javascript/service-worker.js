/**
 * ANANTA PWA Service Worker
 * Gère le cache offline et les requêtes réseau
 */

const CACHE_NAME = 'ananta-v1.5.4';
const OFFLINE_URL = '/web/html/offline.html';

// Ressources à mettre en cache immédiatement
const PRECACHE_ASSETS = [
  '/web/html/entity.html',
  '/web/html/database.html',
  '/web/html/offline.html',
  '/web/css/tailwind.css',
  '/web/css/style.css',
  '/web/vendor/fontawesome/all.min.css',
  '/web/vendor/webfonts/fa-solid-900.woff2',
  '/web/vendor/fonts/jetbrains-mono.css',
  '/web/css/mobile.css',
  '/web/css/app-shell.css',
  '/web/javascript/api-client.js',
  '/web/javascript/app-shell.js',
  '/web/javascript/database.js',
  '/web/javascript/entity.js?v=1.5.4',
  '/web/javascript/entity-graph.js?v=1.5.4',
  '/web/javascript/entity-demo.js',
  '/web/manifest.json',
  '/web/icons/icon-192.png',
  '/web/icons/icon-512.png'
];

// Les réponses de ces API peuvent contenir des données personnelles ou
// opérationnelles. Elles ne doivent jamais entrer dans Cache Storage.
const PRIVATE_API_PREFIXES = [
  '/agent/',
  '/api-keys/',
  '/auth/',
  '/cache/',
  '/entity/',
  '/jobs/',
  '/llm/',
  '/monitoring/',
  '/osint/',
  '/scheduled-scans/',
  '/system/',
  '/workers/',
];

// Installation du service worker
self.addEventListener('install', (event) => {
  console.log('[SW] Installation...');

  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW] Mise en cache des ressources statiques');
        // Cache les ressources locales
        return cache.addAll(PRECACHE_ASSETS.filter(url => !url.startsWith('http')));
      })
      .then(() => {
        // Force l'activation immédiate
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('[SW] Erreur lors du precaching:', error);
      })
  );
});

// Activation du service worker
self.addEventListener('activate', (event) => {
  console.log('[SW] Activation...');

  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              console.log('[SW] Suppression ancien cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => {
        // Prend le contrôle immédiatement
        return self.clients.claim();
      })
  );
});

// Interception des requêtes
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Pour les requêtes non-GET (POST, DELETE, etc.), passer directement au réseau
  if (request.method !== 'GET') {
    event.respondWith(fetch(request));
    return;
  }

  if (PRIVATE_API_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
    event.respondWith(networkOnly(request));
    return;
  }

  // Les sondes non sensibles peuvent conserver un fallback réseau.
  if (url.pathname.startsWith('/health') || url.pathname.startsWith('/ready')) {
    event.respondWith(networkFirst(request));
    return;
  }

  // Stratégie pour les ressources CDN (Cache First avec fallback)
  if (url.hostname !== location.hostname) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // Stratégie pour les ressources statiques (Stale While Revalidate)
  event.respondWith(staleWhileRevalidate(request));
});

async function networkOnly(request) {
  try {
    return await fetch(request);
  } catch {
    return new Response(
      JSON.stringify({ error: 'Offline', message: 'Cette donnée exige une connexion au serveur.' }),
      {
        status: 503,
        headers: {
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json',
        },
      }
    );
  }
}

/**
 * Stratégie Network First (API)
 * Essaie le réseau, fallback sur le cache
 */
async function networkFirst(request) {
  try {
    const networkResponse = await fetch(request);

    // Cache la réponse si succès
    if (networkResponse.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }

    return networkResponse;
  } catch (error) {
    console.log('[SW] Network failed, trying cache:', request.url);

    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }

    // Pour les pages HTML, retourne la page offline
    if (request.headers.get('accept')?.includes('text/html')) {
      return caches.match(OFFLINE_URL);
    }

    // Retourne une réponse d'erreur JSON pour les API
    return new Response(
      JSON.stringify({
        error: 'Offline',
        message: 'Connexion réseau indisponible'
      }),
      {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

/**
 * Stratégie Cache First (CDN, fonts, icons)
 * Utilise le cache si disponible, sinon réseau
 */
async function cacheFirst(request) {
  const cachedResponse = await caches.match(request);

  if (cachedResponse) {
    return cachedResponse;
  }

  try {
    const networkResponse = await fetch(request);

    if (networkResponse.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }

    return networkResponse;
  } catch (error) {
    console.log('[SW] Cache miss and network failed:', request.url);
    return new Response('', { status: 404 });
  }
}

/**
 * Stratégie Stale While Revalidate (ressources statiques)
 * Retourne le cache immédiatement, met à jour en arrière-plan
 */
async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cachedResponse = await cache.match(request);

  // Lancer la mise à jour en arrière-plan
  const fetchPromise = fetch(request)
    .then((networkResponse) => {
      if (networkResponse.ok) {
        cache.put(request, networkResponse.clone());
      }
      return networkResponse;
    })
    .catch(() => null);

  // Retourne le cache immédiatement si disponible
  if (cachedResponse) {
    return cachedResponse;
  }

  // Sinon attend la réponse réseau
  const networkResponse = await fetchPromise;

  if (networkResponse) {
    return networkResponse;
  }

  // Fallback sur la page offline pour les HTML
  if (request.headers.get('accept')?.includes('text/html')) {
    return caches.match(OFFLINE_URL);
  }

  return new Response('', { status: 404 });
}

// Gestion des messages depuis l'application
self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }

  if (event.data === 'clearCache') {
    caches.delete(CACHE_NAME).then(() => {
      console.log('[SW] Cache vidé');
    });
  }
});

// Notification de mise à jour disponible
self.addEventListener('controllerchange', () => {
  console.log('[SW] Nouveau service worker activé');
});
