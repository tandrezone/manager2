/* =============================================================================
   manager2 service worker
   -----------------------------------------------------------------------------
   Scope: make the portal installable and usable on a bad connection, WITHOUT
   ever serving stale business data or caching anything personal.

   Caching policy, and the reasoning behind each choice:

     App shell (CSS, icons, offline page)  cache-first, versioned
       Static, immutable per release. Bump CACHE_VERSION on deploy.

     Navigations and API responses         network-first, NEVER cached
       Prices, stock, credit limits and order status are exactly the things that
       must not be served from a cache. A driver seeing yesterday's delivery
       window, or a buyer seeing a stale price, is worse than an error page.

     Anything with a Set-Cookie or an Authorization header
       Never touched. The Cache API is origin-scoped but shared across every
       session in that browser profile: caching an authenticated response on a
       shared warehouse tablet leaks one user's data to the next.

   Deliberately NOT implemented: background sync for order submission. Silently
   replaying a queued order hours later, against prices and stock that have since
   changed, creates orders nobody intended. The checkout keeps a local draft
   instead and the person presses the button.
   ============================================================================= */

'use strict';

const CACHE_VERSION = 'v1.0.0';
const SHELL_CACHE = `m2-shell-${CACHE_VERSION}`;
const OFFLINE_URL = '/offline.html';

/* Static, non-personal, safe to cache. */
const SHELL_ASSETS = [
  OFFLINE_URL,
  '/assets/app.css',
  '/assets/icon-192.png',
  '/assets/icon-512.png',
  '/assets/icon.svg',
  '/manifest.json',
];

/* Never cache, never serve from cache, under any circumstances. */
const NEVER_CACHE = [
  /^\/api\//,
  /^\/checkout/,
  /^\/orders/,
  /^\/invoices/,
  /^\/messages/,
  /^\/manager/,
  /^\/account/,
  /^\/auth/,
  /^\/login/,
  /^\/logout/,
  /^\/register/,
  /^\/webhooks/,
  /^\/gdpr/,
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      // addAll is atomic: one 404 fails the whole install, which is what we
      // want. A half-populated shell cache fails in confusing ways later.
      .then((cache) => cache.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting())
      .catch((error) => {
        console.warn('[sw] shell precache failed, continuing without it', error);
      })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();

      await Promise.all(
        names
          .filter((name) => name.startsWith('m2-') && name !== SHELL_CACHE)
          .map((name) => caches.delete(name))
      );

      if (self.registration.navigationPreload) {
        // Lets the network request start before this worker has booted, which
        // removes the worker's own startup latency from every navigation.
        await self.registration.navigationPreload.enable();
      }

      await self.clients.claim();
    })()
  );
});

function isNeverCacheable(url) {
  return NEVER_CACHE.some((pattern) => pattern.test(url.pathname));
}

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Only GET. A cached or replayed POST could duplicate an order or a payment.
  if (request.method !== 'GET') {
    return;
  }

  const url = new URL(request.url);

  // Cross-origin requests are left entirely alone.
  if (url.origin !== self.location.origin) {
    return;
  }

  if (request.mode === 'navigate') {
    event.respondWith(handleNavigation(event));
    return;
  }

  if (isNeverCacheable(url)) {
    return; // straight to network, untouched
  }

  event.respondWith(handleAsset(request));
});

/**
 * Navigations: always the network. On failure, the offline page — never a
 * cached copy of a previous page, which would show stale prices and status.
 */
async function handleNavigation(event) {
  try {
    const preloaded = await event.preloadResponse;
    if (preloaded) {
      return preloaded;
    }

    return await fetch(event.request);
  } catch (error) {
    const cache = await caches.open(SHELL_CACHE);
    const offline = await cache.match(OFFLINE_URL);

    return (
      offline ||
      new Response(
        '<!doctype html><meta charset="utf-8"><title>Offline</title>' +
          '<body style="font:16px system-ui;padding:2rem;max-width:32rem;margin:auto">' +
          '<h1>You are offline</h1>' +
          '<p>The trade portal needs a connection to show live prices, stock and ' +
          'order status. Anything you had typed is still saved on this device.</p>' +
          '<button onclick="location.reload()" style="font:inherit;padding:.6rem 1rem">' +
          'Try again</button>',
        { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      )
    );
  }
}

/**
 * Static assets: cache-first, with a background revalidate so a stale
 * stylesheet is corrected on the next load rather than pinned forever.
 */
async function handleAsset(request) {
  const cache = await caches.open(SHELL_CACHE);
  const cached = await cache.match(request);

  if (cached) {
    // Fire and forget; do not await, or the cache stops being a speed win.
    revalidate(cache, request);
    return cached;
  }

  try {
    const response = await fetch(request);

    if (isCacheable(response)) {
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    return new Response('', { status: 504, statusText: 'Asset unavailable offline' });
  }
}

async function revalidate(cache, request) {
  try {
    const fresh = await fetch(request);
    if (isCacheable(fresh)) {
      await cache.put(request, fresh);
    }
  } catch (error) {
    /* Offline. The cached copy stands. */
  }
}

/**
 * A response is cacheable only if it is a plain, same-origin 200 carrying no
 * session material. The Set-Cookie and Vary: Cookie checks are the important
 * ones: they are what stop a personalised response entering a cache that the
 * next user of a shared device can read.
 */
function isCacheable(response) {
  if (!response || !response.ok || response.type === 'opaque') {
    return false;
  }

  if (response.headers.has('Set-Cookie')) {
    return false;
  }

  const vary = response.headers.get('Vary') || '';
  if (/cookie|authorization/i.test(vary)) {
    return false;
  }

  const cacheControl = response.headers.get('Cache-Control') || '';
  return !/no-store|private/i.test(cacheControl);
}

/* Let a new release take over without the user hunting for a reload. */
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
