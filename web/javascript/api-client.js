/**
 * Client API partagé.
 *
 * La clé reste dans sessionStorage : elle disparaît à la fermeture de l'onglet
 * et n'est jamais ajoutée aux requêtes vers des domaines tiers.
 */
(function initAnantaApiClient(global) {
  "use strict";

  const STORAGE_KEY = "ananta-api-key";
  const API_PREFIXES = [
    "/agent/", "/api-keys/", "/auth/", "/cache/", "/entity/", "/health",
    "/jobs/", "/llm/", "/monitoring/", "/osint/", "/ready",
    "/scheduled-scans/", "/system/", "/workers/",
  ];
  const nativeFetch = global.fetch.bind(global);

  function getKey() {
    return global.sessionStorage.getItem(STORAGE_KEY) || "";
  }

  function setKey(value) {
    const key = String(value || "").trim();
    if (key) global.sessionStorage.setItem(STORAGE_KEY, key);
    else global.sessionStorage.removeItem(STORAGE_KEY);
    global.dispatchEvent(new CustomEvent("ananta:auth-changed", { detail: { configured: Boolean(key) } }));
  }

  function isApiUrl(input) {
    let raw = input;
    if (typeof Request !== "undefined" && input instanceof Request) raw = input.url;
    if (typeof URL !== "undefined" && input instanceof URL) raw = input.toString();
    if (typeof raw !== "string") return false;

    try {
      const url = new URL(raw, global.location.href);
      return API_PREFIXES.some((prefix) => url.pathname.startsWith(prefix));
    } catch {
      return false;
    }
  }

  async function authenticatedFetch(input, init) {
    const options = Object.assign({}, init || {});
    if (isApiUrl(input)) {
      const headers = new Headers(
        options.headers || (typeof Request !== "undefined" && input instanceof Request ? input.headers : undefined)
      );
      const key = getKey();
      if (key && !headers.has("X-API-Key")) headers.set("X-API-Key", key);
      options.headers = headers;
    }

    const response = await nativeFetch(input, options);
    if (isApiUrl(input) && response.status === 401) {
      global.dispatchEvent(new CustomEvent("ananta:auth-required"));
    }
    return response;
  }

  global.AnantaAuth = Object.freeze({
    clear: () => setKey(""),
    fetch: authenticatedFetch,
    getKey,
    hasKey: () => Boolean(getKey()),
    setKey,
  });
  global.fetch = authenticatedFetch;
})(window);
