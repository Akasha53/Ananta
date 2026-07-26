/**
 * Contrôle d'accès partagé par toutes les pages Ananta.
 */
(function initAccessShell(global) {
  "use strict";

  const auth = global.AnantaAuth;
  if (!auth) return;

  async function getStatus() {
    try {
      const response = await fetch("/auth/status");
      if (!response.ok) return null;
      return response.json();
    } catch {
      return null;
    }
  }

  function setMessage(element, message, tone) {
    element.textContent = message;
    element.dataset.tone = tone || "neutral";
  }

  async function install() {
    if (document.getElementById("ananta-access-trigger")) return;

    const wrapper = document.createElement("div");
    wrapper.className = "ananta-shell-dock";
    wrapper.innerHTML = `
      <button id="ananta-modules-trigger" class="ananta-modules-trigger" type="button"
        aria-expanded="false" aria-controls="ananta-modules-menu">
        <span aria-hidden="true">⌘</span><span>Modules</span>
      </button>
      <nav id="ananta-modules-menu" class="ananta-modules-menu" aria-label="Modules Ananta" hidden>
        <span class="ananta-access-kicker">Espace de travail</span>
        <a href="/web/html/entity.html"><strong>Entités</strong><small>Recherche et graphe</small></a>
        <a href="/web/html/index.html"><strong>Console</strong><small>Agent et investigations</small></a>
        <a href="/web/html/database.html"><strong>Dossiers</strong><small>Base de connaissances</small></a>
        <a href="/web/html/scheduled.html"><strong>Automations</strong><small>Scans programmés</small></a>
        <a href="/web/html/monitoring.html"><strong>Opérations</strong><small>Santé et audit</small></a>
      </nav>
      <button id="ananta-access-trigger" class="ananta-access-trigger" type="button" aria-label="Configurer l'accès API">
        <span class="ananta-access-dot" aria-hidden="true"></span>
        <span>Accès</span>
      </button>
      <dialog id="ananta-access-dialog" class="ananta-access-dialog" aria-labelledby="ananta-access-title">
        <form method="dialog" class="ananta-access-card">
          <header>
            <div>
              <span class="ananta-access-kicker">Sécurité de la session</span>
              <h2 id="ananta-access-title">Accès à Ananta</h2>
            </div>
            <button class="ananta-access-close" value="cancel" aria-label="Fermer">×</button>
          </header>

          <label for="ananta-api-key">Clé API</label>
          <input id="ananta-api-key" type="password" autocomplete="off" spellcheck="false"
            placeholder="ananta_…" />
          <p class="ananta-access-help">Conservée uniquement pendant cette session de navigateur.</p>

          <div class="ananta-access-actions">
            <button id="ananta-save-key" class="ananta-access-primary" type="button">Utiliser cette clé</button>
            <button id="ananta-clear-key" class="ananta-access-secondary" type="button">Retirer la clé</button>
          </div>

          <section id="ananta-bootstrap-section" class="ananta-bootstrap-section" hidden>
            <span class="ananta-access-kicker">Première installation</span>
            <label for="ananta-bootstrap-token">Jeton de bootstrap</label>
            <input id="ananta-bootstrap-token" type="password" autocomplete="off" spellcheck="false" />
            <label for="ananta-bootstrap-name">Nom de la clé administrateur</label>
            <input id="ananta-bootstrap-name" type="text" maxlength="100" value="Administrateur principal" />
            <button id="ananta-bootstrap-key" class="ananta-access-primary" type="button">
              Créer la première clé
            </button>
          </section>

          <p id="ananta-access-message" class="ananta-access-message" aria-live="polite"></p>
        </form>
      </dialog>
    `;
    document.body.appendChild(wrapper);

    const trigger = document.getElementById("ananta-access-trigger");
    const modulesTrigger = document.getElementById("ananta-modules-trigger");
    const modulesMenu = document.getElementById("ananta-modules-menu");
    const dialog = document.getElementById("ananta-access-dialog");
    const keyInput = document.getElementById("ananta-api-key");
    const message = document.getElementById("ananta-access-message");
    const bootstrapSection = document.getElementById("ananta-bootstrap-section");

    function refreshTrigger() {
      trigger.dataset.configured = auth.hasKey() ? "true" : "false";
      keyInput.value = auth.getKey();
    }

    async function openDialog() {
      refreshTrigger();
      const status = await getStatus();
      bootstrapSection.hidden = !(
        status && status.required && !status.initialized && status.bootstrap_configured
      );
      if (status && !status.required) {
        setMessage(message, "Authentification désactivée pour cette instance locale.", "neutral");
      } else if (auth.hasKey()) {
        setMessage(message, "Une clé est configurée pour cette session.", "success");
      } else {
        setMessage(message, "Une clé valide est nécessaire pour accéder aux dossiers.", "warning");
      }
      if (!dialog.open) dialog.showModal();
    }

    trigger.addEventListener("click", openDialog);
    global.addEventListener("ananta:auth-required", openDialog);
    modulesTrigger.addEventListener("click", () => {
      const willOpen = modulesMenu.hidden;
      modulesMenu.hidden = !willOpen;
      modulesTrigger.setAttribute("aria-expanded", String(willOpen));
    });
    document.addEventListener("click", (event) => {
      if (!wrapper.contains(event.target)) {
        modulesMenu.hidden = true;
        modulesTrigger.setAttribute("aria-expanded", "false");
      }
    });

    document.getElementById("ananta-save-key").addEventListener("click", () => {
      const value = keyInput.value.trim();
      if (!value.startsWith("ananta_")) {
        setMessage(message, "Format de clé invalide.", "error");
        return;
      }
      auth.setKey(value);
      refreshTrigger();
      setMessage(message, "Clé enregistrée pour cette session.", "success");
    });

    document.getElementById("ananta-clear-key").addEventListener("click", () => {
      auth.clear();
      keyInput.value = "";
      refreshTrigger();
      setMessage(message, "Clé retirée de la session.", "neutral");
    });

    document.getElementById("ananta-bootstrap-key").addEventListener("click", async () => {
      const token = document.getElementById("ananta-bootstrap-token").value.trim();
      const name = document.getElementById("ananta-bootstrap-name").value.trim();
      if (!token || !name) {
        setMessage(message, "Renseignez le jeton et le nom de la clé.", "error");
        return;
      }
      setMessage(message, "Création de la clé administrateur…", "neutral");
      try {
        const endpoint = `/api-keys/create?name=${encodeURIComponent(name)}&role=admin`;
        const response = await fetch(endpoint, { method: "POST", headers: { "X-Bootstrap-Token": token } });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.message || payload.detail || `HTTP ${response.status}`);
        auth.setKey(payload.api_key);
        keyInput.value = payload.api_key;
        bootstrapSection.hidden = true;
        refreshTrigger();
        setMessage(message, "Première clé créée et activée pour cette session.", "success");
      } catch (error) {
        setMessage(message, `Initialisation impossible : ${error.message}`, "error");
      }
    });

    refreshTrigger();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install, { once: true });
  } else {
    install();
  }
})(window);
