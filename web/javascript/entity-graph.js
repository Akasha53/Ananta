/**
 * ANANTA - Graphe d'entité
 *
 * L'entité est au centre. Tout ce qu'on sait d'elle gravite autour :
 * les personnes, les sociétés liées, et les faits eux-mêmes (identité,
 * situation légale, finances, empreinte numérique, contacts, risques).
 *
 * Cinq dispositions, une seule structure de données :
 *   orbit         - anneaux concentriques animés, un anneau par nature d'objet
 *   force         - simulation ressorts/répulsion, laisse émerger les grappes
 *   radial        - organigramme radial, par niveau hiérarchique
 *   constellation - grappes thématiques séparées, façon carte du ciel
 *   sunburst      - secteurs concentriques, un secteur par catégorie
 *
 * Cliquer un nœud l'inspecte. Le recentrer (double-clic ou bouton) rejoue la
 * disposition autour de lui : on descend dans le graphe sans le perdre.
 *
 * Rendu Canvas 2D, sans dépendance externe (la page reste utilisable hors ligne).
 */

(function (global) {
  "use strict";

  // ==================== PALETTE ====================

  const PALETTE = {
    organization: { fill: "#0e7490", stroke: "#22d3ee", glow: "rgba(34,211,238,0.55)", label: "Organisation" },
    person: { fill: "#5b21b6", stroke: "#a78bfa", glow: "rgba(167,139,250,0.55)", label: "Personne" },
    unknown: { fill: "#334155", stroke: "#94a3b8", glow: "rgba(148,163,184,0.4)", label: "Indéterminé" },
    identity: { fill: "#0c4a6e", stroke: "#38bdf8", glow: "rgba(56,189,248,0.45)", label: "Identité" },
    legal: { fill: "#065f46", stroke: "#34d399", glow: "rgba(52,211,153,0.45)", label: "Légal" },
    financial: { fill: "#78350f", stroke: "#fbbf24", glow: "rgba(251,191,36,0.45)", label: "Financier" },
    digital: { fill: "#1e3a8a", stroke: "#60a5fa", glow: "rgba(96,165,250,0.45)", label: "Numérique" },
    contact: { fill: "#831843", stroke: "#f472b6", glow: "rgba(244,114,182,0.45)", label: "Contact" },
    network: { fill: "#4c1d95", stroke: "#c084fc", glow: "rgba(192,132,252,0.45)", label: "Réseau" },
    risk: { fill: "#7f1d1d", stroke: "#f87171", glow: "rgba(248,113,113,0.55)", label: "Risque" },
    general: { fill: "#334155", stroke: "#94a3b8", glow: "rgba(148,163,184,0.35)", label: "Divers" },
  };

  const CATEGORY_ORDER = [
    "identity", "legal", "financial", "network", "digital", "contact", "risk", "general",
  ];

  const LAYOUTS = ["orbit", "force", "radial", "constellation", "sunburst"];

  // ==================== UTILITAIRES ====================

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function shortText(value, max) {
    const text = String(value === null || value === undefined ? "" : value);
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  function formatValue(value) {
    if (value === null || value === undefined) return "—";
    if (typeof value === "boolean") return value ? "oui" : "non";
    if (Array.isArray(value)) return value.slice(0, 4).join(", ");
    if (typeof value === "object") {
      return Object.entries(value).slice(0, 3).map(([k, v]) => `${k}: ${v}`).join(", ");
    }
    return String(value);
  }

  function humanize(name) {
    return String(name || "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
  }

  function easeInOutCubic(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  // Générateur pseudo-aléatoire déterministe : deux rendus du même dossier
  // donnent exactement la même carte (indispensable pour s'y retrouver).
  function seededRandom(seed) {
    let state = 0;
    for (let i = 0; i < seed.length; i += 1) {
      state = (state * 31 + seed.charCodeAt(i)) >>> 0;
    }
    return function next() {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state / 4294967296;
    };
  }

  // ==================== CONSTRUCTION DU GRAPHE ====================

  /**
   * Transforme un dossier en nœuds/arêtes centrés sur `centerKey`.
   * Les faits deviennent des nœuds : ce sont eux qui « gravitent ».
   */
  function buildGraph(dossier, centerKey, options) {
    const opts = options || {};
    const maxFactsPerCategory = opts.maxFactsPerCategory || 7;
    const entities = dossier.entities || [];
    const relationships = dossier.relationships || [];

    const byKey = {};
    entities.forEach((entity) => {
      byKey[entity.key] = entity;
    });

    const center = byKey[centerKey] || entities.find((e) => e.key === dossier.root_key) || entities[0];
    if (!center) return { nodes: [], edges: [], center: null };

    const nodes = [];
    const edges = [];
    const index = {};

    function addNode(node) {
      if (index[node.id]) return index[node.id];
      index[node.id] = node;
      nodes.push(node);
      return node;
    }

    // --- Nœud central
    const centerNode = addNode({
      id: center.key,
      kind: "entity",
      category: center.kind,
      label: center.label,
      sublabel: center.kind === "person" ? "Personne" : center.kind === "organization" ? "Organisation" : "Entité",
      confidence: center.confidence,
      weight: 1,
      isCenter: true,
      entity: center,
      aliases: center.aliases || [],
    });

    // --- Faits du centre, regroupés par catégorie
    const grouped = {};
    (center.attributes || []).filter((attribute) => {
      const sourceId = String((attribute.provenance || {}).source_id || "");
      if (["related_person", "related_organization"].includes(attribute.name)) return false;
      if (
        sourceId.startsWith("briefing_") &&
        ["analyst_note", "job_title", "relationship"].includes(attribute.name)
      ) {
        return false;
      }
      if (
        ["full_name", "legal_name"].includes(attribute.name) &&
        foldLabel(attribute.value) === foldLabel(center.label)
      ) {
        return false;
      }
      return true;
    }).forEach((attribute) => {
      const category = CATEGORY_ORDER.includes(attribute.category) ? attribute.category : "general";
      (grouped[category] = grouped[category] || []).push(attribute);
    });

    CATEGORY_ORDER.forEach((category) => {
      const list = (grouped[category] || []).sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
      if (!list.length) return;

      const shown = list.slice(0, maxFactsPerCategory);
      shown.forEach((attribute, position) => {
        const id = `fact:${category}:${attribute.name}:${position}`;
        addNode({
          id,
          kind: "fact",
          category,
          label: shortText(formatValue(attribute.value), 42),
          sublabel: attribute.label || humanize(attribute.name),
          confidence: attribute.confidence,
          weight: 0.35 + (attribute.confidence || 0) * 0.35,
          attribute,
          inferred: (attribute.provenance || {}).method === "inference",
        });
        edges.push({ source: centerNode.id, target: id, kind: "fact", category, strength: 0.4 });
      });

      if (list.length > shown.length) {
        const id = `more:${category}`;
        addNode({
          id,
          kind: "more",
          category,
          label: `+${list.length - shown.length} autres`,
          sublabel: PALETTE[category].label,
          confidence: 0.5,
          weight: 0.4,
          hidden: list.slice(maxFactsPerCategory),
        });
        edges.push({ source: centerNode.id, target: id, kind: "fact", category, strength: 0.35 });
      }
    });

    // --- Entités liées (directement ou non)
    const linked = new Set([center.key]);
    relationships.forEach((relationship) => {
      if (relationship.source === center.key) linked.add(relationship.target);
      if (relationship.target === center.key) linked.add(relationship.source);
    });

    // Second cercle : entités liées aux entités liées (structure de groupe, collègues)
    relationships.forEach((relationship) => {
      if (linked.has(relationship.source)) linked.add(relationship.target);
      if (linked.has(relationship.target)) linked.add(relationship.source);
    });

    linked.forEach((key) => {
      if (key === center.key) return;
      const entity = byKey[key];
      if (!entity) return;

      const rank = Number(entity.attributes ? valueOf(entity, "hierarchy_rank") : 0) || 0;
      addNode({
        id: entity.key,
        kind: "entity",
        category: entity.kind,
        label: entity.label,
        sublabel: entitySublabel(entity, relationships, center),
        confidence: entity.confidence,
        weight: entity.kind === "organization" ? 0.8 : 0.65,
        entity,
        rank,
        factCount: (entity.attributes || []).length,
      });
    });

    relationships.forEach((relationship) => {
      if (!index[relationship.source] || !index[relationship.target]) return;
      edges.push({
        source: relationship.source,
        target: relationship.target,
        kind: "relation",
        label: relationshipLabel(relationship),
        type: relationship.type,
        confidence: relationship.confidence,
        strength: 0.85,
      });
    });

    return { nodes, edges, center: centerNode };
  }

  function valueOf(entity, name) {
    const matches = (entity.attributes || []).filter((a) => a.name === name);
    if (!matches.length) return null;
    return matches.sort((a, b) => (b.confidence || 0) - (a.confidence || 0))[0].value;
  }

  function foldLabel(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .trim()
      .toLowerCase();
  }

  function relationshipLabel(relationship) {
    const fallbackLabels = {
      officer_of: "Dirigeant",
      possible_officer_of: "Dirigeant possible",
      publicly_linked_to: "Lien public",
      employee_of: "Travaille pour",
      owns: "Détient",
      subsidiary_of: "Filiale de",
      spouse_of: "Conjoint public",
      child_of: "Enfant de",
      parent_of: "Parent de",
      sibling_of: "Fratrie publique",
    };
    const label =
      relationship.role ||
      fallbackLabels[relationship.type] ||
      String(relationship.type || "").replace(/_/g, " ");
    return String(relationship.type || "").startsWith("possible_")
      ? `À vérifier · ${label}`
      : label;
  }

  function roleOf(entity, relationships, centerKey) {
    const match = relationships.find(
      (r) =>
        (r.source === entity.key && r.target === centerKey) ||
        (r.target === entity.key && r.source === centerKey)
    );
    if (!match) return null;
    return relationshipLabel(match);
  }

  function entitySublabel(entity, relationships, center) {
    if (
      entity.key !== center.key &&
      entity.kind === center.kind &&
      foldLabel(entity.label) === foldLabel(center.label)
    ) {
      const birthYear = valueOf(entity, "birth_year");
      return birthYear
        ? `Homonyme possible · ${birthYear}`
        : "Homonyme possible";
    }
    return (
      roleOf(entity, relationships, center.key) ||
      (entity.kind === "person" ? "Personne" : "Organisation")
    );
  }

  // ==================== DISPOSITIONS ====================

  const Layouts = {
    /**
     * Anneaux concentriques : les faits proches, les personnes ensuite,
     * les organisations à l'extérieur. Chaque anneau tourne à sa vitesse.
     */
    orbit(graph, size) {
      const facts = [];
      const persons = [];
      const orgs = [];

      graph.nodes.forEach((node) => {
        if (node.isCenter) return;
        if (node.kind === "fact" || node.kind === "more") facts.push(node);
        else if (node.category === "person") persons.push(node);
        else orgs.push(node);
      });

      // Les faits sont groupés par catégorie : chaque anneau montre alors des
      // arcs cohérents plutôt qu'un mélange.
      facts.sort((a, b) => {
        const ca = CATEGORY_ORDER.indexOf(a.category);
        const cb = CATEGORY_ORDER.indexOf(b.category);
        if (ca !== cb) return ca - cb;
        return (b.confidence || 0) - (a.confidence || 0);
      });

      // Densité maximale par anneau : au-delà, les libellés se chevauchent.
      const PER_RING = 11;
      const factRings = [];
      for (let start = 0; start < facts.length; start += PER_RING) {
        factRings.push(facts.slice(start, start + PER_RING));
      }
      if (!factRings.length) factRings.push([]);

      const rings = factRings.concat([persons, orgs]);
      const unit = Math.min(size.width, size.height) / 2;
      const inner = 0.34;
      const step = (0.95 - inner) / Math.max(1, rings.length - 1);

      rings.forEach((ring, ringIndex) => {
        const radius = unit * (inner + ringIndex * step);
        const speed = (ringIndex % 2 ? -1 : 1) * (0.042 - ringIndex * 0.006);
        ring.forEach((node, position) => {
          node.orbit = {
            radius,
            // Décalage d'un demi-pas entre anneaux : évite l'alignement radial
            angle: ((position + (ringIndex % 2 ? 0.5 : 0)) / Math.max(1, ring.length)) * Math.PI * 2,
            speed: Math.max(0.01, Math.abs(speed)) * Math.sign(speed || 1),
          };
        });
      });

      graph.animated = true;
      graph.applyPositions = function (time) {
        graph.nodes.forEach((node) => {
          if (node.isCenter) {
            node.x = 0;
            node.y = 0;
            return;
          }
          if (!node.orbit) return;
          const angle = node.orbit.angle + time * node.orbit.speed;
          node.x = Math.cos(angle) * node.orbit.radius;
          node.y = Math.sin(angle) * node.orbit.radius * 0.82; // ellipse : profondeur
        });
      };
    },

    /**
     * Simulation ressorts/répulsion : les grappes réelles apparaissent
     * d'elles-mêmes (une personne très reliée se rapproche du centre).
     */
    force(graph, size) {
      const random = seededRandom(graph.center ? graph.center.id : "seed");
      const unit = Math.min(size.width, size.height) / 2;

      graph.nodes.forEach((node) => {
        const angle = random() * Math.PI * 2;
        const radius = node.isCenter ? 0 : unit * (0.25 + random() * 0.7);
        node.x = Math.cos(angle) * radius;
        node.y = Math.sin(angle) * radius;
        node.vx = 0;
        node.vy = 0;
      });

      const adjacency = {};
      graph.edges.forEach((edge) => {
        (adjacency[edge.source] = adjacency[edge.source] || []).push(edge);
      });

      graph.animated = true;
      graph.applyPositions = function () {
        const repulsion = unit * unit * 0.055;
        const nodes = graph.nodes;

        for (let i = 0; i < nodes.length; i += 1) {
          const a = nodes[i];
          if (a.isCenter) continue;
          for (let j = i + 1; j < nodes.length; j += 1) {
            const b = nodes[j];
            let dx = a.x - b.x;
            let dy = a.y - b.y;
            let distanceSquared = dx * dx + dy * dy;
            if (distanceSquared < 1) {
              dx = (random() - 0.5) * 2;
              dy = (random() - 0.5) * 2;
              distanceSquared = 1;
            }
            const force = repulsion / distanceSquared;
            const distance = Math.sqrt(distanceSquared);
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;
            a.vx += fx;
            a.vy += fy;
            if (!b.isCenter) {
              b.vx -= fx;
              b.vy -= fy;
            }
          }
        }

        graph.edges.forEach((edge) => {
          const a = graph.index[edge.source];
          const b = graph.index[edge.target];
          if (!a || !b) return;
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const distance = Math.sqrt(dx * dx + dy * dy) || 1;
          const target = edge.kind === "relation" ? unit * 0.42 : unit * 0.24;
          const force = (distance - target) * 0.012 * (edge.strength || 0.5);
          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;
          if (!a.isCenter) {
            a.vx += fx;
            a.vy += fy;
          }
          if (!b.isCenter) {
            b.vx -= fx;
            b.vy -= fy;
          }
        });

        graph.nodes.forEach((node) => {
          if (node.isCenter) {
            node.x = 0;
            node.y = 0;
            return;
          }
          node.vx -= node.x * 0.004;   // rappel vers le centre
          node.vy -= node.y * 0.004;
          node.vx *= 0.86;             // amortissement
          node.vy *= 0.86;
          node.x += clamp(node.vx, -18, 18);
          node.y += clamp(node.vy, -18, 18);
        });
      };
    },

    /**
     * Organigramme radial : niveau hiérarchique = distance au centre.
     * Le rang vient de `hierarchy_rank` quand l'annuaire d'équipe l'a déduit.
     */
    radial(graph, size) {
      const unit = Math.min(size.width, size.height) / 2;
      const levels = {};

      graph.nodes.forEach((node) => {
        if (node.isCenter) return;
        let level;
        if (node.kind === "fact" || node.kind === "more") level = 1;
        else if (node.category === "person") level = 2 + clamp((node.rank || 3) - 1, 0, 4);
        else level = 2;
        (levels[level] = levels[level] || []).push(node);
      });

      const keys = Object.keys(levels).map(Number).sort((a, b) => a - b);
      const maxLevel = keys.length ? keys[keys.length - 1] : 1;

      keys.forEach((level) => {
        const ring = levels[level];
        ring.sort((a, b) => String(a.category).localeCompare(String(b.category)) || a.label.localeCompare(b.label));
        const radius = unit * (0.22 + (level / (maxLevel + 0.5)) * 0.72);
        ring.forEach((node, position) => {
          const spread = Math.PI * 2;
          const angle = (position / Math.max(1, ring.length)) * spread - Math.PI / 2;
          node.x = Math.cos(angle) * radius;
          node.y = Math.sin(angle) * radius;
        });
      });

      graph.animated = false;
      graph.applyPositions = null;
    },

    /**
     * Constellation : une grappe par catégorie, disposée en couronne.
     * Sépare visuellement « ce qu'on sait » en domaines distincts.
     */
    constellation(graph, size) {
      const unit = Math.min(size.width, size.height) / 2;
      const clusters = {};

      graph.nodes.forEach((node) => {
        if (node.isCenter) return;
        const key = node.kind === "entity" ? node.category : node.category;
        (clusters[key] = clusters[key] || []).push(node);
      });

      const keys = Object.keys(clusters).sort(
        (a, b) => CATEGORY_ORDER.indexOf(a) - CATEGORY_ORDER.indexOf(b)
      );

      keys.forEach((key, clusterIndex) => {
        const members = clusters[key];
        const angle = (clusterIndex / keys.length) * Math.PI * 2 - Math.PI / 2;
        const distance = unit * (key === "person" || key === "organization" ? 0.78 : 0.58);
        const cx = Math.cos(angle) * distance;
        const cy = Math.sin(angle) * distance * 0.85;
        const random = seededRandom(key + members.length);
        const spread = unit * 0.16 * Math.sqrt(Math.max(1, members.length) / 4);

        members.forEach((node, position) => {
          // Spirale interne : lisible même avec beaucoup de membres
          const t = position / Math.max(1, members.length);
          const localAngle = t * Math.PI * 5 + random() * 0.5;
          const localRadius = spread * (0.25 + t * 0.9);
          node.x = cx + Math.cos(localAngle) * localRadius;
          node.y = cy + Math.sin(localAngle) * localRadius * 0.9;
          node.twinkle = random() * Math.PI * 2;
        });
      });

      graph.animated = true;
      graph.applyPositions = function (time) {
        graph.nodes.forEach((node) => {
          if (node.isCenter) {
            node.x = 0;
            node.y = 0;
            return;
          }
          if (node.twinkle === undefined) return;
          node.pulse = 0.85 + Math.sin(time * 1.6 + node.twinkle) * 0.15;
        });
      };
    },

    /**
     * Secteurs concentriques : chaque catégorie occupe un secteur angulaire
     * proportionnel à son volume. Donne la structure du dossier d'un coup d'œil.
     */
    sunburst(graph, size) {
      const unit = Math.min(size.width, size.height) / 2;
      const groups = {};

      graph.nodes.forEach((node) => {
        if (node.isCenter) return;
        (groups[node.category] = groups[node.category] || []).push(node);
      });

      const keys = Object.keys(groups).sort(
        (a, b) => CATEGORY_ORDER.indexOf(a) - CATEGORY_ORDER.indexOf(b)
      );
      const total = graph.nodes.length - 1 || 1;

      let cursor = -Math.PI / 2;
      graph.sectors = [];

      keys.forEach((key) => {
        const members = groups[key];
        const share = members.length / total;
        const sweep = Math.max(share * Math.PI * 2, 0.18);
        const start = cursor;
        const end = cursor + sweep;
        cursor = end;

        graph.sectors.push({ category: key, start, end, count: members.length });

        members.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
        const perRing = Math.max(3, Math.ceil(Math.sqrt(members.length) * 1.6));
        members.forEach((node, position) => {
          const ring = Math.floor(position / perRing);
          const inRing = position % perRing;
          const radius = unit * (0.34 + ring * 0.17);
          const angle = start + ((inRing + 0.5) / perRing) * (end - start);
          node.x = Math.cos(angle) * radius;
          node.y = Math.sin(angle) * radius;
        });
      });

      graph.animated = false;
      graph.applyPositions = null;
    },
  };

  // ==================== RENDU ====================

  function EntityGraph(canvas, options) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.options = options || {};
    this.layout = "orbit";
    this.graph = { nodes: [], edges: [], index: {} };
    this.camera = { x: 0, y: 0, zoom: 1, targetZoom: 1 };
    this.hover = null;
    this.selected = null;
    this.filters = { person: true, organization: true, fact: true, risk: true };
    this.search = "";
    this.listeners = {};
    this.time = 0;
    this.transition = null;
    this.dragging = null;
    this.dpr = global.devicePixelRatio || 1;

    // Certains utilisateurs demandent moins d'animation : on fige alors les
    // orbites. Le graphe reste entièrement navigable, il ne tourne plus.
    const motionQuery = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)");
    this.reducedMotion = !!(motionQuery && motionQuery.matches);
    if (motionQuery && motionQuery.addEventListener) {
      motionQuery.addEventListener("change", (event) => {
        this.reducedMotion = event.matches;
      });
    }

    this._bind();
    this._resize();
    this._loop = this._loop.bind(this);
    global.requestAnimationFrame(this._loop);
  }

  EntityGraph.prototype.on = function (event, callback) {
    (this.listeners[event] = this.listeners[event] || []).push(callback);
    return this;
  };

  EntityGraph.prototype._emit = function (event, payload) {
    (this.listeners[event] || []).forEach((callback) => {
      try {
        callback(payload);
      } catch (error) {
        console.error("[entity-graph]", error);
      }
    });
  };

  EntityGraph.prototype.setDossier = function (dossier, centerKey) {
    this.dossier = dossier;
    this.trail = [];
    this.setCenter(centerKey || dossier.root_key, false);
  };

  EntityGraph.prototype.setCenter = function (centerKey, pushTrail) {
    if (!this.dossier) return;
    if (pushTrail && this.centerKey && this.centerKey !== centerKey) {
      this.trail = this.trail || [];
      this.trail.push(this.centerKey);
    }
    this.centerKey = centerKey;

    const built = buildGraph(this.dossier, centerKey, this.options);
    built.index = {};
    built.nodes.forEach((node) => {
      built.index[node.id] = node;
    });
    this.graph = built;
    this.selected = null;
    this.camera.x = 0;
    this.camera.y = 0;
    this.camera.zoom = 0.72;
    this.camera.targetZoom = 1;
    this._applyLayout();
    this._emit("center", { key: centerKey, entity: built.center ? built.center.entity : null, trail: this.trail });
  };

  EntityGraph.prototype.back = function () {
    if (!this.trail || !this.trail.length) return;
    const previous = this.trail.pop();
    this.setCenter(previous, false);
  };

  EntityGraph.prototype.setLayout = function (name) {
    if (LAYOUTS.indexOf(name) === -1) return;
    this.layout = name;
    this._applyLayout();
    this._emit("layout", name);
  };

  EntityGraph.prototype.setFilter = function (key, enabled) {
    this.filters[key] = enabled;
  };

  EntityGraph.prototype.setSearch = function (text) {
    this.search = (text || "").trim().toLowerCase();
  };

  EntityGraph.prototype.fit = function () {
    this.camera.x = 0;
    this.camera.y = 0;
    this.camera.targetZoom = 1;
  };

  EntityGraph.prototype._applyLayout = function () {
    const size = { width: this.width, height: this.height };
    (Layouts[this.layout] || Layouts.orbit)(this.graph, size);
    if (this.graph.applyPositions) this.graph.applyPositions(this.time);
    if (this.layout === "force") {
      // Quelques itérations à l'avance pour éviter l'explosion initiale
      for (let i = 0; i < 120; i += 1) this.graph.applyPositions(this.time);
    }
  };

  EntityGraph.prototype._bind = function () {
    const self = this;
    const canvas = this.canvas;

    global.addEventListener("resize", () => self._resize());

    canvas.addEventListener("mousemove", (event) => {
      const point = self._toWorld(event);
      if (self.dragging) {
        self.camera.x += (event.clientX - self.dragging.x) / self.camera.zoom;
        self.camera.y += (event.clientY - self.dragging.y) / self.camera.zoom;
        self.dragging = { x: event.clientX, y: event.clientY, moved: true };
        return;
      }
      const node = self._nodeAt(point);
      if (node !== self.hover) {
        self.hover = node;
        canvas.style.cursor = node ? "pointer" : "grab";
        self._emit("hover", node);
      }
    });

    canvas.addEventListener("mousedown", (event) => {
      self.dragging = { x: event.clientX, y: event.clientY, moved: false };
      canvas.style.cursor = "grabbing";
    });

    global.addEventListener("mouseup", (event) => {
      if (self.dragging && !self.dragging.moved) {
        const node = self._nodeAt(self._toWorld(event));
        self.selected = node;
        self._emit("select", node);
      }
      self.dragging = null;
      canvas.style.cursor = self.hover ? "pointer" : "grab";
    });

    canvas.addEventListener("dblclick", (event) => {
      const node = self._nodeAt(self._toWorld(event));
      if (node && node.kind === "entity" && !node.isCenter) {
        self.setCenter(node.id, true);
      } else if (node && node.kind === "more") {
        self._emit("expand", node);
      }
    });

    canvas.addEventListener(
      "wheel",
      (event) => {
        event.preventDefault();
        const factor = event.deltaY < 0 ? 1.12 : 1 / 1.12;
        self.camera.targetZoom = clamp(self.camera.targetZoom * factor, 0.25, 4.5);
      },
      { passive: false }
    );

    // Tactile : un doigt déplace, deux doigts zooment
    let pinch = null;
    canvas.addEventListener("touchstart", (event) => {
      if (event.touches.length === 1) {
        self.dragging = { x: event.touches[0].clientX, y: event.touches[0].clientY, moved: false };
      } else if (event.touches.length === 2) {
        pinch = Math.hypot(
          event.touches[0].clientX - event.touches[1].clientX,
          event.touches[0].clientY - event.touches[1].clientY
        );
      }
    }, { passive: true });

    canvas.addEventListener("touchmove", (event) => {
      if (event.touches.length === 1 && self.dragging) {
        self.camera.x += (event.touches[0].clientX - self.dragging.x) / self.camera.zoom;
        self.camera.y += (event.touches[0].clientY - self.dragging.y) / self.camera.zoom;
        self.dragging = { x: event.touches[0].clientX, y: event.touches[0].clientY, moved: true };
      } else if (event.touches.length === 2 && pinch) {
        const distance = Math.hypot(
          event.touches[0].clientX - event.touches[1].clientX,
          event.touches[0].clientY - event.touches[1].clientY
        );
        self.camera.targetZoom = clamp(self.camera.targetZoom * (distance / pinch), 0.25, 4.5);
        pinch = distance;
      }
    }, { passive: true });

    canvas.addEventListener("touchend", (event) => {
      if (self.dragging && !self.dragging.moved && event.changedTouches.length) {
        const touch = event.changedTouches[0];
        const node = self._nodeAt(self._toWorld(touch));
        self.selected = node;
        self._emit("select", node);
      }
      self.dragging = null;
      pinch = null;
    }, { passive: true });
  };

  EntityGraph.prototype._resize = function () {
    const rect = this.canvas.getBoundingClientRect();
    this.width = rect.width || 800;
    this.height = rect.height || 600;
    this.dpr = global.devicePixelRatio || 1;
    this.canvas.width = this.width * this.dpr;
    this.canvas.height = this.height * this.dpr;
    if (this.graph.nodes.length) this._applyLayout();
  };

  EntityGraph.prototype._toWorld = function (event) {
    const rect = this.canvas.getBoundingClientRect();
    const x = (event.clientX - rect.left - this.width / 2) / this.camera.zoom - this.camera.x;
    const y = (event.clientY - rect.top - this.height / 2) / this.camera.zoom - this.camera.y;
    return { x, y };
  };

  EntityGraph.prototype._radiusOf = function (node) {
    const base = node.isCenter ? 46 : 10 + node.weight * 22;
    return base * (node.pulse || 1);
  };

  EntityGraph.prototype._visible = function (node) {
    if (node.isCenter) return true;
    if (node.kind === "entity") {
      if (node.category === "person" && !this.filters.person) return false;
      if (node.category === "organization" && !this.filters.organization) return false;
    }
    if ((node.kind === "fact" || node.kind === "more")) {
      if (node.category === "risk") {
        if (!this.filters.risk) return false;
      } else if (!this.filters.fact) return false;
    }
    return true;
  };

  EntityGraph.prototype._matchesSearch = function (node) {
    if (!this.search) return true;
    const haystack = `${node.label} ${node.sublabel || ""}`.toLowerCase();
    return haystack.indexOf(this.search) !== -1;
  };

  EntityGraph.prototype._nodeAt = function (point) {
    let found = null;
    for (let i = this.graph.nodes.length - 1; i >= 0; i -= 1) {
      const node = this.graph.nodes[i];
      if (!this._visible(node)) continue;
      const radius = this._radiusOf(node) + 6;
      const dx = node.x - point.x;
      const dy = node.y - point.y;
      if (dx * dx + dy * dy <= radius * radius) {
        found = node;
        break;
      }
    }
    return found;
  };

  EntityGraph.prototype._loop = function (timestamp) {
    const seconds = timestamp / 1000;
    const delta = this.lastFrame ? seconds - this.lastFrame : 0.016;
    this.lastFrame = seconds;
    if (!this.reducedMotion) this.time += delta;

    this.camera.zoom += (this.camera.targetZoom - this.camera.zoom) * 0.12;

    if (this.graph.applyPositions && !(this.reducedMotion && this.layout === "force")) {
      this.graph.applyPositions(this.time);
    }
    this._render();

    global.requestAnimationFrame(this._loop);
  };

  EntityGraph.prototype._render = function () {
    const ctx = this.ctx;
    const { width, height, dpr } = this;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    this._renderBackdrop(ctx, width, height);

    ctx.save();
    ctx.translate(width / 2, height / 2);
    ctx.scale(this.camera.zoom, this.camera.zoom);
    ctx.translate(this.camera.x, this.camera.y);

    if (this.layout === "orbit") this._renderOrbitRings(ctx);
    if (this.layout === "sunburst") this._renderSectors(ctx);

    const highlighted = this.selected || this.hover;
    const neighbours = new Set();
    if (highlighted) {
      neighbours.add(highlighted.id);
      this.graph.edges.forEach((edge) => {
        if (edge.source === highlighted.id) neighbours.add(edge.target);
        if (edge.target === highlighted.id) neighbours.add(edge.source);
      });
    }

    this._labelQueue = [];

    // --- Arêtes
    this.graph.edges.forEach((edge) => {
      const a = this.graph.index[edge.source];
      const b = this.graph.index[edge.target];
      if (!a || !b || !this._visible(a) || !this._visible(b)) return;

      const dimmed = highlighted && !(neighbours.has(a.id) && neighbours.has(b.id));
      const palette = PALETTE[edge.category || b.category] || PALETTE.general;

      ctx.beginPath();
      if (edge.kind === "relation") {
        // Courbe : distingue les liens entre entités des rattachements de faits
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        const nx = -(b.y - a.y) * 0.12;
        const ny = (b.x - a.x) * 0.12;
        ctx.moveTo(a.x, a.y);
        ctx.quadraticCurveTo(mx + nx, my + ny, b.x, b.y);
      } else {
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
      }

      ctx.strokeStyle = dimmed
        ? "rgba(71,85,105,0.18)"
        : edge.kind === "relation"
        ? palette.glow
        : "rgba(148,163,184,0.28)";
      ctx.lineWidth = edge.kind === "relation" ? 1.8 : 1;
      ctx.stroke();

      // Libellé du lien : mis en file, la collision décidera de l'afficher
      if (edge.kind === "relation" && edge.label && this.camera.zoom > 0.85 && !dimmed) {
        (this._labelQueue = this._labelQueue || []).push({
          text: shortText(edge.label, 24),
          x: (a.x + b.x) / 2,
          y: (a.y + b.y) / 2 - 4,
          font: "9px 'JetBrains Mono', monospace",
          size: 9,
          color: "rgba(226,232,240,0.8)",
          priority: 50 + (edge.confidence || 0) * 10,
        });
      }
    });

    // --- Nœuds (le rendu des libellés est différé pour gérer les collisions)
    this.graph.nodes.forEach((node) => {
      if (!this._visible(node)) return;
      const dimmed =
        (highlighted && !neighbours.has(node.id)) || (this.search && !this._matchesSearch(node));
      this._renderNode(ctx, node, dimmed, node === highlighted);
    });
    this._renderLabels(ctx);

    ctx.restore();
  };

  /**
   * Dessine les libellés par ordre de priorité en sautant ceux qui
   * chevaucheraient un libellé déjà placé.
   *
   * Sans cela, une entité riche produit une bouillie de texte au centre : le
   * graphe devient joli mais illisible, ce qui est pire qu'inutile.
   */
  EntityGraph.prototype._renderLabels = function (ctx) {
    const placed = [];
    const queue = this._labelQueue.sort((a, b) => b.priority - a.priority);

    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    queue.forEach((label) => {
      ctx.font = label.font;
      const width = ctx.measureText(label.text).width;
      const height = label.size * 1.25;
      const box = {
        x1: label.x - width / 2 - 3,
        y1: label.y - height / 2,
        x2: label.x + width / 2 + 3,
        y2: label.y + height / 2,
      };

      const collides = placed.some(
        (other) => box.x1 < other.x2 && box.x2 > other.x1 && box.y1 < other.y2 && box.y2 > other.y1
      );
      if (collides) return;
      placed.push(box);

      // Plaque sombre : le texte reste lisible par-dessus les halos.
      ctx.fillStyle = "rgba(2,6,23,0.72)";
      ctx.fillRect(box.x1, box.y1, box.x2 - box.x1, box.y2 - box.y1);

      ctx.fillStyle = label.color;
      ctx.fillText(label.text, label.x, label.y);
    });

    ctx.textBaseline = "alphabetic";
  };

  EntityGraph.prototype._renderBackdrop = function (ctx, width, height) {
    const gradient = ctx.createRadialGradient(
      width / 2, height / 2, 10,
      width / 2, height / 2, Math.max(width, height) * 0.75
    );
    gradient.addColorStop(0, "rgba(8,47,73,0.55)");
    gradient.addColorStop(0.55, "rgba(2,6,23,0.9)");
    gradient.addColorStop(1, "#020617");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, width, height);

    // Poussière d'étoiles : donne la profondeur sans distraire
    if (!this._stars) {
      const random = seededRandom("ananta-stars");
      this._stars = [];
      for (let i = 0; i < 90; i += 1) {
        this._stars.push({ x: random(), y: random(), r: random() * 1.2 + 0.2, p: random() * 6.28 });
      }
    }
    this._stars.forEach((star) => {
      const alpha = 0.18 + Math.sin(this.time * 0.8 + star.p) * 0.12;
      ctx.fillStyle = `rgba(148,197,255,${Math.max(0.04, alpha)})`;
      ctx.beginPath();
      ctx.arc(star.x * width, star.y * height, star.r, 0, Math.PI * 2);
      ctx.fill();
    });
  };

  EntityGraph.prototype._renderOrbitRings = function (ctx) {
    const radii = new Set();
    this.graph.nodes.forEach((node) => {
      if (node.orbit) radii.add(Math.round(node.orbit.radius));
    });
    radii.forEach((radius) => {
      ctx.beginPath();
      ctx.ellipse(0, 0, radius, radius * 0.82, 0, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(56,189,248,0.10)";
      ctx.lineWidth = 1;
      ctx.stroke();
    });
  };

  EntityGraph.prototype._renderSectors = function (ctx) {
    if (!this.graph.sectors) return;
    const unit = Math.min(this.width, this.height) / 2;
    this.graph.sectors.forEach((sector) => {
      const palette = PALETTE[sector.category] || PALETTE.general;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, unit * 0.95, sector.start, sector.end);
      ctx.closePath();
      ctx.fillStyle = palette.glow.replace(/0\.\d+\)/, "0.055)");
      ctx.fill();

      const mid = (sector.start + sector.end) / 2;
      ctx.save();
      ctx.translate(Math.cos(mid) * unit * 0.99, Math.sin(mid) * unit * 0.99);
      ctx.font = "bold 10px 'JetBrains Mono', monospace";
      ctx.fillStyle = palette.stroke;
      ctx.textAlign = Math.cos(mid) < 0 ? "right" : "left";
      ctx.fillText(`${palette.label} (${sector.count})`, 0, 0);
      ctx.restore();
    });
  };

  EntityGraph.prototype._renderNode = function (ctx, node, dimmed, isActive) {
    const palette = PALETTE[node.category] || PALETTE.general;
    const radius = this._radiusOf(node);
    const alpha = dimmed ? 0.22 : 1;

    // Halo
    if (!dimmed) {
      const glow = ctx.createRadialGradient(node.x, node.y, radius * 0.4, node.x, node.y, radius * 2.4);
      glow.addColorStop(0, palette.glow);
      glow.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius * 2.4, 0, Math.PI * 2);
      ctx.fill();
    }

    // Corps
    ctx.globalAlpha = alpha;
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = palette.fill;
    ctx.fill();
    ctx.lineWidth = isActive ? 3 : node.isCenter ? 2.5 : 1.5;
    ctx.strokeStyle = isActive ? "#f8fafc" : palette.stroke;
    ctx.stroke();

    // Anneau de confiance
    if (typeof node.confidence === "number" && node.confidence > 0) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius + 4, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * node.confidence);
      ctx.strokeStyle = dimmed ? "rgba(148,163,184,0.2)" : palette.stroke;
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Marqueur d'hypothèse non vérifiée
    if (node.inferred && !dimmed) {
      ctx.beginPath();
      ctx.arc(node.x + radius * 0.75, node.y - radius * 0.75, 3.2, 0, Math.PI * 2);
      ctx.fillStyle = "#fbbf24";
      ctx.fill();
    }

    // Libellés : mis en file, dessinés après tous les nœuds (anti-collision)
    if (!dimmed) {
      const queue = this._labelQueue || (this._labelQueue = []);

      if (node.isCenter) {
        queue.push({
          text: shortText(node.label, 32), x: node.x, y: node.y + radius + 22,
          font: "bold 16px 'JetBrains Mono', monospace", size: 16,
          color: "#f1f5f9", priority: 1000,
        });
        queue.push({
          text: node.sublabel, x: node.x, y: node.y + radius + 40,
          font: "11px 'JetBrains Mono', monospace", size: 11,
          color: palette.stroke, priority: 999,
        });
      } else {
        // Les entités priment sur les faits : on veut toujours lire les noms.
        const isEntity = node.kind === "entity";
        const priority = (isActive ? 900 : 0) + (isEntity ? 500 : 0) + (node.confidence || 0) * 100;

        // Tout le monde propose son libellé ; l'anti-collision garde ce qui
        // tient à l'écran, en commençant par le plus important.
        {
          queue.push({
            text: shortText(node.label, isEntity ? 26 : 22),
            x: node.x, y: node.y + radius + 12,
            font: `bold ${isEntity ? 11 : 9.5}px 'JetBrains Mono', monospace`,
            size: isEntity ? 11 : 9.5,
            color: "#e2e8f0",
            priority,
          });
        }
        if (node.sublabel && (isActive || (isEntity && this.camera.zoom > 0.95))) {
          queue.push({
            text: shortText(node.sublabel, 24),
            x: node.x, y: node.y + radius + 25,
            font: "9px 'JetBrains Mono', monospace", size: 9,
            color: palette.stroke,
            priority: priority - 1,
          });
        }
      }
    }

    ctx.globalAlpha = 1;
  };

  // ==================== EXPORT ====================

  global.EntityGraph = EntityGraph;
  global.EntityGraphPalette = PALETTE;
  global.EntityGraphLayouts = LAYOUTS;
  global.buildEntityGraph = buildGraph;
})(typeof window !== "undefined" ? window : this);
