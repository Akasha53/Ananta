/**
 * ANANTA - Dossier de démonstration.
 *
 * Entreprise fictive, utilisée pour présenter l'interface sans dépendre du
 * réseau ni exposer de données réelles. La structure est strictement celle
 * que renvoie `/entity/research` : ce que montre la démo est ce que produit
 * le moteur.
 */

(function (global) {
  "use strict";

  const OBSERVED = "2026-07-26T09:12:00+00:00";

  function fact(name, label, value, category, confidence, source, url, extra) {
    return Object.assign(
      {
        name,
        label,
        value,
        category,
        confidence,
        sensitivity: "public",
        valid_from: null,
        valid_to: null,
        provenance: {
          source_id: source,
          source_name: source,
          url: url || null,
          observed_at: OBSERVED,
          reliability: confidence,
          method: "api",
          snippet: null,
        },
      },
      extra || {}
    );
  }

  function personal(f) {
    f.sensitivity = "personal";
    return f;
  }

  function inferred(f) {
    f.provenance.method = "inference";
    return f;
  }

  const SIRENE = "https://annuaire-entreprises.data.gouv.fr/entreprise/842019561";
  const SITE = "https://novaterra-industries.fr";

  // ---------------------------------------------------------------- entités

  const root = {
    key: "organization:novaterra industries",
    kind: "organization",
    label: "NOVATERRA INDUSTRIES",
    aliases: ["NOVATERRA INDUSTRIES SAS", "Novaterra"],
    confidence: 0.94,
    is_root: true,
    selectors: [],
    attributes: [
      fact("legal_name", "Dénomination", "NOVATERRA INDUSTRIES", "identity", 0.99, "sirene", SIRENE),
      fact("legal_form", "Forme juridique", "SAS (société par actions simplifiée) (5710)", "legal", 0.97, "sirene", SIRENE),
      fact("siren", "SIREN", "842 019 561", "legal", 0.99, "sirene", SIRENE),
      fact("siret_siege", "SIRET du siège", "842 019 561 00027", "legal", 0.97, "sirene", SIRENE),
      fact("vat_number", "TVA intracom.", "FR52842019561", "legal", 0.98, "vies", "https://ec.europa.eu/taxation_customs/vies/"),
      fact("lei", "LEI", "969500K7T4V6PLBZ8T29", "legal", 0.96, "gleif", "https://search.gleif.org/"),
      fact("rcs_number", "RCS", "RCS Lyon 842 019 561", "legal", 0.88, "website_intel", SITE + "/mentions-legales"),
      fact("status", "Statut", "Active", "legal", 0.97, "sirene", SIRENE),
      fact("incorporation_date", "Date de création", "2018-09-04", "legal", 0.97, "sirene", SIRENE),
      fact("activity_code", "Code NAF/APE", "26.51B", "legal", 0.95, "sirene", SIRENE),
      fact("activity_label", "Activité", "Fabrication d'instrumentation scientifique et technique", "legal", 0.93, "sirene", SIRENE),
      fact("employee_range", "Effectif", "50 à 99 salariés", "legal", 0.85, "sirene", SIRENE),
      fact("share_capital", "Capital social", "1 250 000 €", "financial", 0.9, "website_intel", SITE + "/mentions-legales"),
      fact("revenue", "Chiffre d'affaires 2024", "18 400 000 €", "financial", 0.82, "pappers", "https://www.pappers.fr/"),
      fact("net_income", "Résultat 2024", "1 130 000 €", "financial", 0.82, "pappers", "https://www.pappers.fr/"),
      fact("establishments_count", "Établissements", 3, "legal", 0.9, "sirene", SIRENE),
      fact("headquarters_address", "Siège social", "14 avenue Tony Garnier, 69007 Lyon", "identity", 0.96, "sirene", SIRENE),
      fact("city", "Ville", "Lyon", "identity", 0.95, "sirene", SIRENE),
      fact("postal_code", "Code postal", "69007", "identity", 0.95, "sirene", SIRENE),
      fact("country", "Pays", "FR", "identity", 0.97, "sirene", SIRENE),
      fact("coordinates", "Coordonnées", "45.7325,4.8321", "identity", 0.8, "nominatim", "https://www.openstreetmap.org/"),
      fact("jurisdiction", "Juridiction", "FR", "legal", 0.95, "gleif", "https://search.gleif.org/"),

      fact("website", "Site officiel", SITE, "digital", 0.95, "website_intel", SITE),
      fact("website_title", "Titre du site", "Novaterra Industries — Instrumentation de précision", "digital", 0.85, "website_intel", SITE),
      fact("domain", "Domaine", "novaterra-industries.fr", "digital", 0.97, "dns_intel", null),
      fact("ip_addresses", "Adresses IP", ["185.199.110.153"], "digital", 0.9, "dns_intel", null),
      fact("mail_servers", "Serveurs de messagerie", ["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "digital", 0.92, "dns_intel", null),
      fact("mail_provider", "Messagerie", "Google Workspace", "digital", 0.88, "dns_intel", null),
      fact("spf_record", "SPF", "v=spf1 include:_spf.google.com ~all", "digital", 0.9, "dns_intel", null),
      fact("name_servers", "Serveurs de noms", ["dns10.ovh.net", "ns10.ovh.net"], "digital", 0.9, "dns_intel", null),
      fact("domain_registrar", "Bureau d'enregistrement", "OVH SAS", "digital", 0.9, "domain_pivot", "https://rdap.org/"),
      fact("domain_created", "Création du domaine", "2018-07-19", "digital", 0.9, "domain_pivot", "https://rdap.org/"),
      fact("domain_expires", "Expiration du domaine", "2027-07-19", "digital", 0.9, "domain_pivot", "https://rdap.org/"),
      fact("hosting_provider", "Hébergeur", "OVHcloud", "digital", 0.82, "website_intel", SITE + "/mentions-legales"),
      fact("technology_stack", "Technologies", ["Python", "TypeScript", "C++"], "digital", 0.8, "github_org", "https://github.com/novaterra"),
      fact("github_organization", "Organisation GitHub", "novaterra", "digital", 0.9, "github_org", "https://github.com/novaterra"),
      fact("social_profile", "LinkedIn", "linkedin: https://www.linkedin.com/company/novaterra-industries", "digital", 0.87, "website_intel", SITE),

      fact("email", "Contact général", "contact@novaterra-industries.fr", "contact", 0.9, "website_intel", SITE + "/contact"),
      fact("email", "Presse", "presse@novaterra-industries.fr", "contact", 0.86, "website_intel", SITE + "/contact"),
      fact("phone", "Standard", "+33472000042", "contact", 0.88, "website_intel", SITE + "/contact"),

      fact("staff_count_public", "Personnes publiées", 8, "network", 0.78, "staff_directory", SITE + "/equipe"),
      fact("org_chart_depth", "Niveaux hiérarchiques", 4, "network", 0.7, "staff_directory", SITE + "/equipe"),

      fact("sanctions_screening", "Criblage sanctions/PEP", "Aucune correspondance dans les listes consultées", "risk", 0.92, "opensanctions", "https://www.opensanctions.org"),
      fact("legal_notice", "Annonce BODACC", "2024-11-08 — Modification — Changement de dirigeant", "risk", 0.94, "bodacc", "https://www.bodacc.fr/"),
      fact("legal_notices_count", "Annonces légales", 6, "legal", 0.94, "bodacc", "https://www.bodacc.fr/"),
    ],
  };

  function person(name, role, rank, extras) {
    const key = "person:" + name.toLowerCase();
    const node = {
      key,
      kind: "person",
      label: name,
      aliases: [],
      confidence: extras && extras.confidence ? extras.confidence : 0.8,
      is_root: false,
      selectors: [],
      attributes: [
        personal(fact("full_name", "Nom complet", name, "identity", 0.9, extras.source || "staff_directory", extras.url || SITE + "/equipe")),
        personal(fact("job_title", "Fonction déclarée", role, "network", 0.85, extras.source || "staff_directory", extras.url || SITE + "/equipe")),
        fact("hierarchy_rank", "Niveau hiérarchique", rank, "network", 0.7, "staff_directory", null),
      ],
    };
    (extras.facts || []).forEach((f) => node.attributes.push(f));
    return node;
  }

  const people = [
    person("Camille Ferrand", "Présidente", 1, {
      confidence: 0.93,
      source: "sirene",
      url: SIRENE,
      facts: [
        personal(fact("birth_year", "Année de naissance", "1979", "identity", 0.9, "sirene", SIRENE)),
        personal(fact("nationality", "Nationalité", "Française", "identity", 0.88, "sirene", SIRENE)),
        personal(fact("email", "Email", "c.ferrand@novaterra-industries.fr", "contact", 0.8, "staff_directory", SITE + "/equipe")),
        personal(fact("social_profile", "LinkedIn", "linkedin: https://www.linkedin.com/in/camille-ferrand", "digital", 0.75, "web_presence", null)),
        fact("other_mandates", "Autres mandats", "Gérante — SCI LES TILLEULS (Lyon)", "network", 0.86, "sirene", SIRENE),
        fact("sanctions_screening", "Criblage PEP", "Aucune correspondance", "risk", 0.9, "opensanctions", "https://www.opensanctions.org"),
      ],
    }),
    person("Antoine Rivière", "Directeur général délégué", 1, {
      confidence: 0.88,
      source: "sirene",
      url: SIRENE,
      facts: [
        personal(fact("birth_year", "Année de naissance", "1983", "identity", 0.88, "sirene", SIRENE)),
        personal(fact("email", "Email", "a.riviere@novaterra-industries.fr", "contact", 0.78, "staff_directory", SITE + "/equipe")),
      ],
    }),
    person("Sophie Vasseur", "Directrice financière (CFO)", 2, {
      facts: [
        personal(fact("email", "Email", "s.vasseur@novaterra-industries.fr", "contact", 0.8, "staff_directory", SITE + "/equipe")),
        personal(fact("phone", "Ligne directe", "+33472000048", "contact", 0.76, "staff_directory", SITE + "/equipe")),
      ],
    }),
    person("Karim Belkacem", "Directeur technique (CTO)", 2, {
      facts: [
        personal(fact("email", "Email", "k.belkacem@novaterra-industries.fr", "contact", 0.8, "staff_directory", SITE + "/equipe")),
        personal(fact("github_username", "GitHub", "kbelkacem", "digital", 0.86, "github_org", "https://github.com/kbelkacem")),
        fact("technology_stack", "Technologies", ["C++", "Python", "Rust"], "digital", 0.78, "github", "https://github.com/kbelkacem"),
      ],
    }),
    person("Léa Moreau", "Déléguée à la protection des données (DPO)", 2, {
      facts: [
        fact("email", "Email DPO", "dpo@novaterra-industries.fr", "contact", 0.9, "website_intel", SITE + "/mentions-legales"),
      ],
    }),
    person("Nadia Chaumont", "Assistante de direction", 5, {
      confidence: 0.76,
      facts: [
        personal(fact("email", "Email", "n.chaumont@novaterra-industries.fr", "contact", 0.78, "staff_directory", SITE + "/equipe")),
        personal(fact("phone", "Ligne directe", "+33472000041", "contact", 0.76, "staff_directory", SITE + "/equipe")),
        inferred(personal(fact("candidate_email", "Adresse probable", "nadia.chaumont@novaterra-industries.fr (schéma prenom.nom)", "contact", 0.35, "email_pattern", null))),
      ],
    }),
    person("Thomas Gauthier", "Responsable commercial", 4, {
      confidence: 0.74,
      facts: [
        personal(fact("email", "Email", "t.gauthier@novaterra-industries.fr", "contact", 0.78, "staff_directory", SITE + "/equipe")),
      ],
    }),
    person("Julien Petit", "Ingénieur logiciel", 6, {
      confidence: 0.7,
      facts: [
        personal(fact("github_username", "GitHub", "jpetit-dev", "digital", 0.84, "github_org", "https://github.com/jpetit-dev")),
      ],
    }),
  ];

  const organizations = [
    {
      key: "organization:novaterra holding",
      kind: "organization",
      label: "NOVATERRA HOLDING",
      aliases: [],
      confidence: 0.9,
      is_root: false,
      selectors: [],
      attributes: [
        fact("legal_name", "Dénomination", "NOVATERRA HOLDING", "identity", 0.95, "gleif", null),
        fact("lei", "LEI", "969500PXV3TQ2R8MN471", "legal", 0.96, "gleif", null),
        fact("siren", "SIREN", "839 447 210", "legal", 0.93, "sirene", null),
        fact("country", "Pays", "FR", "identity", 0.95, "gleif", null),
      ],
    },
    {
      key: "organization:novaterra deutschland",
      kind: "organization",
      label: "NOVATERRA DEUTSCHLAND GmbH",
      aliases: [],
      confidence: 0.82,
      is_root: false,
      selectors: [],
      attributes: [
        fact("legal_name", "Dénomination", "NOVATERRA DEUTSCHLAND GmbH", "identity", 0.9, "gleif", null),
        fact("country", "Pays", "DE", "identity", 0.9, "gleif", null),
        fact("vat_number", "TVA", "DE327654109", "legal", 0.85, "vies", null),
      ],
    },
    {
      key: "organization:sci les tilleuls",
      kind: "organization",
      label: "SCI LES TILLEULS",
      aliases: [],
      confidence: 0.78,
      is_root: false,
      selectors: [],
      attributes: [
        fact("legal_name", "Dénomination", "SCI LES TILLEULS", "identity", 0.9, "sirene", null),
        fact("legal_form", "Forme juridique", "Société civile immobilière (SCI) (6540)", "legal", 0.9, "sirene", null),
        fact("siren", "SIREN", "512 388 904", "legal", 0.92, "sirene", null),
      ],
    },
  ];

  // ------------------------------------------------------------- relations

  function relation(source, target, type, role, confidence, sourceId) {
    return {
      source,
      target,
      type,
      role,
      confidence,
      valid_from: null,
      valid_to: null,
      attributes: {},
      provenance: { source_id: sourceId, source_name: sourceId, url: null, observed_at: OBSERVED, reliability: confidence, method: "api", snippet: null },
    };
  }

  const relationships = [
    relation("person:camille ferrand", root.key, "officer_of", "Présidente", 0.95, "sirene"),
    relation("person:antoine rivière", root.key, "officer_of", "Directeur général délégué", 0.92, "sirene"),
    relation("person:sophie vasseur", root.key, "employee_of", "Directrice financière (CFO)", 0.8, "staff_directory"),
    relation("person:karim belkacem", root.key, "employee_of", "Directeur technique (CTO)", 0.8, "staff_directory"),
    relation("person:léa moreau", root.key, "employee_of", "DPO", 0.85, "website_intel"),
    relation("person:nadia chaumont", root.key, "employee_of", "Assistante de direction", 0.78, "staff_directory"),
    relation("person:thomas gauthier", root.key, "employee_of", "Responsable commercial", 0.76, "staff_directory"),
    relation("person:julien petit", root.key, "member_of", "Membre public GitHub", 0.8, "github_org"),
    relation(root.key, "organization:novaterra holding", "subsidiary_of", "Société mère", 0.93, "gleif"),
    relation(root.key, "organization:novaterra deutschland", "parent_of", "Filiale", 0.85, "gleif"),
    relation("person:camille ferrand", "organization:sci les tilleuls", "officer_of", "Gérante", 0.86, "sirene"),
  ];

  // --------------------------------------------------------------- dossier

  const DOSSIER = {
    run_id: "demo_novaterra",
    query: "NOVATERRA INDUSTRIES SAS",
    kind: "organization",
    label: "NOVATERRA INDUSTRIES",
    root_key: root.key,
    started_at: OBSERVED,
    finished_at: "2026-07-26T09:14:37+00:00",
    partial: false,
    confidence_score: 88.6,
    entities: [root].concat(people, organizations),
    relationships,
    graph: null,
    seed_selectors: [],
    resolved_selectors: [],
    conflicts: [
      {
        attribute: "headquarters_address",
        severity: "medium",
        preferred: "14 avenue Tony Garnier, 69007 Lyon",
        variants: [
          { value: "14 avenue Tony Garnier, 69007 Lyon", confidence: 0.96, sources: ["sirene"] },
          { value: "14 av. T. Garnier, Lyon 7e", confidence: 0.82, sources: ["website_intel"] },
        ],
        explanation: "2 valeurs différentes pour 'headquarters_address' selon les sources. Vérifier une donnée périmée ou une écriture abrégée.",
      },
    ],
    gaps: [
      {
        type: "source_unavailable",
        message: "Source 'hibp' non interrogée : Clé d'API non configurée (HIBP_API_KEY)",
        action: "Renseigner la clé d'API de hibp dans le fichier .env",
        suggested_sources: ["hibp"],
        blocked_sources: ["hibp"],
      },
      {
        type: "missing_attribute",
        attribute: "beneficial_owner",
        message: "Bénéficiaires effectifs non déterminés.",
        action: "Configurer une clé d'API pour : pappers",
        suggested_sources: ["pappers"],
        blocked_sources: [],
      },
    ],
    risk_flags: [
      {
        code: "no_dmarc",
        severity: "medium",
        title: "Absence de politique DMARC",
        detail: "Le domaine reçoit du courrier mais ne publie pas d'enregistrement DMARC : usurpation d'identité par email facilitée.",
        sources: ["dns_intel"],
        recommendation: "Publier un enregistrement DMARC (p=quarantine puis p=reject).",
      },
      {
        code: "identity_conflict",
        severity: "medium",
        title: "Sources contradictoires sur 'headquarters_address'",
        detail: "Le registre et le site officiel n'écrivent pas la même adresse.",
        sources: ["sirene", "website_intel"],
        recommendation: "Trancher avec la source la plus officielle et dater l'information.",
      },
      {
        code: "officer_change",
        severity: "low",
        title: "Changement de dirigeant récent",
        detail: "Une annonce BODACC du 8 novembre 2024 enregistre un changement de dirigeant.",
        sources: ["bodacc"],
        recommendation: "Vérifier que les mandats en cours correspondent aux interlocuteurs annoncés.",
      },
    ],
    timeline: [
      { date: "2018-07-19", label: "Création du domaine", detail: "novaterra-industries.fr", source: "domain_pivot", url: null, confidence: 0.9 },
      { date: "2018-09-04", label: "Immatriculation / création", detail: "SAS au capital de 1 250 000 €", source: "sirene", url: SIRENE, confidence: 0.97 },
      { date: "2019-03-12", label: "Attribution du LEI", detail: "969500K7T4V6PLBZ8T29", source: "gleif", url: null, confidence: 0.95 },
      { date: "2021-06-30", label: "Création de la filiale allemande", detail: "NOVATERRA DEUTSCHLAND GmbH", source: "gleif", url: null, confidence: 0.85 },
      { date: "2024-11-08", label: "Annonce BODACC", detail: "Modification — Changement de dirigeant", source: "bodacc", url: "https://www.bodacc.fr/", confidence: 0.94 },
      { date: "2025-04-02", label: "Mise à jour du LEI", detail: "Renouvellement annuel", source: "gleif", url: null, confidence: 0.95 },
    ],
    compliance: {
      policy: { mode: "standard", purpose: "due_diligence", purpose_label: "Vérification d'un partenaire avant engagement contractuel", max_layer: 2, redact_personal_data: false },
      entity_kind: "organization",
      gdpr_applicable: true,
      statements: [
        "Toutes les données collectées proviennent de sources publiquement accessibles.",
        "Finalité déclarée : Vérification d'un partenaire/fournisseur avant engagement contractuel.",
        "Chaque fait conserve sa source, son URL et sa date d'observation (auditabilité).",
      ],
      warnings: [],
      disclaimer: "Ananta ne fournit pas de conseil juridique. L'opérateur reste responsable de la licéité de la collecte et de l'usage des résultats.",
    },
    stats: {
      source_calls: 34,
      waves: 3,
      sources_ok: 11,
      sources_skipped: 6,
      sources_not_found: 3,
      sources_error: 0,
      sources_denied: 2,
      entities_found: 12,
      attributes_collected: 96,
      elapsed_seconds: 47.3,
      mode: "standard",
      llm_synthesis: true,
    },
    sources: [
      { source_id: "sirene", status: "ok", reason: null, error: null },
      { source_id: "gleif", status: "ok", reason: null, error: null },
      { source_id: "vies", status: "ok", reason: null, error: null },
      { source_id: "bodacc", status: "ok", reason: null, error: null },
      { source_id: "dns_intel", status: "ok", reason: null, error: null },
      { source_id: "domain_pivot", status: "ok", reason: null, error: null },
      { source_id: "website_intel", status: "ok", reason: null, error: null },
      { source_id: "staff_directory", status: "ok", reason: null, error: null },
      { source_id: "github_org", status: "ok", reason: null, error: null },
      { source_id: "nominatim", status: "ok", reason: null, error: null },
      { source_id: "opensanctions", status: "ok", reason: null, error: null },
      { source_id: "email_intel", status: "ok", reason: null, error: null },
      { source_id: "wikidata", status: "not_found", reason: "Aucune entité Wikidata pour 'novaterra'", error: null },
      { source_id: "sec_edgar", status: "not_found", reason: "Aucun déposant SEC", error: null },
      { source_id: "orcid", status: "skipped", reason: "Source non pertinente pour une entité 'organization'", error: null },
      { source_id: "hibp", status: "skipped", reason: "Clé d'API non configurée (HIBP_API_KEY)", error: null },
      { source_id: "companies_house", status: "skipped", reason: "Clé d'API non configurée (COMPANIES_HOUSE_API_KEY)", error: null },
      { source_id: "pappers", status: "skipped", reason: "Clé d'API non configurée (PAPPERS_API_KEY)", error: null },
      { source_id: "username_intel", status: "denied", reason: "Énumération de comptes désactivée", error: null },
    ],
    report:
      "# Dossier d'entité — NOVATERRA INDUSTRIES\n\n" +
      "**Statut** : Personne morale  \n**Score de confiance du dossier** : 88.6/100  \n\n" +
      "## Lecture analyste\n\n" +
      "NOVATERRA INDUSTRIES est une SAS lyonnaise immatriculée en septembre 2018, active dans " +
      "l'instrumentation scientifique (NAF 26.51B), au capital de 1 250 000 € pour un chiffre " +
      "d'affaires 2024 de 18,4 M€. L'identité légale est solidement établie : SIREN, LEI et numéro " +
      "de TVA se recoupent entre trois registres officiels indépendants.\n\n" +
      "La société appartient à NOVATERRA HOLDING et contrôle une filiale allemande. Sa présidente, " +
      "Camille Ferrand, détient par ailleurs un mandat de gérante dans une SCI lyonnaise — un lien " +
      "à documenter si l'objectif est d'apprécier des flux intra-groupe.\n\n" +
      "Deux points appellent une vérification. Le BODACC enregistre un changement de dirigeant en " +
      "novembre 2024 : s'assurer que l'interlocuteur du contrat correspond au mandat en cours. Le " +
      "domaine ne publie pas de politique DMARC, ce qui rend l'usurpation d'adresse triviale — un " +
      "risque direct de fraude au virement dans une relation fournisseur.\n\n" +
      "Actions prioritaires : (1) confirmer le mandat en cours auprès du greffe, (2) exiger une " +
      "vérification hors bande de tout changement de coordonnées bancaires, (3) obtenir les " +
      "bénéficiaires effectifs, non couverts sans clé Pappers.\n",
  };

  global.ANANTA_DEMO_DOSSIER = DOSSIER;
})(typeof window !== "undefined" ? window : this);
