// --- MARKDOWN HELPER ---
// Safe markdown parsing with fallback
function parseMarkdown(text) {
    if (!text) return '';

    // Debug logging
    console.log('[Markdown] Parsing text, length:', text.length);
    console.log('[Markdown] marked available:', typeof marked !== 'undefined');

    try {
        // Try marked.parse() first (newer versions)
        if (typeof marked !== 'undefined' && typeof marked.parse === 'function') {
            console.log('[Markdown] Using marked.parse()');
            const result = marked.parse(text);
            console.log('[Markdown] Success, result length:', result.length);
            return result;
        }
        // Try marked() directly (older versions)
        if (typeof marked === 'function') {
            console.log('[Markdown] Using marked() directly');
            return marked(text);
        }
        console.warn('[Markdown] marked library not available, using fallback');
    } catch (e) {
        console.error('[Markdown] Parse error:', e);
    }

    // Fallback: basic markdown-like rendering
    console.log('[Markdown] Using fallback renderer');
    let html = text;

    // Escape HTML first
    html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Headers (must be done before other replacements)
    html = html.replace(/^#{3}\s+(.+)$/gm, '<h3 class="text-lg font-bold text-slate-300 mt-4 mb-2">$1</h3>');
    html = html.replace(/^#{2}\s+(.+)$/gm, '<h2 class="text-xl font-bold text-cyan-400 mt-4 mb-2">$1</h2>');
    html = html.replace(/^#{1}\s+(.+)$/gm, '<h1 class="text-2xl font-bold text-cyan-400 mt-4 mb-2">$1</h1>');

    // Bold and italic
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Code
    html = html.replace(/`(.+?)`/g, '<code class="bg-slate-800 px-1 rounded text-pink-400">$1</code>');

    // Lists
    html = html.replace(/^- (.+)$/gm, '<li class="ml-4 list-disc">$1</li>');
    html = html.replace(/^\d+\. (.+)$/gm, '<li class="ml-4 list-decimal">$1</li>');

    // Tables - more robust parsing
    let inTable = false;
    let isFirstTableRow = false;
    const lines = html.split('\n');
    const processedLines = [];

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Check if this is a table line (starts and ends with |)
        if (line.startsWith('|') && line.endsWith('|')) {
            // Check if this is a separator line (contains only |, -, :, and spaces)
            // Examples: |---|---|---| or |:---:|:---:| or | --- | --- |
            const isSeparator = /^\|[\s\-:|]+\|$/.test(line) && line.includes('-');

            if (isSeparator) {
                // Skip separator lines entirely
                continue;
            }

            // Extract cells (split by | and filter out empty strings)
            const cells = line.split('|').slice(1, -1); // Remove first and last empty strings

            // Skip if all cells are empty or just dashes
            const hasContent = cells.some(c => c.trim() && !/^[\s\-:]+$/.test(c.trim()));
            if (!hasContent) {
                continue;
            }

            // Start new table if not in one
            if (!inTable) {
                processedLines.push('<table class="w-full border-collapse my-4 text-sm">');
                inTable = true;
                isFirstTableRow = true;
            }

            // Render row
            if (isFirstTableRow) {
                // First row is always the header
                processedLines.push('<thead><tr class="bg-slate-800 text-cyan-400">');
                cells.forEach(c => {
                    processedLines.push(`<th class="border border-slate-600 px-3 py-2 text-left font-bold">${c.trim()}</th>`);
                });
                processedLines.push('</tr></thead><tbody>');
                isFirstTableRow = false;
            } else {
                // Data rows
                processedLines.push('<tr class="hover:bg-slate-800/50">');
                cells.forEach(c => {
                    processedLines.push(`<td class="border border-slate-700 px-3 py-2">${c.trim()}</td>`);
                });
                processedLines.push('</tr>');
            }
        } else {
            // Not a table line - close table if we were in one
            if (inTable) {
                processedLines.push('</tbody></table>');
                inTable = false;
                isFirstTableRow = false;
            }
            processedLines.push(line);
        }
    }

    // Close table if still open at end
    if (inTable) {
        processedLines.push('</tbody></table>');
    }

    html = processedLines.join('\n');

    // Paragraphs
    html = html.replace(/\n\n/g, '</p><p class="mb-3">');
    html = html.replace(/\n/g, '<br>');

    return '<p class="mb-3">' + html + '</p>';
}

// --- CONFIGURATION ---
const DEFAULT_SETTINGS = {
    apiUrl: '',
    llmTemperature: 0.7,
    llmTimeout: 180,
    llmHardLimit: 4000,
    cacheTtl: 10,
    exportFormat: 'pdf',
    scanMode: 'standard',  // "fast" (Layer 1), "standard" (Layer 1+2), "full" (all)
    reportTemplate: 'detailed',  // "detailed", "executive", "technical", "minimal"
    compactMode: false,
    fontSize: 'medium',
    accentColor: 'cyan',
    darkMode: true,  // Dark mode by default (Ananta's signature look)
    maxReports: 100,
    autoDeleteDays: 30,
    notifications: false,
    favorites: [],
    language: 'fr'
};

// --- TRADUCTIONS ---
const TRANSLATIONS = {
    fr: {
        // General
        'system_initialized': 'Système Initialisé',
        'system_ready': 'Bienvenue dans la console de renseignement Ananta. Prêt pour l\'extraction de données. Veuillez entrer une URL, une IP ou un domaine pour débuter l\'analyse OSINT.',
        'execute': 'EXECUTER',
        'export_report': 'Exporter Rapport',
        'backend_api': 'Backend API',

        // Sidebar
        'central_console': 'Console Centrale',
        'entity_research': 'Entités',
        'database': 'Base de données',
        'user': 'Utilisateur',
        'root_access': 'Accès Root',

        // System Health
        'system_health': 'Santé du Système',
        'db_latency': 'DB Latency',
        'worker_state': 'Worker State',
        'cpu_load': 'CPU Load',
        'gpu_load': 'GPU Load',
        'indicators_extracted': 'Indicateurs Extraits',
        'no_indicators': 'Aucun indicateur identifié dans la session actuelle.',

        // Messages
        'error_critical': 'ERREUR CRITIQUE:',
        'scan_launched': 'Scan OSINT lancé en arrière-plan. Veuillez patienter...',
        'no_recent_analysis': 'Aucune analyse récente à exporter.',
        'generating_report': 'Génération du rapport',

        // Settings
        'settings': 'Paramètres',
        'api_configuration': 'Configuration API',
        'backend_url': 'URL du Backend',
        'auto_detection': 'Laissez vide pour auto-détection',
        'llm_parameters': 'Paramètres LLM',
        'temperature': 'Température',
        'temperature_hint': 'Plus élevé = plus créatif, plus bas = plus précis',
        'timeout_seconds': 'Timeout (secondes)',
        'cache_management': 'Gestion du Cache',
        'space_used': 'Espace utilisé',
        'cache_ttl_days': 'TTL du cache (jours)',
        'clear_cache': 'Vider le cache',
        'export_settings': 'Export',
        'default_format': 'Format par défaut',
        'display_settings': 'Affichage',
        'compact_mode': 'Mode compact',
        'font_size': 'Taille de police',
        'font_small': 'Petite',
        'font_medium': 'Moyenne',
        'font_large': 'Grande',
        'theme': 'Thème',
        'accent_color': 'Couleur d\'accent',
        'history': 'Historique',
        'max_reports': 'Nombre max de rapports',
        'auto_delete_days': 'Auto-suppression après (jours)',
        'auto_delete_hint': '0 = jamais supprimer',
        'notifications': 'Notifications',
        'browser_alerts': 'Alertes navigateur',
        'notification_hint': 'Recevoir une notification quand un scan est terminé',
        'test': 'Tester',
        'favorites': 'Raccourcis Favoris',
        'no_favorites': 'Aucun favori',
        'add_target': 'Ajouter une cible...',
        'reset': 'Réinitialiser',
        'save': 'Sauvegarder',
        'language': 'Langue',
        'install': 'Installer',
        'later': 'Plus tard',
        'clear_cache_btn': 'Vider le cache',
        'test_btn': 'Tester',
        'favorites_placeholder': 'Ajouter une cible...',
        'export_pdf': 'Exporter PDF',
        'export_excel': 'Exporter Excel',
        'export_json': 'Exporter JSON',
        'export_csv': 'Exporter CSV',
        'export_xml': 'Exporter XML',
        'export_markdown': 'Exporter Markdown',
        'confirm_reset_settings': 'Réinitialiser tous les paramètres aux valeurs par défaut ?',
        'confirm_clear_cache': 'Vider le cache ? Cette action est irréversible.',
        'cache_cleared_success': 'Cache vidé avec succès.',

        // Notifications
        'settings_saved': 'Paramètres sauvegardés avec succès.',
        'settings_reset': 'Paramètres réinitialisés.',
        'cache_cleared': 'Cache vidé avec succès.',
        'scan_complete': 'Scan terminé',
        'scan_complete_message': 'L\'analyse de {target} est terminée.',

        // Layer 3 / Critical Mode
        'critical_consent_required': 'Vous devez confirmer avoir l\'autorisation légale pour utiliser les outils Layer 3.',
        'critical_no_tools': 'Vous devez sélectionner au moins un outil Layer 3 (port scan ou vuln scan).',

        // Keyboard Shortcuts
        'keyboard_shortcuts': 'Raccourcis clavier',
        'execute_scan': 'Exécuter le scan',
        'focus_search': 'Focus recherche',
        'open_settings': 'Paramètres',
        'go_to_database': 'Aller à Database',
        'close_modal': 'Fermer la modale',
        'show_shortcuts': 'Afficher cette aide',
        'press_escape': 'Appuyez sur Escape pour fermer'
    },
    en: {
        // General
        'system_initialized': 'System Initialized',
        'system_ready': 'Welcome to the Ananta intelligence console. Ready for data extraction. Please enter a URL, IP or domain to start the OSINT analysis.',
        'execute': 'EXECUTE',
        'export_report': 'Export Report',
        'backend_api': 'Backend API',

        // Sidebar
        'central_console': 'Central Console',
        'entity_research': 'Entities',
        'database': 'Database',
        'user': 'User',
        'root_access': 'Root Access',

        // System Health
        'system_health': 'System Health',
        'db_latency': 'DB Latency',
        'worker_state': 'Worker State',
        'cpu_load': 'CPU Load',
        'gpu_load': 'GPU Load',
        'indicators_extracted': 'Extracted Indicators',
        'no_indicators': 'No indicators identified in the current session.',

        // Messages
        'error_critical': 'CRITICAL ERROR:',
        'scan_launched': 'OSINT scan launched in the background. Please wait...',
        'no_recent_analysis': 'No recent analysis to export.',
        'generating_report': 'Generating report',

        // Settings
        'settings': 'Settings',
        'api_configuration': 'API Configuration',
        'backend_url': 'Backend URL',
        'auto_detection': 'Leave empty for auto-detection',
        'llm_parameters': 'LLM Parameters',
        'temperature': 'Temperature',
        'temperature_hint': 'Higher = more creative, lower = more precise',
        'timeout_seconds': 'Timeout (seconds)',
        'cache_management': 'Cache Management',
        'space_used': 'Space used',
        'cache_ttl_days': 'Cache TTL (days)',
        'clear_cache': 'Clear cache',
        'export_settings': 'Export',
        'default_format': 'Default format',
        'display_settings': 'Display',
        'compact_mode': 'Compact mode',
        'font_size': 'Font size',
        'font_small': 'Small',
        'font_medium': 'Medium',
        'font_large': 'Large',
        'theme': 'Theme',
        'accent_color': 'Accent color',
        'history': 'History',
        'max_reports': 'Max number of reports',
        'auto_delete_days': 'Auto-delete after (days)',
        'auto_delete_hint': '0 = never delete',
        'notifications': 'Notifications',
        'browser_alerts': 'Browser alerts',
        'notification_hint': 'Receive a notification when a scan is completed',
        'test': 'Test',
        'favorites': 'Favorite Shortcuts',
        'no_favorites': 'No favorites',
        'add_target': 'Add a target...',
        'reset': 'Reset',
        'save': 'Save',
        'language': 'Language',
        'install': 'Install',
        'later': 'Later',
        'clear_cache_btn': 'Clear cache',
        'test_btn': 'Test',
        'favorites_placeholder': 'Add a target...',
        'export_pdf': 'Export PDF',
        'export_excel': 'Export Excel',
        'export_json': 'Export JSON',
        'export_csv': 'Export CSV',
        'export_xml': 'Export XML',
        'export_markdown': 'Export Markdown',
        'confirm_reset_settings': 'Reset all settings to default values?',
        'confirm_clear_cache': 'Clear cache? This action is irreversible.',
        'cache_cleared_success': 'Cache cleared successfully.',

        // Notifications
        'settings_saved': 'Settings saved successfully.',
        'settings_reset': 'Settings reset.',
        'cache_cleared': 'Cache cleared successfully.',
        'scan_complete': 'Scan complete',
        'scan_complete_message': 'The analysis of {target} is complete.',

        // Layer 3 / Critical Mode
        'critical_consent_required': 'You must confirm you have legal authorization to use Layer 3 tools.',
        'critical_no_tools': 'You must select at least one Layer 3 tool (port scan or vuln scan).',

        // Keyboard Shortcuts
        'keyboard_shortcuts': 'Keyboard Shortcuts',
        'execute_scan': 'Execute scan',
        'focus_search': 'Focus search',
        'open_settings': 'Settings',
        'go_to_database': 'Go to Database',
        'close_modal': 'Close modal',
        'show_shortcuts': 'Show this help',
        'press_escape': 'Press Escape to close'
    },
    es: {
        // General
        'system_initialized': 'Sistema Inicializado',
        'system_ready': 'Bienvenido a la consola de inteligencia Ananta. Listo para la extracción de datos. Por favor ingrese una URL, IP o dominio para iniciar el análisis OSINT.',
        'execute': 'EJECUTAR',
        'export_report': 'Exportar Informe',
        'backend_api': 'Backend API',

        // Sidebar
        'central_console': 'Consola Central',
        'entity_research': 'Entidades',
        'database': 'Base de datos',
        'user': 'Usuario',
        'root_access': 'Acceso Root',

        // System Health
        'system_health': 'Salud del Sistema',
        'db_latency': 'Latencia BD',
        'worker_state': 'Estado Worker',
        'cpu_load': 'Carga CPU',
        'gpu_load': 'Carga GPU',
        'indicators_extracted': 'Indicadores Extraídos',
        'no_indicators': 'No se identificaron indicadores en la sesión actual.',

        // Messages
        'error_critical': 'ERROR CRÍTICO:',
        'scan_launched': 'Escaneo OSINT lanzado en segundo plano. Por favor espere...',
        'no_recent_analysis': 'No hay análisis reciente para exportar.',
        'generating_report': 'Generando informe',

        // Settings
        'settings': 'Configuración',
        'api_configuration': 'Configuración API',
        'backend_url': 'URL del Backend',
        'auto_detection': 'Dejar vacío para auto-detección',
        'llm_parameters': 'Parámetros LLM',
        'temperature': 'Temperatura',
        'temperature_hint': 'Más alto = más creativo, más bajo = más preciso',
        'timeout_seconds': 'Timeout (segundos)',
        'cache_management': 'Gestión de Caché',
        'space_used': 'Espacio utilizado',
        'cache_ttl_days': 'TTL del caché (días)',
        'clear_cache': 'Limpiar caché',
        'export_settings': 'Exportar',
        'default_format': 'Formato predeterminado',
        'display_settings': 'Visualización',
        'compact_mode': 'Modo compacto',
        'font_size': 'Tamaño de fuente',
        'font_small': 'Pequeña',
        'font_medium': 'Mediana',
        'font_large': 'Grande',
        'theme': 'Tema',
        'accent_color': 'Color de acento',
        'history': 'Historial',
        'max_reports': 'Número máximo de informes',
        'auto_delete_days': 'Auto-eliminar después de (días)',
        'auto_delete_hint': '0 = nunca eliminar',
        'notifications': 'Notificaciones',
        'browser_alerts': 'Alertas del navegador',
        'notification_hint': 'Recibir una notificación cuando termine un escaneo',
        'test': 'Probar',
        'favorites': 'Accesos Directos Favoritos',
        'no_favorites': 'Sin favoritos',
        'add_target': 'Agregar un objetivo...',
        'reset': 'Restablecer',
        'save': 'Guardar',
        'language': 'Idioma',
        'install': 'Instalar',
        'later': 'Más tarde',
        'clear_cache_btn': 'Vaciar caché',
        'test_btn': 'Probar',
        'favorites_placeholder': 'Añadir un objetivo...',
        'export_pdf': 'Exportar PDF',
        'export_excel': 'Exportar Excel',
        'export_json': 'Exportar JSON',
        'export_csv': 'Exportar CSV',
        'export_xml': 'Exportar XML',
        'export_markdown': 'Exportar Markdown',
        'confirm_reset_settings': '¿Restablecer toda la configuración a los valores predeterminados?',
        'confirm_clear_cache': '¿Vaciar la caché? Esta acción es irreversible.',
        'cache_cleared_success': 'Caché vaciada correctamente.',

        // Notifications
        'settings_saved': 'Configuración guardada correctamente.',
        'settings_reset': 'Configuración restablecida.',
        'cache_cleared': 'Caché limpiado correctamente.',
        'scan_complete': 'Escaneo completo',
        'scan_complete_message': 'El análisis de {target} está completo.',

        // Layer 3 / Critical Mode
        'critical_consent_required': 'Debe confirmar que tiene autorización legal para usar las herramientas Layer 3.',
        'critical_no_tools': 'Debe seleccionar al menos una herramienta Layer 3 (escaneo de puertos o vulnerabilidades).',

        // Keyboard Shortcuts
        'keyboard_shortcuts': 'Atajos de Teclado',
        'execute_scan': 'Ejecutar escaneo',
        'focus_search': 'Enfocar búsqueda',
        'open_settings': 'Configuración',
        'go_to_database': 'Ir a Base de datos',
        'close_modal': 'Cerrar modal',
        'show_shortcuts': 'Mostrar esta ayuda',
        'press_escape': 'Presione Escape para cerrar'
    },
    de: {
        // General
        'system_initialized': 'System Initialisiert',
        'system_ready': 'Willkommen bei der Ananta Intelligence-Konsole. Bereit für Datenextraktion. Bitte geben Sie eine URL, IP oder Domain ein, um die OSINT-Analyse zu starten.',
        'execute': 'AUSFÜHREN',
        'export_report': 'Bericht Exportieren',
        'backend_api': 'Backend API',

        // Sidebar
        'central_console': 'Zentrale Konsole',
        'entity_research': 'Entitäten',
        'database': 'Datenbank',
        'user': 'Benutzer',
        'root_access': 'Root-Zugang',

        // System Health
        'system_health': 'Systemzustand',
        'db_latency': 'DB-Latenz',
        'worker_state': 'Worker-Status',
        'cpu_load': 'CPU-Last',
        'gpu_load': 'GPU-Last',
        'indicators_extracted': 'Extrahierte Indikatoren',
        'no_indicators': 'Keine Indikatoren in der aktuellen Sitzung identifiziert.',

        // Messages
        'error_critical': 'KRITISCHER FEHLER:',
        'scan_launched': 'OSINT-Scan im Hintergrund gestartet. Bitte warten...',
        'no_recent_analysis': 'Keine aktuelle Analyse zum Exportieren.',
        'generating_report': 'Bericht wird erstellt',

        // Settings
        'settings': 'Einstellungen',
        'api_configuration': 'API-Konfiguration',
        'backend_url': 'Backend-URL',
        'auto_detection': 'Leer lassen für automatische Erkennung',
        'llm_parameters': 'LLM-Parameter',
        'temperature': 'Temperatur',
        'temperature_hint': 'Höher = kreativer, niedriger = präziser',
        'timeout_seconds': 'Timeout (Sekunden)',
        'cache_management': 'Cache-Verwaltung',
        'space_used': 'Genutzter Speicher',
        'cache_ttl_days': 'Cache-TTL (Tage)',
        'clear_cache': 'Cache leeren',
        'export_settings': 'Export',
        'default_format': 'Standardformat',
        'display_settings': 'Anzeige',
        'compact_mode': 'Kompaktmodus',
        'font_size': 'Schriftgröße',
        'font_small': 'Klein',
        'font_medium': 'Mittel',
        'font_large': 'Groß',
        'theme': 'Design',
        'accent_color': 'Akzentfarbe',
        'history': 'Verlauf',
        'max_reports': 'Maximale Anzahl Berichte',
        'auto_delete_days': 'Auto-Löschen nach (Tagen)',
        'auto_delete_hint': '0 = niemals löschen',
        'notifications': 'Benachrichtigungen',
        'browser_alerts': 'Browser-Benachrichtigungen',
        'notification_hint': 'Benachrichtigung erhalten, wenn ein Scan abgeschlossen ist',
        'test': 'Testen',
        'favorites': 'Favoriten-Verknüpfungen',
        'no_favorites': 'Keine Favoriten',
        'add_target': 'Ziel hinzufügen...',
        'reset': 'Zurücksetzen',
        'save': 'Speichern',
        'language': 'Sprache',
        'install': 'Installieren',
        'later': 'Später',
        'clear_cache_btn': 'Cache leeren',
        'test_btn': 'Testen',
        'favorites_placeholder': 'Ziel hinzufügen...',
        'export_pdf': 'PDF exportieren',
        'export_excel': 'Excel exportieren',
        'export_json': 'JSON exportieren',
        'export_csv': 'CSV exportieren',
        'export_xml': 'XML exportieren',
        'export_markdown': 'Markdown exportieren',
        'confirm_reset_settings': 'Alle Einstellungen auf Standardwerte zurücksetzen?',
        'confirm_clear_cache': 'Cache leeren? Diese Aktion ist irreversibel.',
        'cache_cleared_success': 'Cache erfolgreich geleert.',

        // Notifications
        'settings_saved': 'Einstellungen erfolgreich gespeichert.',
        'settings_reset': 'Einstellungen zurückgesetzt.',
        'cache_cleared': 'Cache erfolgreich geleert.',
        'scan_complete': 'Scan abgeschlossen',
        'scan_complete_message': 'Die Analyse von {target} ist abgeschlossen.',

        // Layer 3 / Critical Mode
        'critical_consent_required': 'Sie müssen bestätigen, dass Sie die rechtliche Genehmigung zur Verwendung von Layer 3-Tools haben.',
        'critical_no_tools': 'Sie müssen mindestens ein Layer 3-Tool auswählen (Port-Scan oder Schwachstellen-Scan).',

        // Keyboard Shortcuts
        'keyboard_shortcuts': 'Tastaturkürzel',
        'execute_scan': 'Scan ausführen',
        'focus_search': 'Suche fokussieren',
        'open_settings': 'Einstellungen',
        'go_to_database': 'Zur Datenbank',
        'close_modal': 'Modal schließen',
        'show_shortcuts': 'Diese Hilfe anzeigen',
        'press_escape': 'Escape drücken zum Schließen'
    }
};

// Helper function to translate text
function t(key, params = {}) {
    const lang = appSettings.language || 'fr';
    let text = TRANSLATIONS[lang]?.[key] || TRANSLATIONS['fr'][key] || key;

    // Replace parameters {param}
    for (const [param, value] of Object.entries(params)) {
        text = text.replace(`{${param}}`, value);
    }

    return text;
}

// Apply translations to all elements with data-i18n attribute
function applyTranslations() {
    const lang = appSettings.language || 'fr';
    console.log('[i18n] Applying translations for language:', lang);

    // Update all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key && TRANSLATIONS[lang]?.[key]) {
            el.textContent = TRANSLATIONS[lang][key];
        } else if (key && TRANSLATIONS['fr']?.[key]) {
            el.textContent = TRANSLATIONS['fr'][key];
        }
    });

    // Update all elements with data-i18n-placeholder attribute
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key && TRANSLATIONS[lang]?.[key]) {
            el.placeholder = TRANSLATIONS[lang][key];
        }
    });

    // Update all elements with data-i18n-title attribute
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (key && TRANSLATIONS[lang]?.[key]) {
            el.title = TRANSLATIONS[lang][key];
        }
    });

    // Update HTML lang attribute
    document.documentElement.lang = lang;

    // Update specific well-known elements by ID
    const translations = {
        // Sidebar
        'btn-console span.hidden': 'central_console',
        // Header
        // Main UI elements are handled by data-i18n attributes
    };

    // Apply critical UI translations directly
    applyStaticTranslations(lang);
}

// Apply translations to static HTML elements that don't have data-i18n
function applyStaticTranslations(lang) {
    const trans = TRANSLATIONS[lang] || TRANSLATIONS['fr'];
    const ui = {
        fr: {
            hard_limit_tokens: "Hard limit (tokens)",
            hard_limit_hint: "Plafond max_tokens pour la synthèse (plus haut = plus long, plus détaillé)",
            scan_mode: "Mode de Scan",
            scan_depth: "Profondeur du scan OSINT",
            scan_fast: "Rapide (Layer 1)",
            scan_fast_hint: "WHOIS, DNS, Headers HTTP (~30s)",
            scan_standard: "Standard (Layer 1+2)",
            scan_standard_hint: "+ Censys, crt.sh, analyse web (~2-3min)",
            scan_full: "Complet (Tous les layers)",
            scan_full_hint: "Scan exhaustif avec toutes les sources (~5min)",
            scan_critical: "Critique (Layer 3 - Risque Légal)",
            scan_critical_hint: "Port scan, vuln scan - NÉCESSITE AUTORISATION EXPLICITE",
            layer3_tools_label: "Outils Layer 3 à activer",
            layer3_port_scan: "Port Scan (TCP top 100 ports)",
            layer3_vuln_scan: "Vuln Scan (CVE detection)",
            legal_warning_title: "AVERTISSEMENT LÉGAL",
            legal_warning_text: "Les scans de ports et de vulnérabilités peuvent être illégaux sans autorisation écrite du propriétaire de la cible. En activant ces outils, vous confirmez disposer d'une autorisation valide (pentest contractuel, bug bounty, audit interne).",
            legal_consent_text: "Je confirme avoir l'autorisation légale pour ce scan",
            report_template_title: "Template de Rapport",
            report_style: "Style du rapport généré",
            template_detailed: "Détaillé",
            template_detailed_hint: "Rapport complet avec toutes les informations et analyses",
            template_executive: "Exécutif",
            template_executive_hint: "Résumé pour décideurs avec points clés et recommandations",
            template_technical: "Technique",
            template_technical_hint: "Focus sur les détails techniques (ports, CVE, headers)",
            template_minimal: "Minimal",
            template_minimal_hint: "Essentiel uniquement: verdict et indicateurs critiques",
            dark_mode: "Mode sombre",
            theme_toggle_hint: "Basculer entre thème sombre et clair",
            interface_language: "Langue de l'interface",
            install: "Installer",
            later: "Plus tard"
        },
        en: {
            hard_limit_tokens: "Hard limit (tokens)",
            hard_limit_hint: "max_tokens cap for synthesis (higher = longer, more detailed)",
            scan_mode: "Scan Mode",
            scan_depth: "OSINT scan depth",
            scan_fast: "Fast (Layer 1)",
            scan_fast_hint: "WHOIS, DNS, HTTP headers (~30s)",
            scan_standard: "Standard (Layer 1+2)",
            scan_standard_hint: "+ Censys, crt.sh, web analysis (~2-3min)",
            scan_full: "Full (All layers)",
            scan_full_hint: "Exhaustive scan with all sources (~5min)",
            scan_critical: "Critical (Layer 3 - Legal Risk)",
            scan_critical_hint: "Port scan, vuln scan - EXPLICIT AUTHORIZATION REQUIRED",
            layer3_tools_label: "Layer 3 tools to enable",
            layer3_port_scan: "Port Scan (TCP top 100 ports)",
            layer3_vuln_scan: "Vuln Scan (CVE detection)",
            legal_warning_title: "LEGAL WARNING",
            legal_warning_text: "Port and vulnerability scans may be illegal without written authorization from the target owner. By enabling these tools, you confirm you have valid authorization (contractual pentest, bug bounty, internal audit).",
            legal_consent_text: "I confirm I have legal authorization for this scan",
            report_template_title: "Report Template",
            report_style: "Generated report style",
            template_detailed: "Detailed",
            template_detailed_hint: "Full report with complete information and analysis",
            template_executive: "Executive",
            template_executive_hint: "Decision-maker summary with key points and recommendations",
            template_technical: "Technical",
            template_technical_hint: "Focus on technical details (ports, CVE, headers)",
            template_minimal: "Minimal",
            template_minimal_hint: "Essentials only: verdict and critical indicators",
            dark_mode: "Dark mode",
            theme_toggle_hint: "Switch between dark and light theme",
            interface_language: "Interface language",
            install: "Install",
            later: "Later"
        },
        es: {
            hard_limit_tokens: "Límite duro (tokens)",
            hard_limit_hint: "Límite de max_tokens para el resumen (más alto = más largo, más detallado)",
            scan_mode: "Modo de Escaneo",
            scan_depth: "Profundidad del escaneo OSINT",
            scan_fast: "Rápido (Layer 1)",
            scan_fast_hint: "WHOIS, DNS, cabeceras HTTP (~30s)",
            scan_standard: "Estándar (Layer 1+2)",
            scan_standard_hint: "+ Censys, crt.sh, análisis web (~2-3min)",
            scan_full: "Completo (Todas las capas)",
            scan_full_hint: "Escaneo exhaustivo con todas las fuentes (~5min)",
            scan_critical: "Crítico (Layer 3 - Riesgo Legal)",
            scan_critical_hint: "Port scan, vuln scan - SE REQUIERE AUTORIZACIÓN EXPLÍCITA",
            layer3_tools_label: "Herramientas Layer 3 a activar",
            layer3_port_scan: "Port Scan (TCP top 100 puertos)",
            layer3_vuln_scan: "Vuln Scan (detección CVE)",
            legal_warning_title: "ADVERTENCIA LEGAL",
            legal_warning_text: "Los escaneos de puertos y vulnerabilidades pueden ser ilegales sin autorización escrita del propietario del objetivo. Al activar estas herramientas, confirmas que tienes autorización válida (pentest contractual, bug bounty, auditoría interna).",
            legal_consent_text: "Confirmo que tengo autorización legal para este escaneo",
            report_template_title: "Plantilla de Informe",
            report_style: "Estilo del informe generado",
            template_detailed: "Detallado",
            template_detailed_hint: "Informe completo con toda la información y análisis",
            template_executive: "Ejecutivo",
            template_executive_hint: "Resumen para decisores con puntos clave y recomendaciones",
            template_technical: "Técnico",
            template_technical_hint: "Enfoque en detalles técnicos (puertos, CVE, cabeceras)",
            template_minimal: "Mínimo",
            template_minimal_hint: "Solo lo esencial: veredicto e indicadores críticos",
            dark_mode: "Modo oscuro",
            theme_toggle_hint: "Alternar entre tema oscuro y claro",
            interface_language: "Idioma de la interfaz",
            install: "Instalar",
            later: "Más tarde"
        },
        de: {
            hard_limit_tokens: "Hard Limit (Tokens)",
            hard_limit_hint: "max_tokens-Obergrenze für die Synthese (höher = länger, detaillierter)",
            scan_mode: "Scan-Modus",
            scan_depth: "OSINT-Scan-Tiefe",
            scan_fast: "Schnell (Layer 1)",
            scan_fast_hint: "WHOIS, DNS, HTTP-Header (~30s)",
            scan_standard: "Standard (Layer 1+2)",
            scan_standard_hint: "+ Censys, crt.sh, Web-Analyse (~2-3min)",
            scan_full: "Vollständig (Alle Layer)",
            scan_full_hint: "Umfassender Scan mit allen Quellen (~5min)",
            scan_critical: "Kritisch (Layer 3 - Rechtliches Risiko)",
            scan_critical_hint: "Port scan, vuln scan - AUSDRÜCKLICHE AUTORISIERUNG ERFORDERLICH",
            layer3_tools_label: "Zu aktivierende Layer-3-Tools",
            layer3_port_scan: "Port-Scan (TCP Top 100 Ports)",
            layer3_vuln_scan: "Vuln-Scan (CVE-Erkennung)",
            legal_warning_title: "RECHTLICHER HINWEIS",
            legal_warning_text: "Port- und Schwachstellen-Scans können ohne schriftliche Genehmigung des Zielinhabers illegal sein. Durch Aktivieren dieser Tools bestätigen Sie, dass Sie eine gültige Autorisierung besitzen (vertraglicher Pentest, Bug Bounty, internes Audit).",
            legal_consent_text: "Ich bestätige, dass ich die rechtliche Genehmigung für diesen Scan habe",
            report_template_title: "Berichtsvorlage",
            report_style: "Stil des generierten Berichts",
            template_detailed: "Detailliert",
            template_detailed_hint: "Vollständiger Bericht mit allen Informationen und Analysen",
            template_executive: "Executive",
            template_executive_hint: "Management-Zusammenfassung mit Kernpunkten und Empfehlungen",
            template_technical: "Technisch",
            template_technical_hint: "Fokus auf technische Details (Ports, CVE, Header)",
            template_minimal: "Minimal",
            template_minimal_hint: "Nur das Wesentliche: Urteil und kritische Indikatoren",
            dark_mode: "Dunkler Modus",
            theme_toggle_hint: "Zwischen dunklem und hellem Design wechseln",
            interface_language: "Sprache der Oberfläche",
            install: "Installieren",
            later: "Später"
        }
    };
    const u = ui[lang] || ui.fr;
    const setText = (selector, value) => {
        const el = document.querySelector(selector);
        if (el) el.textContent = value;
    };
    const setWithIcon = (selector, value) => {
        const el = document.querySelector(selector);
        if (!el) return;
        const icon = el.querySelector('i');
        el.innerHTML = '';
        if (icon) el.appendChild(icon);
        el.appendChild(document.createTextNode((icon ? ' ' : '') + value));
    };

    // Send button
    const sendBtn = document.querySelector('#send-btn span');
    if (sendBtn) sendBtn.textContent = trans['execute'] || 'EXECUTER';

    // Export button
    const exportBtn = document.querySelector('#btn-export-pdf');
    if (exportBtn) {
        const icon = exportBtn.querySelector('i');
        exportBtn.innerHTML = '';
        if (icon) exportBtn.appendChild(icon);
        exportBtn.appendChild(document.createTextNode(' ' + (trans['export_report'] || 'Exporter Rapport')));
    }

    // Settings modal title
    const settingsTitle = document.getElementById('settings-title');
    if (settingsTitle) {
        const icon = settingsTitle.querySelector('i');
        settingsTitle.innerHTML = '';
        if (icon) {
            settingsTitle.appendChild(icon);
            settingsTitle.appendChild(document.createTextNode(' ' + (trans['settings'] || 'Paramètres')));
        }
    }

    // Settings section titles
    setWithIcon('.settings-section:nth-child(1) .settings-section-title', trans['api_configuration'] || 'Configuration API');
    setWithIcon('.settings-section:nth-child(2) .settings-section-title', trans['llm_parameters'] || 'Paramètres LLM');
    setWithIcon('.settings-section:nth-child(3) .settings-section-title', u.scan_mode);
    setWithIcon('.settings-section:nth-child(4) .settings-section-title', trans['cache_management'] || 'Gestion du Cache');
    setWithIcon('.settings-section:nth-child(5) .settings-section-title', u.report_template_title);
    setWithIcon('.settings-section:nth-child(6) .settings-section-title', trans['export_settings'] || 'Export');
    setWithIcon('.settings-section:nth-child(7) .settings-section-title', trans['display_settings'] || 'Affichage');
    setWithIcon('.settings-section:nth-child(8) .settings-section-title', trans['theme'] || 'Thème');
    setWithIcon('.settings-section:nth-child(9) .settings-section-title', trans['language'] || 'Langue');
    setWithIcon('.settings-section:nth-child(10) .settings-section-title', trans['history'] || 'Historique');
    setWithIcon('.settings-section:nth-child(11) .settings-section-title', trans['notifications'] || 'Notifications');
    setWithIcon('.settings-section:nth-child(12) .settings-section-title', trans['favorites'] || 'Raccourcis Favoris');

    setText('label[for="setting-api-url"]', trans['backend_url'] || 'URL du Backend');
    setText('.settings-section:nth-child(1) .settings-hint', trans['auto_detection'] || 'Laissez vide pour auto-détection');
    setText('label[for="setting-llm-temperature"]', trans['temperature'] || 'Température');
    setText('.settings-section:nth-child(2) .settings-field:nth-child(2) .settings-hint', trans['temperature_hint'] || '');
    setText('label[for="setting-llm-timeout"]', trans['timeout_seconds'] || 'Timeout (secondes)');
    setText('label[for="setting-llm-hard-limit"]', u.hard_limit_tokens);
    setText('.settings-section:nth-child(2) .settings-field:nth-child(4) .settings-hint', u.hard_limit_hint);

    setText('.settings-section:nth-child(3) .settings-field > label', u.scan_depth);
    setWithIcon('input[name="scan-mode"][value="fast"] + span', u.scan_fast);
    const scanFastHint = document.querySelector('input[name="scan-mode"][value="fast"]')?.closest('label')?.nextElementSibling;
    if (scanFastHint) scanFastHint.textContent = u.scan_fast_hint;
    setWithIcon('input[name="scan-mode"][value="standard"] + span', u.scan_standard);
    const scanStandardHint = document.querySelector('input[name="scan-mode"][value="standard"]')?.closest('label')?.nextElementSibling;
    if (scanStandardHint) scanStandardHint.textContent = u.scan_standard_hint;
    setWithIcon('input[name="scan-mode"][value="full"] + span', u.scan_full);
    const scanFullHint = document.querySelector('input[name="scan-mode"][value="full"]')?.closest('label')?.nextElementSibling;
    if (scanFullHint) scanFullHint.textContent = u.scan_full_hint;
    setWithIcon('input[name="scan-mode"][value="critical"] + span', u.scan_critical);
    const scanCriticalHint = document.querySelector('input[name="scan-mode"][value="critical"]')?.closest('label')?.nextElementSibling;
    if (scanCriticalHint) {
        const icon = scanCriticalHint.querySelector('i');
        scanCriticalHint.innerHTML = '';
        if (icon) scanCriticalHint.appendChild(icon);
        scanCriticalHint.appendChild(document.createTextNode((icon ? ' ' : '') + u.scan_critical_hint));
    }

    const layer3Label = document.querySelector('#layer3-tools-section > label');
    if (layer3Label) {
        const icon = layer3Label.querySelector('i');
        layer3Label.innerHTML = '';
        if (icon) layer3Label.appendChild(icon);
        layer3Label.appendChild(document.createTextNode((icon ? ' ' : '') + u.layer3_tools_label));
    }
    setWithIcon('input[name="layer3-tool"][value="port_scan"] + span', u.layer3_port_scan);
    setWithIcon('input[name="layer3-tool"][value="vuln_scan"] + span', u.layer3_vuln_scan);
    const legalTitle = document.querySelector('.legal-consent-box p strong');
    if (legalTitle) legalTitle.textContent = u.legal_warning_title;
    const legalText = document.querySelector('.legal-consent-box p:nth-child(2)');
    if (legalText) legalText.textContent = u.legal_warning_text;
    const legalConsent = document.querySelector('#legal-consent-checkbox + span');
    if (legalConsent) legalConsent.textContent = u.legal_consent_text;

    // Settings buttons
    const clearCacheBtn = document.getElementById('btn-clear-cache');
    if (clearCacheBtn) {
        clearCacheBtn.innerHTML = `<i class="fas fa-trash mr-2"></i> ${trans['clear_cache_btn'] || 'Vider le cache'}`;
    }

    const testBtn = document.getElementById('btn-test-notification');
    if (testBtn) {
        testBtn.innerHTML = `<i class="fas fa-bell mr-2"></i> ${trans['test_btn'] || 'Tester'}`;
    }

    const resetBtn = document.querySelector('button[onclick="resetSettings()"]');
    if (resetBtn) {
        resetBtn.innerHTML = `<i class="fas fa-undo mr-2"></i> ${trans['reset'] || 'Réinitialiser'}`;
    }

    const saveBtn = document.querySelector('button[onclick="saveSettings()"]');
    if (saveBtn) {
        saveBtn.innerHTML = `<i class="fas fa-save mr-2"></i> ${trans['save'] || 'Sauvegarder'}`;
    }

    // Favorites placeholder
    const favInput = document.getElementById('new-favorite-input');
    if (favInput) {
        favInput.placeholder = trans['favorites_placeholder'] || 'Ajouter une cible...';
    }

    setText('.settings-section:nth-child(4) .settings-field > label', trans['space_used'] || 'Espace utilisé');
    setText('label[for="setting-cache-ttl"]', trans['cache_ttl_days'] || 'TTL du cache (jours)');
    setText('.settings-section:nth-child(6) .settings-field > label', trans['default_format'] || 'Format par défaut');
    setText('.settings-section:nth-child(5) .settings-field > label', u.report_style);
    setWithIcon('input[name="report-template"][value="detailed"] + span', u.template_detailed);
    const detailedHint = document.querySelector('input[name="report-template"][value="detailed"]')?.closest('label')?.nextElementSibling;
    if (detailedHint) detailedHint.textContent = u.template_detailed_hint;
    setWithIcon('input[name="report-template"][value="executive"] + span', u.template_executive);
    const executiveHint = document.querySelector('input[name="report-template"][value="executive"]')?.closest('label')?.nextElementSibling;
    if (executiveHint) executiveHint.textContent = u.template_executive_hint;
    setWithIcon('input[name="report-template"][value="technical"] + span', u.template_technical);
    const technicalHint = document.querySelector('input[name="report-template"][value="technical"]')?.closest('label')?.nextElementSibling;
    if (technicalHint) technicalHint.textContent = u.template_technical_hint;
    setWithIcon('input[name="report-template"][value="minimal"] + span', u.template_minimal);
    const minimalHint = document.querySelector('input[name="report-template"][value="minimal"]')?.closest('label')?.nextElementSibling;
    if (minimalHint) minimalHint.textContent = u.template_minimal_hint;
    setText('.settings-section:nth-child(9) .settings-field > label', u.interface_language);
    setText('.settings-section:nth-child(10) label[for="setting-max-reports"]', trans['max_reports'] || 'Nombre max de rapports');
    setText('.settings-section:nth-child(10) label[for="setting-auto-delete"]', trans['auto_delete_days'] || 'Auto-suppression après (jours)');
    setText('.settings-section:nth-child(10) .settings-hint', trans['auto_delete_hint'] || '0 = jamais supprimer');
    const darkLabel = document.querySelector('#setting-dark-mode + .toggle-slider + .toggle-label');
    if (darkLabel) darkLabel.textContent = u.dark_mode;
    setText('.settings-section:nth-child(8) .settings-hint', u.theme_toggle_hint);
    const compactLabel = document.querySelector('#setting-compact-mode + .toggle-slider + .toggle-label');
    if (compactLabel) compactLabel.textContent = trans['compact_mode'] || 'Mode compact';
    setText('label[for="setting-font-size"]', trans['font_size'] || 'Taille de police');
    const notifLabel = document.querySelector('#setting-notifications + .toggle-slider + .toggle-label');
    if (notifLabel) notifLabel.textContent = trans['browser_alerts'] || 'Alertes navigateur';
    setText('.settings-section:nth-child(11) .settings-hint', trans['notification_hint'] || '');
    const fontOptions = document.querySelectorAll('#setting-font-size option');
    if (fontOptions.length >= 3) {
        fontOptions[0].textContent = trans['font_small'] || 'Petite';
        fontOptions[1].textContent = trans['font_medium'] || 'Moyenne';
        fontOptions[2].textContent = trans['font_large'] || 'Grande';
    }

    // PWA install buttons
    const installBtn = document.querySelector('.install-btn');
    if (installBtn) installBtn.textContent = u.install;

    const dismissBtn = document.querySelector('.dismiss-btn');
    if (dismissBtn) dismissBtn.textContent = u.later;
}

// Detect browser language and map to supported languages
function detectBrowserLanguage() {
    const supportedLanguages = ['fr', 'en', 'es', 'de'];
    const browserLang = navigator.language || navigator.userLanguage || 'fr';
    const langCode = browserLang.split('-')[0].toLowerCase();

    if (supportedLanguages.includes(langCode)) {
        return langCode;
    }
    // Default to English for unsupported languages, French for francophone fallback
    return browserLang.startsWith('fr') ? 'fr' : 'en';
}

// Load settings from localStorage
function loadSettings() {
    try {
        const saved = localStorage.getItem('ananta-settings');
        if (saved) {
            return { ...DEFAULT_SETTINGS, ...JSON.parse(saved) };
        } else {
            // First time load - detect browser language
            const detectedLang = detectBrowserLanguage();
            console.log('[Settings] Auto-detected language:', detectedLang);
            return { ...DEFAULT_SETTINGS, language: detectedLang };
        }
    } catch {
        return { ...DEFAULT_SETTINGS };
    }
}

let appSettings = loadSettings();

const API_BASE = (() => {
    // Check if user has set a custom API URL
    if (appSettings.apiUrl && appSettings.apiUrl.trim()) {
        return appSettings.apiUrl.trim().replace(/\/$/, '');
    }
    try {
        const host = window.location.hostname;
        const port = window.location.port;
        const isBackendHosted = (host === "127.0.0.1" || host === "localhost") && String(port) === "8010";
        return isBackendHosted ? "" : "http://127.0.0.1:8010";
    } catch {
        return "http://127.0.0.1:8010";
    }
})();

let startTime = Date.now();
let lastQuery = "";
let lastTarget = "";

/**
 * Extrait la cible (IP ou domaine) d'une requête
 * "analyze 1.1.1.1" → "1.1.1.1"
 * "analyze google.com" → "google.com"
 * "1.1.1.1" → "1.1.1.1"
 */
function extractTarget(query) {
    if (!query) return "";
    let q = query.trim();

    // Retirer les préfixes de commande
    const prefixes = ["analyze", "whois", "censys", "scan"];
    for (const prefix of prefixes) {
        if (q.toLowerCase().startsWith(prefix + " ")) {
            q = q.substring(prefix.length + 1).trim();
            break;
        }
    }

    // Retirer les protocoles et www
    q = q.replace(/^https?:\/\//i, "").replace(/^www\./i, "");

    // Garder seulement le domaine/IP (pas le path)
    q = q.split("/")[0].split("?")[0];

    return q;
}

// --- HORLOGE ---
function updateClock() {
    const diff = Math.floor((Date.now() - startTime) / 1000);
    const h = String(Math.floor(diff / 3600)).padStart(2, '0');
    const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
    const s = String(diff % 60).padStart(2, '0');
    const el = document.getElementById("runtime-clock");
    if (el) el.textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);

// --- UI HELPERS ---
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function addChatMessage({ author, content }) {
    const chatInner = document.getElementById("chat-inner");
    if (!chatInner) return;

    const wrapper = document.createElement("div");
    const isUser = author === "ANALYSTE";
    wrapper.className = isUser ? "message-appear user-message" : "message-appear";

    const icon = isUser ? "fa-user-secret" : (author === "SYSTEM" ? "fa-triangle-exclamation" : "fa-robot");
    const accent = isUser ? "slate" : (author === "SYSTEM" ? "rose" : "cyan");

    // Pour l'utilisateur : largeur réduite (max-w-[70%]) et poussé à droite
    const widthClass = isUser ? "max-w-[70%] ml-auto" : "w-full";

    wrapper.innerHTML = `
    <div class="flex gap-5 items-start ${isUser ? 'flex-row-reverse text-right' : ''} ${widthClass}">
      <div class="w-10 h-10 rounded-lg bg-${accent}-500/10 border border-${accent}-500/20 flex items-center justify-center text-${accent}-400 flex-shrink-0 shadow-lg">
        <i class="fas ${icon}"></i>
      </div>
      <div class="flex-1 overflow-hidden">
        <div class="flex items-center gap-3 mb-2 ${isUser ? 'justify-end' : ''}">
          <span class="text-[10px] font-bold uppercase tracking-widest text-slate-500">${escapeHtml(author)}</span>
          <span class="text-[9px] text-slate-700">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="p-4 rounded-xl ${isUser ? 'bg-slate-800/40 border border-slate-700' : 'glass-panel border-cyan-500/20'} text-sm leading-relaxed text-slate-300">
          ${content}
        </div>
      </div>
    </div>
  `;

    chatInner.appendChild(wrapper);

    const chatZone = document.getElementById("chat-zone");
    setTimeout(() => {
        chatZone?.scrollTo({ top: chatZone.scrollHeight, behavior: 'smooth' });
    }, 50);
}

function addApprovalRequest({ approval_id, tool_name, target, message }) {
    const chatInner = document.getElementById("chat-inner");
    if (!chatInner) return;

    const wrapper = document.createElement("div");
    wrapper.className = "message-appear";
    wrapper.id = `approval-${approval_id}`;

    wrapper.innerHTML = `
    <div class="flex gap-5 items-start w-full">
      <div class="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 flex-shrink-0 shadow-lg">
        <i class="fas fa-shield-halved"></i>
      </div>
      <div class="flex-1 overflow-hidden">
        <div class="flex items-center gap-3 mb-2">
          <span class="text-[10px] font-bold uppercase tracking-widest text-amber-500">APPROBATION REQUISE</span>
          <span class="text-[9px] text-slate-700">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="p-4 rounded-xl glass-panel border-amber-500/20 text-sm leading-relaxed text-slate-300">
          <p class="mb-3"><i class="fas fa-exclamation-triangle text-amber-400 mr-2"></i>${escapeHtml(message)}</p>
          <div class="bg-slate-900/50 p-3 rounded border border-slate-700 mb-4 text-xs">
            <div class="flex justify-between mb-1">
              <span class="text-slate-500">Outil:</span>
              <span class="text-cyan-400 font-bold">${escapeHtml(tool_name)}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-500">Cible:</span>
              <span class="text-slate-300">${escapeHtml(target)}</span>
            </div>
          </div>
          <div class="flex gap-3" id="approval-buttons-${approval_id}">
            <button onclick="approveToolUsage('${approval_id}')"
                    class="flex-1 px-4 py-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg hover:bg-emerald-500/20 transition-all font-bold text-xs">
              <i class="fas fa-check mr-2"></i>APPROUVER
            </button>
            <button onclick="denyToolUsage('${approval_id}')"
                    class="flex-1 px-4 py-2 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-lg hover:bg-rose-500/20 transition-all font-bold text-xs">
              <i class="fas fa-times mr-2"></i>REFUSER
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

    chatInner.appendChild(wrapper);

    const chatZone = document.getElementById("chat-zone");
    setTimeout(() => {
        chatZone?.scrollTo({ top: chatZone.scrollHeight, behavior: 'smooth' });
    }, 50);
}

async function approveToolUsage(approval_id) {
    const buttonsDiv = document.getElementById(`approval-buttons-${approval_id}`);
    if (!buttonsDiv) return;

    buttonsDiv.innerHTML = '<p class="text-center text-emerald-400 text-xs"><i class="fas fa-spinner fa-spin mr-2"></i>Approbation en cours...</p>';

    try {
        const response = await fetch(`${API_BASE}/agent/approve/${approval_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            throw new Error(`Erreur ${response.status}: ${await response.text()}`);
        }

        const result = await response.json();

        buttonsDiv.innerHTML = `<p class="text-center text-emerald-400 text-sm font-bold"><i class="fas fa-check-circle mr-2"></i>Outil approuvé</p>`;

        addChatMessage({
            author: "SYSTEM",
            content: `<span class="text-emerald-400 font-bold">✅ Outil ${result.tool_name} approuvé.</span> Poursuite du scan en cours...`
        });

    } catch (e) {
        buttonsDiv.innerHTML = `<p class="text-center text-rose-400 text-xs"><i class="fas fa-exclamation-circle mr-2"></i>Erreur: ${escapeHtml(e.message)}</p>`;
    }
}

async function denyToolUsage(approval_id) {
    const buttonsDiv = document.getElementById(`approval-buttons-${approval_id}`);
    if (!buttonsDiv) return;

    buttonsDiv.innerHTML = '<p class="text-center text-rose-400 text-xs"><i class="fas fa-spinner fa-spin mr-2"></i>Refus en cours...</p>';

    try {
        const response = await fetch(`${API_BASE}/agent/deny/${approval_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            throw new Error(`Erreur ${response.status}: ${await response.text()}`);
        }

        const result = await response.json();

        buttonsDiv.innerHTML = `<p class="text-center text-rose-400 text-sm font-bold"><i class="fas fa-times-circle mr-2"></i>Outil refusé</p>`;

        addChatMessage({
            author: "SYSTEM",
            content: `<span class="text-rose-400 font-bold">❌ Outil ${result.tool_name} refusé.</span> Le scan continuera sans cet outil.`
        });

    } catch (e) {
        buttonsDiv.innerHTML = `<p class="text-center text-rose-400 text-xs"><i class="fas fa-exclamation-circle mr-2"></i>Erreur: ${escapeHtml(e.message)}</p>`;
    }
}

// Lazy Loading Observer for report sections
const lazyLoadObserver = 'IntersectionObserver' in window ? new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const section = entry.target;
            const lazyContent = section.getAttribute('data-lazy-content');
            if (lazyContent) {
                try {
                    // Replace placeholder with actual content
                    section.innerHTML = decodeURIComponent(lazyContent);
                    section.removeAttribute('data-lazy-content');
                    section.classList.remove('lazy-section');
                    section.classList.add('lazy-section-loaded');
                } catch (e) {
                    console.error('[LazyLoad] Error loading section:', e);
                }
            }
            lazyLoadObserver.unobserve(section);
        }
    });
}, {
    rootMargin: '100px', // Start loading 100px before visible
    threshold: 0.1
}) : null;

// Create a lazy-loadable section
function createLazySection(content, placeholder = null) {
    if (!lazyLoadObserver) {
        // Fallback: return content directly if IntersectionObserver not supported
        return content;
    }

    const sectionId = `lazy-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const placeholderHtml = placeholder || `
        <div class="lazy-placeholder animate-pulse">
            <div class="h-4 bg-slate-700 rounded w-3/4 mb-2"></div>
            <div class="h-3 bg-slate-700 rounded w-1/2"></div>
        </div>
    `;

    // Schedule observer attachment after DOM is updated
    setTimeout(() => {
        const section = document.getElementById(sectionId);
        if (section) {
            lazyLoadObserver.observe(section);
        }
    }, 0);

    return `
        <div id="${sectionId}" class="lazy-section" data-lazy-content="${encodeURIComponent(content)}">
            ${placeholderHtml}
        </div>
    `;
}

function renderOsintResults(results, useLazyLoad = true) {
    if (!results || results.length === 0) {
        return `<p class="text-rose-400 italic">⚠️ Aucun point d'entrée trouvé pour cette cible.</p>`;
    }

    // For large result sets, use lazy loading
    const LAZY_THRESHOLD = 4;
    const shouldLazyLoad = useLazyLoad && results.length > LAZY_THRESHOLD;

    const renderCard = (r, i) => `
    <div class="osint-card border border-slate-800 bg-slate-900/40 p-4 rounded-xl transition-all" role="article" aria-label="Source ${i + 1}">
      <div class="flex justify-between items-start mb-3">
        <span class="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded text-[9px] font-bold uppercase tracking-tighter">SOURCE #${i + 1}</span>
        <a href="${r.url}" target="_blank" rel="noopener noreferrer" class="text-slate-500 hover:text-cyan-400 transition-colors" aria-label="Ouvrir la source dans un nouvel onglet">
          <i class="fas fa-external-link-alt text-xs" aria-hidden="true"></i>
        </a>
      </div>
      <h4 class="text-cyan-100 font-bold text-sm mb-2 truncate">${escapeHtml(r.title || 'Sans titre')}</h4>
      <p class="text-slate-400 text-xs line-clamp-3 mb-4 font-sans leading-relaxed">
        ${escapeHtml(r.summary || r.description || 'Aucune description disponible.')}
      </p>
    </div>
  `;

    if (shouldLazyLoad) {
        // Render first few cards immediately, lazy load the rest
        const immediateCards = results.slice(0, LAZY_THRESHOLD).map((r, i) => renderCard(r, i)).join("");
        const lazyCards = results.slice(LAZY_THRESHOLD).map((r, i) => renderCard(r, i + LAZY_THRESHOLD)).join("");

        const lazySection = createLazySection(
            `<div class="grid grid-cols-1 md:grid-cols-2 gap-4">${lazyCards}</div>`,
            `<div class="text-center py-4">
                <i class="fas fa-spinner fa-spin text-cyan-500 mr-2"></i>
                <span class="text-slate-500 text-xs">Chargement de ${results.length - LAZY_THRESHOLD} sources supplémentaires...</span>
            </div>`
        );

        return `
        <div class="space-y-4 mt-2">
          <p class="text-xs text-slate-500 uppercase tracking-widest font-bold mb-4">Sources Analysées (${results.length}):</p>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${immediateCards}
          </div>
          ${lazySection}
        </div>
      `;
    }

    // Standard rendering for small result sets
    const cards = results.map((r, i) => renderCard(r, i)).join("");

    return `
    <div class="space-y-4 mt-2">
      <p class="text-xs text-slate-500 uppercase tracking-widest font-bold mb-4">Sources Analysées :</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        ${cards}
      </div>
    </div>
  `;
}

// Render Layer 3 (Critical) scan results
function renderLayer3Results(result) {
    const { target, tools_executed, results, warning } = result;
    let html = '';

    // Warning banner
    if (warning) {
        html += `<div class="mb-4 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
            <p class="text-amber-400 text-xs"><i class="fas fa-exclamation-triangle mr-2"></i>${escapeHtml(warning)}</p>
        </div>`;
    }

    // Port scan results
    if (results.port_scan && results.port_scan.raw) {
        const ps = results.port_scan.raw;
        html += `<div class="mb-4 p-4 bg-slate-900/60 border border-slate-700 rounded-xl">
            <div class="flex items-center gap-2 mb-3">
                <i class="fas fa-network-wired text-cyan-400"></i>
                <span class="text-cyan-400 font-bold text-sm uppercase">Port Scan</span>
                <span class="ml-auto text-xs text-slate-500">${ps.scan_type || 'TCP'}</span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs mb-3">
                <div class="bg-slate-800/50 p-2 rounded">
                    <span class="text-slate-500">Ports scannés:</span>
                    <span class="text-slate-200 ml-2">${ps.ports_scanned || 0}</span>
                </div>
                <div class="bg-slate-800/50 p-2 rounded">
                    <span class="text-slate-500">Ports ouverts:</span>
                    <span class="text-emerald-400 ml-2 font-bold">${ps.ports_open || 0}</span>
                </div>
            </div>`;

        if (ps.open_ports && ps.open_ports.length > 0) {
            html += `<div class="space-y-1">
                <p class="text-xs text-slate-400 mb-2">Ports ouverts détectés:</p>
                <div class="grid grid-cols-2 md:grid-cols-3 gap-2">`;
            ps.open_ports.forEach(port => {
                html += `<div class="bg-emerald-500/10 border border-emerald-500/20 p-2 rounded text-xs">
                    <span class="text-emerald-400 font-mono font-bold">${port.port}</span>
                    <span class="text-slate-400 mx-1">/</span>
                    <span class="text-slate-300">${escapeHtml(port.service || 'unknown')}</span>
                </div>`;
            });
            html += `</div></div>`;
        }
        html += `</div>`;
    }

    // Vulnerability scan results
    if (results.vuln_scan && results.vuln_scan.raw) {
        const vs = results.vuln_scan.raw;
        const riskColors = {
            'CRITICAL': 'rose',
            'HIGH': 'red',
            'MEDIUM': 'amber',
            'LOW': 'emerald'
        };
        const riskColor = riskColors[vs.risk_level] || 'slate';

        html += `<div class="mb-4 p-4 bg-slate-900/60 border border-slate-700 rounded-xl">
            <div class="flex items-center gap-2 mb-3">
                <i class="fas fa-shield-alt text-${riskColor}-400"></i>
                <span class="text-${riskColor}-400 font-bold text-sm uppercase">Vulnerability Scan</span>
                <span class="ml-auto px-2 py-0.5 bg-${riskColor}-500/20 text-${riskColor}-400 rounded text-xs font-bold">
                    ${vs.risk_level || 'UNKNOWN'} (Score: ${vs.risk_score || 0}/10)
                </span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs mb-3">
                <div class="bg-slate-800/50 p-2 rounded">
                    <span class="text-slate-500">Vulnérabilités:</span>
                    <span class="text-amber-400 ml-2 font-bold">${vs.vulnerabilities_found || 0}</span>
                </div>
                <div class="bg-slate-800/50 p-2 rounded">
                    <span class="text-slate-500">CVE détectées:</span>
                    <span class="text-rose-400 ml-2 font-bold">${vs.cve_found || 0}</span>
                </div>
            </div>`;

        // Security headers present
        if (vs.security_headers_present && vs.security_headers_present.length > 0) {
            html += `<div class="mb-3">
                <p class="text-xs text-emerald-400 mb-2"><i class="fas fa-check-circle mr-1"></i>Headers de sécurité présents:</p>
                <div class="flex flex-wrap gap-1">`;
            vs.security_headers_present.forEach(h => {
                html += `<span class="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded text-[10px]">${escapeHtml(h)}</span>`;
            });
            html += `</div></div>`;
        }

        // Vulnerabilities found
        if (vs.vulnerabilities && vs.vulnerabilities.length > 0) {
            html += `<div class="space-y-2">
                <p class="text-xs text-amber-400 mb-2"><i class="fas fa-exclamation-circle mr-1"></i>Problèmes détectés:</p>`;
            vs.vulnerabilities.forEach(v => {
                const sevColor = v.severity === 'HIGH' || v.severity === 'CRITICAL' ? 'rose' :
                                v.severity === 'MEDIUM' ? 'amber' : 'slate';
                html += `<div class="bg-${sevColor}-500/5 border border-${sevColor}-500/20 p-2 rounded">
                    <div class="flex items-center gap-2 mb-1">
                        <span class="px-1.5 py-0.5 bg-${sevColor}-500/20 text-${sevColor}-400 rounded text-[9px] font-bold">${v.severity}</span>
                        <span class="text-slate-300 text-xs">${escapeHtml(v.type)}</span>
                    </div>
                    <p class="text-slate-400 text-xs">${escapeHtml(v.description)}</p>
                    ${v.remediation ? `<p class="text-slate-500 text-[10px] mt-1"><i class="fas fa-wrench mr-1"></i>${escapeHtml(v.remediation)}</p>` : ''}
                </div>`;
            });
            html += `</div>`;
        }

        // CVE findings
        if (vs.cve_findings && vs.cve_findings.length > 0) {
            html += `<div class="mt-3 space-y-2">
                <p class="text-xs text-rose-400 mb-2"><i class="fas fa-bug mr-1"></i>CVE détectées:</p>`;
            vs.cve_findings.forEach(cve => {
                html += `<div class="bg-rose-500/10 border border-rose-500/20 p-2 rounded">
                    <span class="text-rose-400 font-mono text-xs font-bold">${escapeHtml(cve.cve_id)}</span>
                    <span class="text-slate-400 text-xs ml-2">${escapeHtml(cve.description || '')}</span>
                </div>`;
            });
            html += `</div>`;
        }

        html += `</div>`;
    }

    // Tools executed summary
    html += `<div class="mt-4 pt-3 border-t border-slate-800">
        <p class="text-xs text-slate-500">
            <i class="fas fa-tools mr-1"></i>Outils exécutés:
            <span class="text-slate-400">${tools_executed ? tools_executed.join(', ') : 'N/A'}</span>
        </p>
    </div>`;

    return html;
}

function updateIntelFeed(results) {
    const feed = document.getElementById("intel-feed");
    if (!feed || !results || results.length === 0) return;

    if (feed.querySelector(".italic")) feed.innerHTML = "";

    // On prend les 5 premiers pour ne pas spammer
    results.slice(0, 5).forEach(r => {
        const item = document.createElement("div");
        item.className = "p-2 rounded bg-slate-800/30 border-l-2 border-cyan-500 text-[10px] message-appear";
        item.innerHTML = `
      <div class="text-slate-400 truncate font-bold uppercase mb-1">${escapeHtml(r.title || 'Donnée')}</div>
      <div class="text-cyan-400 truncate opacity-70">${escapeHtml(r.url || '')}</div>
    `;
        feed.prepend(item);
    });
}

function setBar(pct, percentEl, barEl) {
    if (!percentEl || !barEl) {
        console.warn('[setBar] Missing elements:', { percentEl: !!percentEl, barEl: !!barEl });
        return;
    }

    if (typeof pct === "number" && Number.isFinite(pct)) {
        const v = Math.max(0, Math.min(100, pct));
        percentEl.textContent = `${v.toFixed(0)}%`;
        percentEl.className = "text-[10px] font-bold text-cyan-500";
        barEl.style.width = `${v}%`;
        console.log('[setBar] Updated bar:', v + '%');
    } else {
        percentEl.textContent = `--%`;
        percentEl.className = "text-[10px] font-bold text-slate-600";
        barEl.style.width = `0%`;
        console.log('[setBar] No valid data, resetting bar');
    }
}

// --- SYSTEM PULSE ELEMENTS ---
const ledApi = document.getElementById("led-api");

const dbLatencyEl = document.getElementById("db-latency");
const workerStatusEl = document.getElementById("worker-status");

const cpuPercentEl = document.getElementById("cpu-percent");
const cpuBarEl = document.getElementById("cpu-bar");

const gpuPercentEl = document.getElementById("gpu-percent");
const gpuBarEl = document.getElementById("gpu-bar");

// --- SYSTEM PULSE ---
async function updateSystemPulse() {
  const ledApi = document.getElementById("led-api");
  const workerStatusEl = document.getElementById("worker-status");
  const dbLatencyEl = document.getElementById("db-latency");

  const cpuPercentEl = document.getElementById("cpu-percent");
  const cpuBarEl = document.getElementById("cpu-bar");
  const gpuPercentEl = document.getElementById("gpu-percent");
  const gpuBarEl = document.getElementById("gpu-bar");

  try {
    console.log('[System Pulse] Fetching health data from:', `${API_BASE}/health`);
    const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });

    if (!res.ok) {
      console.error('[System Pulse] Health endpoint returned status:', res.status);
      throw new Error(`Health not OK (${res.status})`);
    }

    const data = await res.json();
    console.log('[System Pulse] Received data:', data);

    // LED API
    if (ledApi) {
      ledApi.className = "status-led led-green";
      console.log('[System Pulse] LED set to green');
    }

    // DB Latency
    if (dbLatencyEl) {
      if (typeof data.db_latency_ms === "number" && data.db_latency_ms >= 0) {
        dbLatencyEl.textContent = `${data.db_latency_ms} ms`;
        dbLatencyEl.className = "text-xs font-bold text-emerald-400";
      } else {
        dbLatencyEl.textContent = "ERROR";
        dbLatencyEl.className = "text-xs font-bold text-rose-400";
      }
      console.log('[System Pulse] DB latency updated:', dbLatencyEl.textContent);
    }

    // Worker state
    if (workerStatusEl) {
      const state = (data.worker_state || "UNKNOWN").toUpperCase();
      workerStatusEl.textContent = state;

      if (state === "STABLE") workerStatusEl.className = "text-xs font-bold text-cyan-400";
      else if (state === "DEGRADED") workerStatusEl.className = "text-xs font-bold text-amber-400";
      else workerStatusEl.className = "text-xs font-bold text-slate-500";

      console.log('[System Pulse] Worker state updated:', state);
    }

    // CPU and GPU bars
    console.log('[System Pulse] Setting CPU bar:', data.cpu_load);
    setBar(data.cpu_load, cpuPercentEl, cpuBarEl);

    console.log('[System Pulse] Setting GPU bar:', data.gpu_load);
    setBar(data.gpu_load, gpuPercentEl, gpuBarEl);

  } catch (e) {
    console.error('[System Pulse] Error:', e.message, e);

    if (ledApi) ledApi.className = "status-led led-red";

    if (dbLatencyEl) {
      dbLatencyEl.textContent = "--";
      dbLatencyEl.className = "text-xs font-bold text-slate-600";
    }

    if (workerStatusEl) {
      workerStatusEl.textContent = "OFFLINE";
      workerStatusEl.className = "text-xs font-bold text-slate-500";
    }

    setBar(null, cpuPercentEl, cpuBarEl);
    setBar(null, gpuPercentEl, gpuBarEl);
  }
}


// --- ACTIONS BACKEND ---
async function askBackend(query) {
    const llmHardLimit = Math.max(200, Math.min(5000, Number(appSettings.llmHardLimit || 4000)));
    const res = await fetch(`${API_BASE}/agent/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, llm_hard_limit: llmHardLimit })
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Erreur inconnue" }));
        throw new Error(err.detail || "Le serveur a renvoyé une erreur.");
    }
    return res.json();
}

async function askBackendAsync(query) {
    // Récupérer le scan_mode depuis les settings (défaut: "standard")
    const scanMode = appSettings.scanMode || 'standard';
    // Récupérer la langue depuis les settings (défaut: "fr")
    const language = appSettings.language || 'fr';
    // Récupérer le template de rapport (défaut: "detailed")
    const reportTemplate = appSettings.reportTemplate || 'detailed';
    const llmHardLimit = Math.max(200, Math.min(5000, Number(appSettings.llmHardLimit || 4000)));

    // Build request payload
    const payload = {
        query: query,
        scan_mode: scanMode,
        language: language,
        report_template: reportTemplate,
        llm_hard_limit: llmHardLimit
    };

    // Si mode critique, vérifier le consentement et récupérer les outils approuvés
    if (scanMode === 'critical') {
        const legalConsent = document.getElementById('legal-consent-checkbox');
        if (!legalConsent || !legalConsent.checked) {
            throw new Error(t('critical_consent_required') || "Vous devez confirmer avoir l'autorisation légale pour utiliser les outils Layer 3.");
        }

        // Récupérer les outils Layer 3 sélectionnés
        const selectedTools = Array.from(document.querySelectorAll('input[name="layer3-tool"]:checked'))
            .map(cb => cb.value);

        if (selectedTools.length === 0) {
            throw new Error(t('critical_no_tools') || "Vous devez sélectionner au moins un outil Layer 3.");
        }

        payload.approved_tools = selectedTools;
    }

    const res = await fetch(`${API_BASE}/agent/ask_async`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Erreur inconnue" }));
        throw new Error(err.detail || "Le serveur a renvoyé une erreur.");
    }
    return res.json();
}

async function pollJobStatus(jobId) {
    const res = await fetch(`${API_BASE}/jobs/${jobId}`);
    if (!res.ok) {
        throw new Error("Impossible de récupérer le statut du job");
    }
    return res.json();
}

// WebSocket support for real-time job updates
function createJobWebSocket(jobId, onUpdate, onComplete, onError) {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = API_BASE.replace(/^https?:\/\//, '') || `${window.location.hostname}:${window.location.port}`;
    const wsUrl = `${wsProtocol}//${wsHost}/ws/jobs/${jobId}`;

    console.log('[WebSocket] Connecting to:', wsUrl);

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('[WebSocket] Connected for job:', jobId);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            console.log('[WebSocket] Received:', data.type, data);

            if (data.type === 'update' || data.type === 'status') {
                onUpdate(data);
            }

            if (data.type === 'complete' || data.status === 'COMPLETED' || data.status === 'FAILED') {
                onComplete(data);
                ws.close();
            }

            if (data.type === 'error') {
                onError(new Error(data.message || 'WebSocket error'));
                ws.close();
            }
        } catch (e) {
            console.error('[WebSocket] Parse error:', e);
        }
    };

    ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error);
        onError(new Error('WebSocket connection error'));
    };

    ws.onclose = (event) => {
        console.log('[WebSocket] Closed:', event.code, event.reason);
    };

    // Ping to keep connection alive
    const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
        } else {
            clearInterval(pingInterval);
        }
    }, 30000);

    return {
        ws,
        close: () => {
            clearInterval(pingInterval);
            ws.close();
        }
    };
}

function isOsintQuery(query) {
    // Détecte si c'est une commande OSINT longue (analyze, IP, domaine)
    const q = query.toLowerCase();
    if (q.startsWith("analyze")) return true;
    // Regex simple pour IP et domaine
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(query)) return true;
    if (/\b([a-z0-9-]+\.)+[a-z]{2,}\b/i.test(query)) return true;
    return false;
}

async function handleExecution() {
    const input = document.getElementById("query-input");
    const btn = document.getElementById("send-btn");
    const q = input?.value?.trim();

    if (!q) return;

    input.value = "";
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-circle-notch animate-spin text-slate-900"></i>';

    addChatMessage({ author: "ANALYSTE", content: escapeHtml(q) });
    lastQuery = q;
    lastTarget = extractTarget(q);  // Extraire la cible pour l'export PDF

    // Détecter si c'est une requête OSINT longue → Mode ASYNC
    const useAsync = isOsintQuery(q);

    try {
        if (useAsync) {
            // MODE ASYNCHRONE avec polling
            const asyncData = await askBackendAsync(q);

            if (asyncData.type === "async" && asyncData.job_id) {
                addChatMessage({
                    author: "SYSTEM",
                    content: `<div class="text-amber-400"><i class="fas fa-hourglass-half"></i> ${t('scan_launched')}</div>
                              <div class="text-xs text-slate-500 mt-1">Job ID: <code class="text-cyan-400">${asyncData.job_id}</code></div>`
                });
                await pollAndDisplayResults(asyncData.job_id);
            } else {
                throw new Error("Réponse async invalide");
            }

        } else {
            // MODE SYNCHRONE classique
            const data = await askBackend(q);

            let aiContent = "";

            if (data.answer) {
                // Parse markdown to HTML for proper rendering
                const renderedAnswer = parseMarkdown(data.answer);
                aiContent += `<div class="mb-4 prose prose-invert prose-sm max-w-none">${renderedAnswer}</div>`;
            }

            if (data.results && data.results.length > 0) {
                aiContent += renderOsintResults(data.results);
                updateIntelFeed(data.results);
            }

            if (!aiContent) {
                aiContent = "<i>Aucune donnée retournée.</i>";
            }

            addChatMessage({ author: "ANANTA AI", content: aiContent });
        }

    } catch (e) {
        addChatMessage({ author: "SYSTEM", content: `<span class="text-rose-500 font-bold">ERREUR CRITIQUE:</span> ${escapeHtml(e.message)}` });
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>${t('execute')}</span> <i class="fas fa-paper-plane text-xs"></i>`;
    }
}

async function pollAndDisplayResults(jobId) {
    // Créer un message de progression
    const chatInner = document.getElementById("chat-inner");
    const progressWrapper = document.createElement("div");
    progressWrapper.className = "message-appear";
    progressWrapper.innerHTML = `
        <div class="glass-panel border-cyan-500/20 p-4 rounded-xl">
            <div class="flex items-center gap-3 mb-3">
                <i class="fas fa-sync animate-spin text-cyan-400"></i>
                <span class="text-sm font-bold text-cyan-400">SCAN EN COURS</span>
                <span id="connection-type-${jobId}" class="text-[10px] text-slate-600 ml-auto"></span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div id="progress-bar-${jobId}" class="bg-cyan-500 h-2 transition-all duration-300" style="width: 0%"></div>
            </div>
            <div id="progress-text-${jobId}" class="text-xs text-slate-500 mt-2">Initialisation...</div>
        </div>
    `;
    chatInner.appendChild(progressWrapper);

    const progressBar = document.getElementById(`progress-bar-${jobId}`);
    const progressText = document.getElementById(`progress-text-${jobId}`);
    const connectionType = document.getElementById(`connection-type-${jobId}`);

    // Try WebSocket first, fallback to polling
    const useWebSocket = 'WebSocket' in window;

    return new Promise((resolve, reject) => {
        let wsConnection = null;
        let pollingFallback = false;

        const handleResult = (result) => {
            progressWrapper.remove();
            let aiContent = "";

            // Check if this is a Layer 3 (critical) scan result
            if (result.layer === 3 && result.results) {
                aiContent += `<div class="mb-4">
                    <div class="flex items-center gap-2 mb-3">
                        <span class="px-2 py-1 bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded text-xs font-bold">
                            <i class="fas fa-radiation mr-1"></i>LAYER 3 CRITICAL SCAN
                        </span>
                        <span class="text-slate-400 text-xs">${escapeHtml(result.target)}</span>
                    </div>
                </div>`;

                if (result.report) {
                    const renderedReport = parseMarkdown(result.report);
                    aiContent += `<div class="mb-4 prose prose-invert prose-sm max-w-none">${renderedReport}</div>`;
                }

                aiContent += `<details class="mt-4">
                    <summary class="cursor-pointer text-sm text-slate-400 hover:text-cyan-400">
                        <i class="fas fa-code mr-2"></i>Données brutes du scan
                    </summary>
                    <div class="mt-2">${renderLayer3Results(result)}</div>
                </details>`;
            } else {
                if (result.report) {
                    const renderedReport = parseMarkdown(result.report);
                    aiContent += `<div class="mb-4 prose prose-invert prose-sm max-w-none">${renderedReport}</div>`;
                }

                if (result.sources && result.sources.length > 0) {
                    aiContent += renderOsintResults(result.sources);
                    updateIntelFeed(result.sources);
                }
            }

            addChatMessage({ author: "ANANTA AI", content: aiContent || "<i>Scan complété</i>" });
            notifyScanComplete(lastTarget);
            resolve();
        };

        const handleError = (error) => {
            progressWrapper.remove();
            reject(error);
        };

        const updateProgress = (data) => {
            if (progressBar && data.progress !== undefined) {
                progressBar.style.width = `${data.progress}%`;
            }
            if (progressText) {
                progressText.textContent = `${data.status || 'PROCESSING'} - ${data.progress || 0}%`;
            }
        };

        // Try WebSocket first
        if (useWebSocket) {
            if (connectionType) connectionType.textContent = '⚡ WebSocket';

            wsConnection = createJobWebSocket(
                jobId,
                // onUpdate
                (data) => {
                    updateProgress(data);
                },
                // onComplete
                async (data) => {
                    try {
                        // Some backends may send a COMPLETED status without embedding the full result in the WS payload.
                        // In that case, do a final HTTP fetch to get the stored result from /jobs/{id}.
                        if (data.status === 'COMPLETED') {
                            if (data.result) {
                                handleResult(data.result);
                                return;
                            }
                            const finalStatus = await pollJobStatus(jobId);
                            if (finalStatus.status === 'COMPLETED' && finalStatus.result) {
                                handleResult(finalStatus.result);
                                return;
                            }
                            handleError(new Error('Scan terminé mais résultat introuvable (job.result vide).'));
                            return;
                        }

                        if (data.status === 'FAILED') {
                            // Same idea: fetch to retrieve any persisted error_message
                            const finalStatus = await pollJobStatus(jobId).catch(() => null);
                            handleError(new Error((finalStatus && finalStatus.error) || data.error || 'Le scan a échoué'));
                            return;
                        }
                    } catch (e) {
                        handleError(e);
                    }
                },
                // onError - fallback to polling
                (error) => {
                    console.warn('[WebSocket] Error, falling back to polling:', error);
                    pollingFallback = true;
                    if (connectionType) connectionType.textContent = '📡 Polling';
                    startPolling();
                }
            );

            // Set a timeout to switch to polling if WebSocket doesn't work
            setTimeout(() => {
                if (wsConnection && wsConnection.ws.readyState !== WebSocket.OPEN && !pollingFallback) {
                    console.warn('[WebSocket] Connection timeout, falling back to polling');
                    wsConnection.close();
                    pollingFallback = true;
                    if (connectionType) connectionType.textContent = '📡 Polling';
                    startPolling();
                }
            }, 5000);
        } else {
            if (connectionType) connectionType.textContent = '📡 Polling';
            startPolling();
        }

        // Polling fallback function
        async function startPolling() {
            const maxAttempts = 180;
            let attempts = 0;

            while (attempts < maxAttempts) {
                await new Promise(r => setTimeout(r, 2000));

                try {
                    const jobStatus = await pollJobStatus(jobId);
                    updateProgress(jobStatus);

                    if (jobStatus.status === "COMPLETED") {
                        handleResult(jobStatus.result);
                        return;
                    } else if (jobStatus.status === "FAILED") {
                        handleError(new Error(jobStatus.error || "Le scan a échoué"));
                        return;
                    }

                    attempts++;
                } catch (e) {
                    handleError(new Error(`Erreur de polling: ${e.message}`));
                    return;
                }
            }

            handleError(new Error("Timeout : le scan a pris trop de temps"));
        }
    });
}

// --- BOUTONS SIDEBAR ---

async function handleExportPDF() {
    if (!lastTarget) {
        addChatMessage({ author: "SYSTEM", content: `⚠️ ${t('no_recent_analysis')}` });
        return;
    }

    const format = appSettings.exportFormat || 'pdf';
    const formatNames = {
        'pdf': 'PDF',
        'xlsx': 'Excel',
        'json': 'JSON',
        'csv': 'CSV',
        'xml': 'XML',
        'md': 'Markdown'
    };

    const endpoints = {
        'pdf': `/osint/generate_pdf/?query=${encodeURIComponent(lastTarget)}`,
        'xlsx': `/osint/export/xlsx?query=${encodeURIComponent(lastTarget)}`,
        'json': `/osint/export/json?query=${encodeURIComponent(lastTarget)}`,
        'csv': `/osint/export/csv?query=${encodeURIComponent(lastTarget)}`,
        'xml': `/osint/export/xml?query=${encodeURIComponent(lastTarget)}`,
        'md': `/osint/export/markdown?query=${encodeURIComponent(lastTarget)}`
    };

    const formatName = formatNames[format] || 'PDF';
    const endpoint = endpoints[format] || endpoints['pdf'];

    addChatMessage({
        author: "SYSTEM",
        content: `<i class="fas fa-file-export mr-2"></i>${t('generating_report')} ${formatName} : ${escapeHtml(lastTarget)}...`
    });

    window.open(`${API_BASE}${endpoint}`, '_blank');
}

// --- INIT ---
document.addEventListener("DOMContentLoaded", () => {
    console.log('[Init] DOM Content Loaded');
    console.log('[Init] API_BASE:', API_BASE);
    console.log('[Init] Language:', appSettings.language);

    // Apply translations immediately on page load
    applyTranslations();

    // Check if all required elements exist
    const requiredElements = {
        'led-api': document.getElementById("led-api"),
        'cpu-percent': document.getElementById("cpu-percent"),
        'cpu-bar': document.getElementById("cpu-bar"),
        'gpu-percent': document.getElementById("gpu-percent"),
        'gpu-bar': document.getElementById("gpu-bar"),
        'db-latency': document.getElementById("db-latency"),
        'worker-status': document.getElementById("worker-status")
    };

    for (const [name, element] of Object.entries(requiredElements)) {
        if (!element) {
            console.error(`[Init] Missing element: ${name}`);
        } else {
            console.log(`[Init] Found element: ${name}`);
        }
    }

    console.log('[Init] Starting system pulse updates');
    updateSystemPulse();
    setInterval(updateSystemPulse, 2000);

    // Send
    document.getElementById("send-btn")?.addEventListener("click", handleExecution);
    document.getElementById("query-input")?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") handleExecution();
    });

    // Sidebar Buttons
    document.getElementById("btn-export-pdf")?.addEventListener("click", handleExportPDF);

    // Settings Button
    document.getElementById("btn-settings")?.addEventListener("click", openSettings);

    // Settings Event Listeners
    initSettingsListeners();

    // Apply saved settings on load
    applySettings();
    updateExportButton();

    console.log('[Init] All event listeners attached');
});

// ===== SETTINGS FUNCTIONS =====

function openSettings() {
    const modal = document.getElementById("settings-modal");
    if (modal) {
        modal.classList.remove("hidden");
        populateSettingsForm();
        updateCacheUsage();
    }
}

function closeSettings() {
    const modal = document.getElementById("settings-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
}

function populateSettingsForm() {
    // API URL
    const apiUrlInput = document.getElementById("setting-api-url");
    if (apiUrlInput) apiUrlInput.value = appSettings.apiUrl || '';

    // LLM Temperature
    const tempSlider = document.getElementById("setting-llm-temperature");
    const tempValue = document.getElementById("setting-llm-temperature-value");
    if (tempSlider) {
        tempSlider.value = appSettings.llmTemperature * 100;
        if (tempValue) tempValue.textContent = appSettings.llmTemperature.toFixed(1);
    }

    // LLM Timeout
    const timeoutInput = document.getElementById("setting-llm-timeout");
    if (timeoutInput) timeoutInput.value = appSettings.llmTimeout;

    // LLM Hard Limit
    const hardLimitSlider = document.getElementById("setting-llm-hard-limit");
    const hardLimitValue = document.getElementById("setting-llm-hard-limit-value");
    if (hardLimitSlider) {
        const v = Math.max(200, Math.min(5000, Number(appSettings.llmHardLimit || 4000)));
        hardLimitSlider.value = v;
        if (hardLimitValue) hardLimitValue.textContent = String(v);
    }

    // Cache TTL
    const cacheTtlInput = document.getElementById("setting-cache-ttl");
    if (cacheTtlInput) cacheTtlInput.value = appSettings.cacheTtl;

    // Export Format
    const exportRadios = document.querySelectorAll('input[name="export-format"]');
    exportRadios.forEach(radio => {
        radio.checked = radio.value === appSettings.exportFormat;
    });

    // Scan Mode
    const scanModeRadios = document.querySelectorAll('input[name="scan-mode"]');
    scanModeRadios.forEach(radio => {
        radio.checked = radio.value === (appSettings.scanMode || 'standard');
    });

    // Report Template
    const reportTemplateRadios = document.querySelectorAll('input[name="report-template"]');
    reportTemplateRadios.forEach(radio => {
        radio.checked = radio.value === (appSettings.reportTemplate || 'detailed');
    });

    // Compact Mode
    const compactCheckbox = document.getElementById("setting-compact-mode");
    if (compactCheckbox) compactCheckbox.checked = appSettings.compactMode;

    // Dark Mode
    const darkModeCheckbox = document.getElementById("setting-dark-mode");
    if (darkModeCheckbox) darkModeCheckbox.checked = appSettings.darkMode !== false;

    // Font Size
    const fontSizeSelect = document.getElementById("setting-font-size");
    if (fontSizeSelect) fontSizeSelect.value = appSettings.fontSize;

    // Accent Color
    const colorSwatches = document.querySelectorAll(".color-swatch");
    colorSwatches.forEach(swatch => {
        swatch.classList.toggle("active", swatch.dataset.color === appSettings.accentColor);
    });

    // Language
    const languageRadios = document.querySelectorAll('input[name="language"]');
    languageRadios.forEach(radio => {
        radio.checked = radio.value === appSettings.language;
    });

    // Show detected language hint
    const langHint = document.getElementById("auto-detect-lang-hint");
    if (langHint) {
        const detectedLang = detectBrowserLanguage();
        const langNames = { fr: 'Français', en: 'English', es: 'Español', de: 'Deutsch' };
        langHint.textContent = `Langue détectée du navigateur: ${langNames[detectedLang] || detectedLang}`;
    }

    // Max Reports
    const maxReportsInput = document.getElementById("setting-max-reports");
    if (maxReportsInput) maxReportsInput.value = appSettings.maxReports;

    // Auto Delete Days
    const autoDeleteInput = document.getElementById("setting-auto-delete");
    if (autoDeleteInput) autoDeleteInput.value = appSettings.autoDeleteDays;

    // Notifications
    const notifCheckbox = document.getElementById("setting-notifications");
    if (notifCheckbox) notifCheckbox.checked = appSettings.notifications;

    // Favorites
    renderFavorites();
}

function initSettingsListeners() {
    // Temperature slider
    const tempSlider = document.getElementById("setting-llm-temperature");
    const tempValue = document.getElementById("setting-llm-temperature-value");
    if (tempSlider && tempValue) {
        tempSlider.addEventListener("input", () => {
            tempValue.textContent = (tempSlider.value / 100).toFixed(1);
        });
    }

    // Hard limit slider
    const hardLimitSlider = document.getElementById("setting-llm-hard-limit");
    const hardLimitValue = document.getElementById("setting-llm-hard-limit-value");
    if (hardLimitSlider && hardLimitValue) {
        hardLimitSlider.addEventListener("input", () => {
            hardLimitValue.textContent = String(hardLimitSlider.value);
        });
    }

    // Color swatches
    document.querySelectorAll(".color-swatch").forEach(swatch => {
        swatch.addEventListener("click", () => {
            document.querySelectorAll(".color-swatch").forEach(s => s.classList.remove("active"));
            swatch.classList.add("active");
        });
    });

    // Clear cache button
    document.getElementById("btn-clear-cache")?.addEventListener("click", clearCache);

    // Test notification button
    document.getElementById("btn-test-notification")?.addEventListener("click", testNotification);

    // Add favorite button
    document.getElementById("btn-add-favorite")?.addEventListener("click", addFavorite);

    // Add favorite on Enter key
    document.getElementById("new-favorite-input")?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") addFavorite();
    });

    // Global keyboard shortcuts
    document.addEventListener("keydown", (e) => {
        // Escape - Close modal
        if (e.key === "Escape") {
            closeSettings();
            return;
        }

        // Don't trigger shortcuts when typing in inputs
        const isTyping = ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName);
        const queryInput = document.getElementById("query-input");

        // Ctrl+Enter or Cmd+Enter - Execute scan (works even in input)
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            handleExecution();
            return;
        }

        // Skip remaining shortcuts if typing
        if (isTyping) return;

        // Ctrl+K or Cmd+K - Focus search input
        if ((e.ctrlKey || e.metaKey) && e.key === "k") {
            e.preventDefault();
            if (queryInput) {
                queryInput.focus();
                queryInput.select();
            }
            return;
        }

        // Ctrl+E or Cmd+E - Export report
        if ((e.ctrlKey || e.metaKey) && e.key === "e") {
            e.preventDefault();
            handleExportPDF();
            return;
        }

        // Ctrl+, or Cmd+, - Open settings
        if ((e.ctrlKey || e.metaKey) && e.key === ",") {
            e.preventDefault();
            openSettings();
            return;
        }

        // Ctrl+D or Cmd+D - Go to database
        if ((e.ctrlKey || e.metaKey) && e.key === "d") {
            e.preventDefault();
            window.location.href = "/web/html/database.html";
            return;
        }

        // ? - Show keyboard shortcuts help
        if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
            e.preventDefault();
            showKeyboardShortcutsHelp();
            return;
        }
    });

    // Scan Mode change - show/hide Layer 3 tools section
    const scanModeRadios = document.querySelectorAll('input[name="scan-mode"]');
    const layer3Section = document.getElementById('layer3-tools-section');

    function updateLayer3Visibility() {
        const selectedMode = document.querySelector('input[name="scan-mode"]:checked')?.value;
        if (layer3Section) {
            layer3Section.style.display = selectedMode === 'critical' ? 'block' : 'none';
        }
    }

    scanModeRadios.forEach(radio => {
        radio.addEventListener('change', updateLayer3Visibility);
    });

    // Initial state
    updateLayer3Visibility();
}

function showKeyboardShortcutsHelp() {
    // Create modal if it doesn't exist
    let modal = document.getElementById("keyboard-shortcuts-modal");
    if (!modal) {
        modal = document.createElement("div");
        modal.id = "keyboard-shortcuts-modal";
        modal.className = "fixed inset-0 bg-black/80 z-50 flex items-center justify-center";
        modal.innerHTML = `
            <div class="bg-slate-900 border border-slate-700 rounded-lg p-6 max-w-md w-full mx-4">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-lg font-semibold text-white">
                        <i class="fas fa-keyboard mr-2"></i>${t('keyboard_shortcuts') || 'Raccourcis clavier'}
                    </h3>
                    <button onclick="document.getElementById('keyboard-shortcuts-modal').remove()"
                            class="text-slate-400 hover:text-white">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="space-y-3 text-sm">
                    <div class="flex justify-between items-center py-2 border-b border-slate-700">
                        <span class="text-slate-300">${t('execute_scan') || 'Exécuter le scan'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">Ctrl+Enter</kbd>
                    </div>
                    <div class="flex justify-between items-center py-2 border-b border-slate-700">
                        <span class="text-slate-300">${t('focus_search') || 'Focus recherche'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">Ctrl+K</kbd>
                    </div>
                    <div class="flex justify-between items-center py-2 border-b border-slate-700">
                        <span class="text-slate-300">${t('export_report') || 'Exporter le rapport'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">Ctrl+E</kbd>
                    </div>
                    <div class="flex justify-between items-center py-2 border-b border-slate-700">
                        <span class="text-slate-300">${t('open_settings') || 'Paramètres'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">Ctrl+,</kbd>
                    </div>
                    <div class="flex justify-between items-center py-2 border-b border-slate-700">
                        <span class="text-slate-300">${t('go_to_database') || 'Aller à Database'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">Ctrl+D</kbd>
                    </div>
                    <div class="flex justify-between items-center py-2 border-b border-slate-700">
                        <span class="text-slate-300">${t('close_modal') || 'Fermer la modale'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">Escape</kbd>
                    </div>
                    <div class="flex justify-between items-center py-2">
                        <span class="text-slate-300">${t('show_shortcuts') || 'Afficher cette aide'}</span>
                        <kbd class="px-2 py-1 bg-slate-800 rounded text-cyan-400 font-mono">?</kbd>
                    </div>
                </div>
                <p class="mt-4 text-xs text-slate-500 text-center">
                    ${t('press_escape') || 'Appuyez sur Escape pour fermer'}
                </p>
            </div>
        `;
        document.body.appendChild(modal);

        // Close on click outside
        modal.addEventListener("click", (e) => {
            if (e.target === modal) modal.remove();
        });

        // Close on Escape
        const closeHandler = (e) => {
            if (e.key === "Escape") {
                modal.remove();
                document.removeEventListener("keydown", closeHandler);
            }
        };
        document.addEventListener("keydown", closeHandler);
    }
}

function saveSettings() {
    // Gather all values from form
    const apiUrlInput = document.getElementById("setting-api-url");
    const tempSlider = document.getElementById("setting-llm-temperature");
    const timeoutInput = document.getElementById("setting-llm-timeout");
    const hardLimitSlider = document.getElementById("setting-llm-hard-limit");
    const cacheTtlInput = document.getElementById("setting-cache-ttl");
    const compactCheckbox = document.getElementById("setting-compact-mode");
    const fontSizeSelect = document.getElementById("setting-font-size");
    const maxReportsInput = document.getElementById("setting-max-reports");
    const autoDeleteInput = document.getElementById("setting-auto-delete");
    const notifCheckbox = document.getElementById("setting-notifications");

    // Export format
    const exportFormat = document.querySelector('input[name="export-format"]:checked')?.value || 'pdf';

    // Scan mode
    const scanMode = document.querySelector('input[name="scan-mode"]:checked')?.value || 'standard';

    // Report template
    const reportTemplate = document.querySelector('input[name="report-template"]:checked')?.value || 'detailed';

    // Accent color
    const activeColor = document.querySelector(".color-swatch.active");
    const accentColor = activeColor?.dataset.color || 'cyan';

    // Language
    const language = document.querySelector('input[name="language"]:checked')?.value || 'fr';

    // Dark Mode
    const darkModeCheckbox = document.getElementById("setting-dark-mode");
    const darkMode = darkModeCheckbox?.checked !== false;  // Default to true

    appSettings = {
        apiUrl: apiUrlInput?.value || '',
        llmTemperature: tempSlider ? tempSlider.value / 100 : 0.7,
        llmTimeout: parseInt(timeoutInput?.value) || 180,
        llmHardLimit: Math.max(200, Math.min(5000, parseInt(hardLimitSlider?.value) || 4000)),
        cacheTtl: parseInt(cacheTtlInput?.value) || 10,
        exportFormat,
        scanMode,
        reportTemplate,
        compactMode: compactCheckbox?.checked || false,
        fontSize: fontSizeSelect?.value || 'medium',
        accentColor,
        darkMode,
        language,
        maxReports: parseInt(maxReportsInput?.value) || 100,
        autoDeleteDays: parseInt(autoDeleteInput?.value) || 30,
        notifications: notifCheckbox?.checked || false,
        favorites: appSettings.favorites || []
    };

    // Save to localStorage
    localStorage.setItem('ananta-settings', JSON.stringify(appSettings));

    // Apply settings immediately
    applySettings();

    // Check if language or API URL changed
    const oldLanguage = localStorage.getItem('ananta-settings')
        ? JSON.parse(localStorage.getItem('ananta-settings')).language
        : 'fr';
    const languageChanged = oldLanguage !== language;
    const apiUrlChanged = apiUrlInput?.value !== '' && apiUrlInput?.value !== API_BASE;

    // Show confirmation
    addChatMessage({
        author: "SYSTEM",
        content: `<span class="text-emerald-400"><i class="fas fa-check-circle mr-2"></i>${t('settings_saved')}</span>`
    });

    closeSettings();

    // Reload page only if API URL changed (language is now applied dynamically)
    if (apiUrlChanged) {
        setTimeout(() => {
            const message = language === 'fr'
                ? 'L\'URL de l\'API a changé. Recharger la page pour appliquer ?'
                : 'API URL changed. Reload the page to apply?';

            if (confirm(message)) {
                window.location.reload();
            }
        }, 500);
    }

    // Translations are now applied dynamically without reload
    if (languageChanged) {
        console.log('[Settings] Language changed to:', language);
        // applyTranslations is called in applySettings()
    }
}

function resetSettings() {
    if (confirm(t('confirm_reset_settings'))) {
        appSettings = { ...DEFAULT_SETTINGS };
        localStorage.removeItem('ananta-settings');
        populateSettingsForm();
        applySettings();
        addChatMessage({
            author: "SYSTEM",
            content: '<span class="text-amber-400"><i class="fas fa-undo mr-2"></i>Paramètres réinitialisés.</span>'
        });
    }
}

function applySettings() {
    // Apply accent color
    document.documentElement.setAttribute('data-accent', appSettings.accentColor);

    // Apply dark/light mode
    const darkMode = appSettings.darkMode !== false;  // Default to dark
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    document.body.classList.toggle('dark-mode', darkMode);
    document.body.classList.toggle('light-mode', !darkMode);

    // Apply font size
    document.body.classList.remove('font-small', 'font-medium', 'font-large');
    document.body.classList.add(`font-${appSettings.fontSize}`);

    // Apply compact mode
    document.body.classList.toggle('compact-mode', appSettings.compactMode);

    // Request notification permission if enabled
    if (appSettings.notifications && 'Notification' in window) {
        Notification.requestPermission();
    }

    // Apply translations based on selected language
    applyTranslations();

    // Update export button text based on format
    updateExportButton();
}

function updateExportButton() {
    const exportBtn = document.getElementById("btn-export-pdf");
    if (!exportBtn) return;

    const format = appSettings.exportFormat || 'pdf';
    const icons = {
        'pdf': 'fa-file-pdf',
        'xlsx': 'fa-file-excel',
        'json': 'fa-file-code',
        'csv': 'fa-file-csv',
        'xml': 'fa-file-code',
        'md': 'fa-file-alt'
    };

    const labels = {
        'pdf': t('export_pdf'),
        'xlsx': t('export_excel'),
        'json': t('export_json'),
        'csv': t('export_csv'),
        'xml': t('export_xml'),
        'md': t('export_markdown')
    };

    const icon = icons[format] || icons['pdf'];
    const label = labels[format] || labels['pdf'];

    exportBtn.innerHTML = `<i class="fas ${icon} mr-2"></i> ${label}`;
}

function renderFavorites() {
    const container = document.getElementById("favorites-list");
    if (!container) return;

    if (!appSettings.favorites || appSettings.favorites.length === 0) {
        container.innerHTML = `<p class="text-slate-600 text-xs italic">${t('no_favorites')}</p>`;
        return;
    }

    container.innerHTML = appSettings.favorites.map((fav, index) => `
        <div class="favorite-tag" onclick="useFavorite('${escapeHtml(fav)}')">
            <i class="fas fa-crosshairs"></i>
            <span>${escapeHtml(fav)}</span>
            <i class="fas fa-times remove-favorite" onclick="event.stopPropagation(); removeFavorite(${index})"></i>
        </div>
    `).join('');
}

function addFavorite() {
    const input = document.getElementById("new-favorite-input");
    const value = input?.value?.trim();

    if (!value) return;

    if (!appSettings.favorites.includes(value)) {
        appSettings.favorites.push(value);
        localStorage.setItem('ananta-settings', JSON.stringify(appSettings));
        renderFavorites();
    }

    input.value = '';
}

function removeFavorite(index) {
    appSettings.favorites.splice(index, 1);
    localStorage.setItem('ananta-settings', JSON.stringify(appSettings));
    renderFavorites();
}

function useFavorite(target) {
    closeSettings();
    const input = document.getElementById("query-input");
    if (input) {
        input.value = `analyze ${target}`;
        input.focus();
    }
}

async function clearCache() {
    if (!confirm(t('confirm_clear_cache'))) return;

    try {
        const res = await fetch(`${API_BASE}/cache/clear`, { method: 'POST' });
        if (res.ok) {
            addChatMessage({
                author: "SYSTEM",
                content: `<span class="text-emerald-400"><i class="fas fa-trash mr-2"></i>${t('cache_cleared_success')}</span>`
            });
            updateCacheUsage();
        } else {
            throw new Error('Erreur serveur');
        }
    } catch (e) {
        addChatMessage({
            author: "SYSTEM",
            content: `<span class="text-rose-400"><i class="fas fa-exclamation-circle mr-2"></i>Erreur: ${escapeHtml(e.message)}</span>`
        });
    }
}

async function updateCacheUsage() {
    const bar = document.getElementById("cache-usage-bar");
    const text = document.getElementById("cache-usage-text");

    console.log('[Cache] Updating cache usage...');

    if (!bar || !text) {
        console.error('[Cache] Missing DOM elements:', { bar: !!bar, text: !!text });
        return;
    }

    try {
        console.log('[Cache] Fetching from:', `${API_BASE}/cache/stats`);
        const res = await fetch(`${API_BASE}/cache/stats`);

        if (!res.ok) {
            console.error('[Cache] Fetch failed with status:', res.status);
            throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();
        console.log('[Cache] Received data:', data);

        const usedMB = data.used_mb || 0;
        const maxMB = data.max_mb || 100;
        const percent = Math.min(100, (usedMB / maxMB) * 100);

        bar.style.width = `${percent}%`;
        text.textContent = `${usedMB.toFixed(1)} MB / ${maxMB} MB`;

        console.log('[Cache] Updated successfully:', { usedMB, maxMB, percent });

    } catch (e) {
        console.error('[Cache] Error:', e.message, e);
        text.textContent = 'Erreur de chargement';
        bar.style.width = '0%';
    }
}

function testNotification() {
    if (!('Notification' in window)) {
        alert('Les notifications ne sont pas supportées par ce navigateur.');
        return;
    }

    if (Notification.permission === 'granted') {
        new Notification('ANANTA', {
            body: 'Les notifications fonctionnent correctement !',
            icon: '../icons/icon-192.png'
        });
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                new Notification('ANANTA', {
                    body: 'Les notifications sont maintenant activées !',
                    icon: '../icons/icon-192.png'
                });
            }
        });
    } else {
        alert('Les notifications sont bloquées. Veuillez les autoriser dans les paramètres du navigateur.');
    }
}

// Send notification when scan completes
function notifyScanComplete(target) {
    if (!appSettings.notifications) return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;

    new Notification('ANANTA - Scan terminé', {
        body: `L'analyse de ${target} est terminée.`,
        icon: '../icons/icon-192.png'
    });
}
