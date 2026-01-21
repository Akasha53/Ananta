/**
 * Theme Management - Shared across all pages
 * Loads and applies theme settings from localStorage
 */

const DEFAULT_THEME_SETTINGS = {
    accentColor: 'cyan',
    fontSize: 'medium',
    compactMode: false,
    language: 'fr',
    darkMode: true  // Dark mode by default (Ananta's signature look)
};

/**
 * Load theme settings from localStorage
 */
function loadThemeSettings() {
    try {
        const stored = localStorage.getItem('ananta-settings');
        if (stored) {
            const settings = JSON.parse(stored);
            return {
                accentColor: settings.accentColor || DEFAULT_THEME_SETTINGS.accentColor,
                fontSize: settings.fontSize || DEFAULT_THEME_SETTINGS.fontSize,
                compactMode: settings.compactMode || DEFAULT_THEME_SETTINGS.compactMode,
                language: settings.language || DEFAULT_THEME_SETTINGS.language,
                darkMode: settings.darkMode !== undefined ? settings.darkMode : DEFAULT_THEME_SETTINGS.darkMode
            };
        }
    } catch (e) {
        console.error('[Theme] Error loading settings:', e);
    }
    return DEFAULT_THEME_SETTINGS;
}

/**
 * Apply theme to current page
 */
function applyTheme() {
    const settings = loadThemeSettings();

    // Apply accent color
    document.documentElement.setAttribute('data-accent', settings.accentColor);

    // Apply dark/light mode
    document.documentElement.setAttribute('data-theme', settings.darkMode ? 'dark' : 'light');
    document.body.classList.toggle('dark-mode', settings.darkMode);
    document.body.classList.toggle('light-mode', !settings.darkMode);

    // Apply font size
    document.body.classList.remove('font-small', 'font-medium', 'font-large');
    document.body.classList.add(`font-${settings.fontSize}`);

    // Apply compact mode
    document.body.classList.toggle('compact-mode', settings.compactMode);

    console.log('[Theme] Applied:', settings);
}

/**
 * Initialize theme on page load
 */
(function initTheme() {
    // Apply theme immediately
    applyTheme();

    // Re-apply on storage change (for sync across tabs)
    window.addEventListener('storage', function(e) {
        if (e.key === 'ananta-settings') {
            console.log('[Theme] Settings changed in another tab, reloading...');
            applyTheme();
        }
    });
})();
