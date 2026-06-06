// EasyWAF — sidebar & UI initialisation

// ── Theme handling ────────────────────────────────────────
// Preference is one of: 'auto' (follow the OS setting), 'light', 'dark'.
// The resolved theme (always 'light' or 'dark') is applied as the
// html[data-theme] attribute by an inline <head> script to avoid a flash.
// This file wires up the cycle button, persists the preference, updates the
// icon, and live-updates when the OS theme changes while in 'auto' mode.
(function () {
    var KEY = 'easywaf-theme';
    var mql = window.matchMedia('(prefers-color-scheme: dark)');

    function getPref() {
        try { return localStorage.getItem(KEY) || 'auto'; } catch (e) { return 'auto'; }
    }
    // Resolve a preference to an actual theme.
    function resolve(pref) {
        if (pref === 'light' || pref === 'dark') return pref;
        return mql.matches ? 'dark' : 'light'; // 'auto'
    }
    function apply(pref) {
        document.documentElement.setAttribute('data-theme', resolve(pref));
        try { localStorage.setItem(KEY, pref); } catch (e) {}
        updateIcon(pref);
    }
    function updateIcon(pref) {
        var icon = document.getElementById('themeToggleIcon');
        var btn  = document.getElementById('themeToggle');
        if (!icon) return;
        if (pref === 'auto') {
            icon.className = 'fa fa-adjust';
            if (btn) btn.title = 'Theme: Auto (follows your system) — click for Light';
        } else if (pref === 'light') {
            icon.className = 'fa fa-sun-o';
            if (btn) btn.title = 'Theme: Light — click for Dark';
        } else {
            icon.className = 'fa fa-moon-o';
            if (btn) btn.title = 'Theme: Dark — click for Auto';
        }
    }

    // Cycle: auto → light → dark → auto.
    var NEXT = { auto: 'light', light: 'dark', dark: 'auto' };
    window.cycleTheme = function () {
        apply(NEXT[getPref()] || 'auto');
    };
    // Back-compat alias for any cached markup calling toggleTheme().
    window.toggleTheme = window.cycleTheme;

    // When the OS theme changes and we're in 'auto', re-resolve live.
    var onOsChange = function () {
        if (getPref() === 'auto') {
            document.documentElement.setAttribute('data-theme', resolve('auto'));
        }
    };
    if (mql.addEventListener) { mql.addEventListener('change', onOsChange); }
    else if (mql.addListener) { mql.addListener(onOsChange); } // older browsers

    document.addEventListener('DOMContentLoaded', function () {
        updateIcon(getPref());
    });
})();

// ── Sidebar & alerts ──────────────────────────────────────
$(document).ready(function () {
    // MetisMenu sidebar
    if ($.fn.metisMenu) {
        $('#side-menu').metisMenu();
    }

    // Auto-dismiss alerts after 5 seconds
    window.setTimeout(function () {
        $('.alert-dismissible').fadeTo(500, 0).slideUp(500);
    }, 5000);
});
