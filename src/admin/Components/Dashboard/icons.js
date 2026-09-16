/*
 * The dashboard's glyphs.
 *
 * Inline SVG strings rather than a component each or an icon font, for the same reason the
 * settings sidebar does it (see Settings/nav.js): there are a handful, they never change,
 * and this keeps the panels that use them declarative.
 */

const icon = (paths, size = 20) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" width="${size}" height="${size}">${paths}</svg>`;

export default {
    // Tiles
    success: icon('<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>'),
    failed: icon('<path d="M12 4.5L3 19.5h18L12 4.5z"/><path d="M12 10v4"/><path d="M12 17h.01"/>'),
    blocked: icon('<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 15l6-6"/>'),
    twoFa: icon('<circle cx="9" cy="12" r="3.5"/><path d="M12.5 12H21"/><path d="M17 12v3"/><path d="M20 12v2"/>'),

    /*
     * The two device factors, drawn from the same paths as the profile card's own rows
     * (TwoFaProfileHandler::icon) - a passkey should not be one glyph on the screen that
     * lists who holds one and a different glyph on the screen where they hold it.
     */
    authApp: icon('<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>', 15),
    passkey: icon('<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M18 12v3M15 12v2"/>', 15),

    // Panels
    chart: icon('<path d="M4 19V5"/><path d="M4 19h16"/><rect x="7.5" y="11" width="3" height="5"/><rect x="13.5" y="8" width="3" height="8"/>', 18),
    threat: icon('<path d="M12 4.5L3 19.5h18L12 4.5z"/><path d="M12 10v4"/><path d="M12 17h.01"/>', 18),
    check: icon('<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>', 18),
    globe: icon('<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.4 2.5 15.6 0 18-2.5-2.4-2.5-15.6 0-18z"/>', 18),
    key: icon('<circle cx="8" cy="14" r="4"/><path d="M11 11l8-8"/><path d="M16 4l3 3"/><path d="M14 6l3 3"/>', 18),
    empty: icon('<rect x="3.5" y="5" width="17" height="14" rx="2"/><path d="M3.5 11h4l1.5 2.5h6L16.5 11h4"/>', 28),

    // List screens
    search: icon('<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/>', 17),
    refresh: icon('<path d="M20 12a8 8 0 1 1-2.4-5.7"/><path d="M20 4v4h-4"/>', 17),

    // Marks
    tick: icon('<path d="M5 12.5l4.5 4.5L19 7"/>', 12),
    tickSmall: icon('<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>', 16)
};
