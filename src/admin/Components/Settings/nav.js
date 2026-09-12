/*
 * The settings sidebar.
 *
 * One entry per destination. A group with `children` has more than one screen under it
 * and lists them; everything else is a single route.
 *
 * General Settings used to list its seven blocks here as well, and they were only scroll
 * anchors - the same seven headings the page already shows, read twice. What it bought
 * was a rail of eighteen entries for eleven places to go. The blocks are still linkable
 * (the dashboard checklist points at one with `?section=`), they are just not a menu.
 *
 * Icons are inline SVG rather than an icon font or a component per glyph: there are a
 * dozen of them, they never change, and this keeps the sidebar a data structure.
 */

const icon = (paths) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" width="18" height="18">${paths}</svg>`;

export const chevronIcon = icon('<path d="M9 18l6-6-6-6"/>');

const icons = {
    shield: icon('<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/>'),
    users: icon('<circle cx="9" cy="8" r="3.2"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><path d="M16 5.2a3.2 3.2 0 0 1 0 5.6M17.5 19a5.5 5.5 0 0 0-2-4.3"/>'),
    login: icon('<path d="M14 3h5a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-5"/><path d="M10 17l5-5-5-5"/><path d="M15 12H3"/>'),
    form: icon('<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h4"/>'),
    redirect: icon('<path d="M4 7h11a5 5 0 0 1 0 10H9"/><path d="M12 14l-3 3 3 3"/>'),
    mail: icon('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>'),
    server: icon('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'),
    shieldCheck: icon('<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>')
};

/**
 * @param vm the component, for $t
 */
export const settingsNav = (vm) => [
    {
        route: 'settings_general',
        title: vm.$t('General Settings'),
        icon: icons.shield
    },
    {
        route: 'settings_two_fa_enrollment',
        title: vm.$t('2FA Enrollment'),
        icon: icons.users
    },
    {
        route: 'settings_ip_rules',
        title: vm.$t('IP Access Rules'),
        icon: icons.shieldCheck
    },
    {
        route: 'settings_social_login',
        title: vm.$t('Social Login'),
        icon: icons.login
    },
    {
        route: 'settings_auth_forms',
        title: vm.$t('Login & Signup Forms'),
        icon: icons.form,
        children: [
            {route: 'settings_auth_forms', title: vm.$t('Forms')},
            {route: 'settings_auth_customizer', title: vm.$t('Login Page Design')}
        ]
    },
    {
        route: 'settings_redirects',
        title: vm.$t('Login Redirects'),
        icon: icons.redirect
    },
    {
        route: 'settings_emails',
        title: vm.$t('System Emails'),
        icon: icons.mail,
        children: [
            {route: 'settings_emails', title: vm.$t('All Emails')},
            {route: 'settings_email_template', title: vm.$t('Template Design')}
        ]
    },
    {
        route: 'settings_server_mode',
        title: vm.$t('Remote Auth'),
        icon: icons.server,
        when: (appVars) => !!appVars.has_server_mode
    }
];
