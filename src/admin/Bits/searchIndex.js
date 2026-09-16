/*
 * Everywhere in the app you can go, as one flat list for the search box.
 *
 * Hand-written rather than derived from the router, because a route is a path and this is
 * a place: the settings screens are all one route with a `?section=`, "Been Hacked?" is
 * called `security_recovery`, and half the router's entries (an email being edited, the
 * scanner's registration detour) are not somewhere anyone searches for. Deriving it would
 * mean annotating every route with everything below anyway.
 *
 * It stops at the screen. Individual switches are labels inside Vue templates, and a list
 * of them here would be a copy that drifts the first time one is reworded - so instead
 * each entry carries `keywords`: the words somebody types when they are looking for a
 * setting on that screen but do not know what the screen is called. Typing "xmlrpc" or
 * "brute force" lands on the section that holds it; the screen itself does the rest.
 */

/**
 * @param vm the component, for $t and appVars
 * @returns {Array} every destination, in the order the groups are shown
 */
export const searchIndex = (vm) => {
    const entries = [
        /* ------------------------------------------------------------- places */

        {
            group: 'Pages',
            title: vm.$t('Dashboard'),
            subtitle: vm.$t('Login activity and security status'),
            to: {name: 'dashboard'},
            keywords: ['home', 'overview', 'summary', 'stats', 'checklist']
        },
        {
            group: 'Pages',
            title: vm.$t('Activity Log'),
            subtitle: vm.$t('Every sign-in, failure and block'),
            to: {name: 'logs'},
            keywords: ['logs', 'audit', 'history', 'events', 'who logged in']
        },
        {
            group: 'Pages',
            title: vm.$t('Security Findings'),
            subtitle: vm.$t('What needs doing on this site'),
            to: {name: 'security_findings'},
            keywords: ['checks', 'hardening', 'recommendations', 'issues', 'scan results']
        },
        {
            group: 'Pages',
            title: vm.$t('Monitoring'),
            subtitle: vm.$t('File integrity scans and alerts'),
            to: {name: 'security_scans'},
            keywords: ['malware', 'file scan', 'integrity', 'checksums', 'quarantine', 'alerts']
        },
        {
            group: 'Pages',
            title: vm.$t('Been Hacked?'),
            subtitle: vm.$t('What to do after a break-in'),
            to: {name: 'security_recovery'},
            keywords: ['recovery', 'compromised', 'cleanup', 'lock everyone out', 'emergency']
        },

        /* ------------------------------------------------------ settings screens */

        {
            group: 'Settings',
            title: vm.$t('General Settings'),
            to: {name: 'settings_general'},
            keywords: ['options', 'configuration']
        },
        {
            group: 'Settings',
            title: vm.$t('2FA Enrollment'),
            subtitle: vm.$t('Who has set up an authenticator app'),
            to: {name: 'settings_two_fa_enrollment'},
            keywords: ['two factor', 'enrolled users', 'reset 2fa', 'authenticator', 'passkeys']
        },
        {
            group: 'Settings',
            title: vm.$t('IP Access Rules'),
            subtitle: vm.$t('Addresses always allowed, and always blocked'),
            to: {name: 'settings_ip_rules'},
            keywords: ['allow list', 'block list', 'whitelist', 'blacklist', 'ban ip', 'ip address']
        },
        {
            group: 'Settings',
            title: vm.$t('Social Login'),
            subtitle: vm.$t('Google, GitHub and Facebook sign-in'),
            to: {name: 'settings_social_login'},
            keywords: ['google', 'github', 'facebook', 'oauth', 'one tap', 'sso']
        },
        {
            group: 'Settings',
            title: vm.$t('Login & Signup Forms'),
            subtitle: vm.$t('Shortcodes for front-end auth forms'),
            to: {name: 'settings_auth_forms'},
            keywords: ['shortcode', 'registration form', 'front end login', 'block']
        },
        {
            group: 'Settings',
            title: vm.$t('Login Page Design'),
            subtitle: vm.$t('How wp-login.php looks'),
            to: {name: 'settings_auth_customizer'},
            keywords: ['customizer', 'branding', 'logo', 'background', 'wp-login', 'theme']
        },
        {
            group: 'Settings',
            title: vm.$t('Login Redirects'),
            subtitle: vm.$t('Where people land after signing in or out'),
            to: {name: 'settings_redirects'},
            keywords: ['after login', 'after logout', 'landing page', 'per role']
        },
        {
            group: 'Settings',
            title: vm.$t('System Emails'),
            subtitle: vm.$t('The mail WordPress sends, rewritten'),
            to: {name: 'settings_emails'},
            keywords: ['new user email', 'password reset email', 'notifications', 'wp_mail']
        },
        {
            group: 'Settings',
            title: vm.$t('Email Template Design'),
            subtitle: vm.$t('The frame every system email is sent in'),
            to: {name: 'settings_email_template'},
            keywords: ['header', 'footer', 'email branding', 'colours', 'colors']
        },
        {
            group: 'Settings',
            title: vm.$t('Remote Auth'),
            subtitle: vm.$t('Sign in against another site'),
            to: {name: 'settings_server_mode'},
            keywords: ['server mode', 'central login', 'api'],
            when: (appVars) => !!appVars.has_server_mode
        },

        /* ----------------------------------- the blocks within General Settings */

        {
            group: 'Settings',
            title: vm.$t('Core Security'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'core'}},
            keywords: ['xmlrpc', 'xml-rpc', 'application passwords', 'rest api users',
                'hide usernames', 'author enumeration', 'signup verification']
        },
        {
            group: 'Settings',
            title: vm.$t('Login Security'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'login_security'}},
            keywords: ['brute force', 'failed attempts', 'lockout', 'rate limit',
                'login attempts', 'block duration', 'captcha', 'recaptcha', 'turnstile']
        },
        {
            group: 'Settings',
            title: vm.$t('Two-Factor Authentication'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'two_fa'}},
            keywords: ['2fa', 'mfa', 'totp', 'authenticator app', 'email code',
                'passkey', 'webauthn', 'security key', 'backup codes', 'require 2fa']
        },
        {
            group: 'Settings',
            title: vm.$t('Magic Login'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'magic_login'}},
            keywords: ['passwordless', 'email link', 'magic link', 'one click login']
        },
        {
            group: 'Settings',
            title: vm.$t('Notifications'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'notifications'}},
            keywords: ['email alerts', 'admin email', 'notify me', 'new admin created']
        },
        {
            group: 'Settings',
            title: vm.$t('Visitor IP'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'visitor_ip'}},
            keywords: ['proxy', 'cloudflare', 'x-forwarded-for', 'real ip', 'reverse proxy']
        },
        {
            group: 'Settings',
            title: vm.$t('Advanced'),
            subtitle: vm.$t('In General Settings'),
            to: {name: 'settings_general', query: {section: 'advanced'}},
            keywords: ['log retention', 'delete logs', 'admin area access', 'dashboard access']
        }
    ];

    return entries.filter(entry => !entry.when || entry.when(vm.appVars));
};

/*
 * The groups, in the order the results list them. A group with nothing in it is not drawn,
 * so this can name more than a given site has.
 */
export const searchGroups = ['Pages', 'Settings'];

/**
 * One string, reduced to the words in it.
 *
 * Everything is matched on this rather than on what was typed, so "two factor" finds
 * "Two-Factor", "wp login" finds "wp-login.php", and a stray double space costs nothing.
 *
 * @param {String} text
 * @returns {String}
 */
function normalise(text) {
    return (text || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();
}

/**
 * Where one term lands in one string: 0 at the start, 5 at the start of a word, and
 * further in the further along it is. Null if it is not there at all.
 *
 * @param {String} text already normalised
 * @param {String} term already normalised
 * @returns {Number|null}
 */
function positionIn(text, term) {
    const at = text.indexOf(term);

    if (at === -1) {
        return null;
    }

    if (at === 0) {
        return 0;
    }

    return text[at - 1] === ' ' ? 5 : 10 + at;
}

/**
 * How well one entry answers one term, lower being better, or null for no answer.
 *
 * The three fields are tried in the order they are worth: a hit in the title beats a hit
 * in the line under it, which beats a hit in the words that are not written on the screen
 * at all. The penalties are far enough apart that a field never overtakes the one above it.
 */
function rankTerm(entry, term) {
    const fields = [
        [entry.search.title, 0],
        [entry.search.subtitle, 100],
        [entry.search.keywords, 200]
    ];

    let best = null;

    fields.forEach(([text, penalty]) => {
        const at = positionIn(text, term);

        if (at === null) {
            return;
        }

        const score = penalty + at;

        if (best === null || score < best) {
            best = score;
        }
    });

    return best;
}

/**
 * The entries that answer a query, best first.
 *
 * Every term has to land somewhere, so "email template" narrows rather than widens, and
 * the terms are independent, so it finds the same thing typed the other way round. An
 * empty query returns everything - the box with nothing in it is a menu of where you can
 * go, not an empty state.
 *
 * @param {Array} index from searchIndex()
 * @param {String} query what was typed
 * @returns {Array}
 */
export function searchEntries(index, query) {
    const prepared = index.map(entry => ({
        ...entry,
        search: {
            title: normalise(entry.title),
            subtitle: normalise(entry.subtitle),
            keywords: normalise((entry.keywords || []).join(' '))
        }
    }));

    const terms = normalise(query).split(' ').filter(term => term.length > 0);

    if (!terms.length) {
        return prepared;
    }

    const scored = [];

    prepared.forEach(entry => {
        let total = 0;

        for (const term of terms) {
            const score = rankTerm(entry, term);

            if (score === null) {
                return;
            }

            total += score;
        }

        scored.push({entry, total});
    });

    /*
     * Ties are common - two sections both matched on a keyword - and sort() is only stable
     * within equal keys, so the index's own order is what breaks them. That is deliberate:
     * it puts Pages above Settings and General above its own blocks.
     */
    return scored
        .sort((a, b) => a.total - b.total)
        .map(item => item.entry);
}
