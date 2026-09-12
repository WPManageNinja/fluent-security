import {reactive} from 'vue';

/*
 * The bar of sections that sits under the app bar.
 *
 * A top-level destination that is really several views of one subject gets a second bar
 * rather than several entries in the first one: the top bar stays a list of places, and
 * which view of a place you are looking at is a question answered underneath it.
 *
 * Keyed by the same `active` the app bar highlights on, so a route joins a section by
 * naming one in its meta and nothing here has to know about paths. `names` is the list of
 * route names a tab owns - a tab can own more than one, which is how a detour like the
 * scanner's registration screen keeps its tab lit.
 */
export const sections = {
    security: {
        label: 'Security sections',
        items: [
            {
                route: 'security_findings',
                title: 'Findings',
                names: ['security_findings'],
                count: 'findings'
            },
            {
                route: 'security_scans',
                title: 'Monitoring',
                names: ['security_scans', 'security_scan_register']
            },
            /*
             * Last, and named for the situation rather than for the feature. Nobody goes
             * looking for "recovery"; they go looking for what to do after a break-in - and a
             * label that names the emergency is also a label that says when not to open it.
             * "Recovery" meant the 2FA codes on the profile screen long before it meant this.
             */
            {
                route: 'security_recovery',
                title: 'Been Hacked?',
                names: ['security_recovery']
            }
        ]
    }
};

/*
 * The numbers shown beside a tab, written by whichever screen has just loaded one.
 *
 * The bar is drawn by the shell, above the screen it belongs to, so a screen cannot hand
 * its count up as a prop. One shallow object rather than a store: these are badges, not
 * state that anything acts on.
 */
export const counts = reactive({
    findings: 0
});

/**
 * The section a route belongs to, or null if it is a destination of its own.
 *
 * @param {Object} route
 * @returns {Object|null}
 */
export function sectionFor(route) {
    const active = route && route.meta ? route.meta.active : '';

    return sections[active] || null;
}
