import {createApp} from 'vue'
import {createRouter, createWebHashHistory} from 'vue-router';
import {routes} from './routes';
import Rest from './Bits/Rest.js';
import {ElNotification, ElLoading, ElMessageBox} from 'element-plus'
import Storage from '@/Bits/Storage';
import {$t, $_n, $_x} from './Bits/i18n.js';
import App from './App.vue';

import {CloseBold, ArrowLeftBold, View} from '@element-plus/icons-vue';

require('./app.scss');

function convertToText(obj) {
    const string = [];
    if (typeof (obj) === 'object' && (obj.join === undefined)) {
        for (const prop in obj) {
            string.push(convertToText(obj[prop]));
        }
    } else if (typeof (obj) === 'object' && !(obj.join === undefined)) {
        for (const prop in obj) {
            string.push(convertToText(obj[prop]));
        }
    } else if (typeof (obj) === 'function') {

    } else if (typeof (obj) === 'string') {
        string.push(obj)
    }

    return string.join('<br />')
}

const app = createApp(App);
app.use(ElLoading);

app.component(View.name, View);
app.component(CloseBold.name, CloseBold);
app.component(ArrowLeftBold.name, ArrowLeftBold);

app.config.globalProperties.appVars = window.fluentAuthAdmin;

app.mixin({
    data() {
        return {
            Storage
        }
    },
    methods: {
        $get: Rest.get,
        $post: Rest.post,
        $put: Rest.put,
        $del: Rest.delete,
        changeTitle(title) {
            jQuery('head title').text(title + ' - Fluent Auth');
        },
        $handleError(response) {
            let errorMessage = '';
            if (typeof response === 'string') {
                errorMessage = response;
            } else if (response && response.message) {
                errorMessage = response.message;
            } else {
                errorMessage = convertToText(response);
            }
            if (!errorMessage) {
                errorMessage = 'Something is wrong!';
            }
            this.$notify({
                type: 'error',
                title: 'Error',
                message: errorMessage,
                dangerouslyUseHTMLString: true
            });
        },
        convertToText,
        $t,
        $_n,
        $_x
    }
});

app.config.globalProperties.$notify = ElNotification;
app.config.globalProperties.$confirm = ElMessageBox.confirm;
/* For the handful of actions that are worth typing out rather than clicking twice. */
app.config.globalProperties.$prompt = ElMessageBox.prompt;

const router = createRouter({
    routes,
    history: createWebHashHistory()
});

window.fluentFrameworkApp = app.use(router).mount(
    '#fluent_auth_app'
);

/*
 * Keeps WordPress's own submenu in step with the app.
 *
 * All four entries are the same page with a different hash, so WordPress marks the first
 * one current when the page loads and then stops thinking about it: every screen looked
 * like Dashboard, and moving around inside the app never moved the menu.
 *
 * Keyed on the route's own `active` rather than on the URL, which is the same thing the
 * app bar highlights on (see App.vue) - so the two navigations agree by construction, and
 * a screen whose path does not look like its section still lights the right entry.
 * `/security-scans` and `/login-page-design` are both like that.
 */
const MENU_HASHES = {
    dashboard: '',
    logs: '#/logs',
    security: '#/security',
    settings: '#/settings'
};

function syncAdminMenu(route) {
    const active = route && route.meta ? route.meta.active : '';

    // The wizard has no menu entry of its own; leave whatever is lit alone.
    if (!(active in MENU_HASHES)) {
        return;
    }

    const suffix = MENU_HASHES[active];
    const items = jQuery('#toplevel_page_fluent-auth .wp-submenu li');

    items.each(function () {
        const href = jQuery(this).find('a').attr('href') || '';
        const hash = href.indexOf('#') === -1 ? '' : href.slice(href.indexOf('#'));

        jQuery(this).toggleClass('current', hash === suffix);
    });
}

router.afterEach((to) => {
    syncAdminMenu(to);
});

jQuery('#toplevel_page_fluent-auth .wp-submenu a').on('click', function () {
    window.scrollTo({top: 0, behavior: 'smooth'});
});

syncAdminMenu(router.currentRoute.value);
