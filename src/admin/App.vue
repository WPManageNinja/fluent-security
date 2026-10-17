<script type="text/babel">
import ThemeSwitch from './Bits/ThemeSwitch.vue';
import GlobalSearch from './Bits/GlobalSearch.vue';
import SubNav from './Bits/SubNav.vue';
import {sectionFor} from './Bits/subNav';

export default {
    name: 'FluentAuthApp',
    components: {
        ThemeSwitch,
        GlobalSearch,
        SubNav
    },
    data() {
        return {
            scrolled: false,
            navOpen: false,
            /*
             * Only destinations - places you go to look at something. Everything you go
             * to change lives behind Settings, in one sidebar, so there is never a
             * question of which of two menus a given option is under.
             */
            menuItems: [
                {route: 'dashboard', title: this.$t('Dashboard')},
                {route: 'logs', title: this.$t('Logs')},
                {route: 'security_findings', title: this.$t('Security'), match: 'security'},
                {route: 'settings_general', title: this.$t('Settings'), match: 'settings'}
            ]
        }
    },
    computed: {
        /*
         * The wizard covers the whole screen and carries its own header, so the app bar
         * would only be a second navigation offering to abandon it. See routes.js.
         */
        isBare() {
            return !!(this.$route.meta && this.$route.meta.bare);
        },
        /*
         * Whether a second bar is drawn under the first one. The shell has to know, and not
         * only the bar itself: both bars are pinned, so the page below them is only clear of
         * them because it is padded by the height of whatever is up there.
         */
        hasSubNav() {
            return !this.isBare && !!sectionFor(this.$route);
        }
    },
    methods: {
        /**
         * Sends a site that has never been set up into the wizard, once.
         *
         * On the flag the server sends rather than on anything stored in the browser, so
         * finishing setup in one tab does not leave another one still redirecting. The
         * wizard clears the flag itself when it is finished or left, which is what stops
         * this from being a loop.
         */
        redirectToOnboarding() {
            if (!this.appVars.is_onboarding) {
                return;
            }

            if (this.$route.name === 'onboarding') {
                return;
            }

            this.$router.replace({name: 'onboarding'});
        },
        isActive(item) {
            const active = this.$route.meta ? this.$route.meta.active : '';

            return item.match ? active === item.match : active === item.route;
        },
        onScroll() {
            this.scrolled = window.scrollY > 10;
        },
        /**
         * Publishes wp-admin's content insets as CSS variables.
         *
         * The app bar and the settings pane are pinned to the viewport, which means they
         * cannot inherit the page offset the way an in-flow element does - they have to
         * be told where the menu ends. Measuring both edges handles WordPress's left-side
         * menu in LTR and right-side menu in RTL, as well as the folded and off-canvas
         * variants, without hard-coding their widths.
         */
        measureShell() {
            const content = document.getElementById('wpcontent');
            const bounds = content ? content.getBoundingClientRect() : null;
            const styles = content ? window.getComputedStyle(content) : null;
            const viewportWidth = document.documentElement.clientWidth;
            const left = bounds ? Math.max(0, bounds.left) : 0;
            const right = bounds ? Math.max(0, viewportWidth - bounds.right) : 0;
            const paddingLeft = styles ? parseFloat(styles.paddingLeft) || 0 : 0;
            const paddingRight = styles ? parseFloat(styles.paddingRight) || 0 : 0;

            document.documentElement.style.setProperty('--fls-shell-left', left + 'px');
            document.documentElement.style.setProperty('--fls-shell-right', right + 'px');
            document.documentElement.style.setProperty('--fls-content-padding-left', paddingLeft + 'px');
            document.documentElement.style.setProperty('--fls-content-padding-right', paddingRight + 'px');
        }
    },
    watch: {
        $route(to) {
            this.navOpen = false;
            document.title = this.$t(to.meta.title) + ' | ' + this.$t('FluentAuth');
        }
    },
    created() {
        jQuery('.update-nag,.notice, #wpbody-content > .updated, #wpbody-content > .error').remove();
        this.redirectToOnboarding();
    },
    mounted() {
        window.addEventListener('scroll', this.onScroll);
        this.onScroll();

        this.measureShell();

        /*
         * Folding the menu changes the width of #wpcontent, so watching its size catches
         * the fold, the automatic fold at narrow widths and an ordinary window resize
         * without listening for any of them by name.
         */
        const content = document.getElementById('wpcontent');

        if (content && window.ResizeObserver) {
            this.shellObserver = new ResizeObserver(this.measureShell);
            this.shellObserver.observe(content);
        } else {
            window.addEventListener('resize', this.measureShell);
        }
    },
    beforeUnmount() {
        window.removeEventListener('scroll', this.onScroll);
        window.removeEventListener('resize', this.measureShell);

        if (this.shellObserver) {
            this.shellObserver.disconnect();
        }
    }
}
</script>

<template>
    <div class="fframe_app" :class="{'is-bare': isBare, 'has-subnav': hasSubNav}">
        <div v-if="!isBare" class="fls_app_bar" :class="{'is-scrolled': scrolled}">
            <div class="fls_app_logo">
                <router-link :to="{name: 'dashboard'}">
                    <img :src="appVars.asset_url + '/images/logo.png'" alt="FluentAuth"/>
                </router-link>
            </div>

            <button class="fls_app_bar_toggle" type="button" @click="navOpen = !navOpen"
                    :aria-label="$t('Menu')">
                <span class="dashicons dashicons-menu-alt3"></span>
            </button>

            <ul class="fls_app_nav" :class="{'is-open': navOpen}">
                <li v-for="item in menuItems" :key="item.route">
                    <router-link :to="{name: item.route}"
                                 :class="{'router-link-active': isActive(item)}">
                        {{ item.title }}
                    </router-link>
                </li>
            </ul>

            <div class="fls_app_bar_actions">
                <slot name="actions"/>
                <global-search/>
                <theme-switch/>
            </div>
        </div>

        <sub-nav v-if="!isBare"/>

        <div class="ff_app_body">
            <router-view></router-view>
        </div>
    </div>
</template>
