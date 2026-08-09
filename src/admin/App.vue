<script type="text/babel">
import ThemeSwitch from './Bits/ThemeSwitch.vue';

export default {
    name: 'FluentAuthApp',
    components: {
        ThemeSwitch
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
    methods: {
        isActive(item) {
            const active = this.$route.meta ? this.$route.meta.active : '';

            return item.match ? active === item.match : active === item.route;
        },
        onScroll() {
            this.scrolled = window.scrollY > 10;
        },
        /**
         * Publishes the width of wp-admin's menu as a CSS variable.
         *
         * The app bar and the settings pane are pinned to the viewport, which means they
         * cannot inherit the page's left offset the way an in-flow element does - they
         * have to be told where the menu ends. Measuring it beats hard-coding 160px:
         * collapsing the menu, the automatic fold on a narrow window and the off-canvas
         * menu on a phone all land on different widths, and all of them show up here.
         */
        measureShell() {
            const content = document.getElementById('wpcontent');
            const left = content ? content.getBoundingClientRect().left : 0;

            document.documentElement.style.setProperty('--fls-shell-left', left + 'px');
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
    <div class="fframe_app">
        <div class="fls_app_bar" :class="{'is-scrolled': scrolled}">
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
                <theme-switch/>
            </div>
        </div>

        <div class="ff_app_body">
            <router-view></router-view>
        </div>
    </div>
</template>
