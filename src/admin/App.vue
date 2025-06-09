<template>
    <div class="fframe_app">
        <div class="fframe_main-menu-items">
            <div class="menu_logo_holder">
                <h3 style="margin: 10px 0; display: flex;align-items: center;"><img :src="appVars.asset_url + '/images/logo.png'" style="width: 150px; margin-top: -10px; margin-right: 7px;"/></h3>
            </div>
            <div class="fframe_handheld"><span class="dashicons dashicons-menu-alt3"></span></div>
            <ul class="fframe_menu">
                <li v-for="item in menuItems" :key="item.route" :class="'fframe_route_'+item.route"
                    class="fframe_menu_item">
                    <router-link :to="{ name: item.route }" class="fframe_menu_primary">
                        {{ item.title }}
                    </router-link>
                </li>
            </ul>
        </div>

        <div class="ff_app_body">
            <router-view></router-view>
        </div>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'FluentAuthApp',
    data() {
        return {
            menuItems: [
                {
                    route: 'dashboard',
                    title: this.$t('Dashboard')
                },
                {
                    route: 'logs',
                    title: this.$t('Logs')
                },
                {
                    route: 'settings',
                    title: this.$t('Settings')
                },
                {
                    route: 'auth_shortcodes',
                    title: this.$t('Login/Signip Forms')
                },
                {
                    route: 'login_redirects',
                    title: this.$t('Login Redirects')
                },
                {
                    route: 'custom_wp_emails',
                    title: this.$t('System Emails')
                },
                {
                    route: 'security_scans',
                    title: this.$t('Security Scans')
                }
            ]
        }
    },
    watch: {
        $route(to, from) {
            jQuery('.fframe_menu_item').removeClass('router-current-active_li');
            jQuery('.fframe_route_' + to.meta.active).addClass('router-current-active_li');
            document.title = this.$t(to.meta.title) + ' | ' + this.$t('FluentAuth');
        }
    },
    created() {
        jQuery('.update-nag,.notice, #wpbody-content > .updated, #wpbody-content > .error').remove();
    },
    mounted() {
        if (this.appVars.has_server_mode) {
            this.menuItems.push({
                route: 'server_mode',
                title: this.$t('Remote Auth')
            });
        }

        jQuery('.fframe_handheld span').on('click', function () {
            jQuery('ul.fframe_menu').toggle('show');
        });
    }
}
</script>
