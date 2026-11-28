<script type="text/babel">
/**
 * About FluentAuth: what it is, who makes it, and a few of the team's other plugins that
 * install in one click. Nothing is installed or fetched until the admin asks.
 */
export default {
    name: 'AboutPage',
    data() {
        return {
            loading: true,
            plugins: [],
            canInstall: false,
            canActivate: false,
            version: '',
            contributors: [],
            contributorsLoaded: false,
            busy: ''
        }
    },
    computed: {
        links() {
            return [
                {url: 'https://fluentauth.com/docs/', label: this.$t('Read the documentation')},
                {url: 'https://github.com/WPManageNinja/fluent-security/issues', label: this.$t('Report a problem on GitHub')},
                {url: 'https://github.com/WPManageNinja/fluent-security', label: this.$t('Browse the source code')},
                {url: 'https://wordpress.org/support/plugin/fluent-security/reviews/#new-post', label: this.$t('Leave a review on WordPress.org')}
            ];
        }
    },
    methods: {
        fetch() {
            this.$get('about')
                .then(response => {
                    this.plugins = response.plugins || [];
                    this.canInstall = !!response.can_install;
                    this.canActivate = !!response.can_activate;
                    this.version = response.version || '';
                })
                .catch(errors => this.$handleError(errors))
                .finally(() => {
                    this.loading = false;
                });

            // Separate, so a slow answer from GitHub never holds up the page.
            this.$get('about/contributors')
                .then(response => {
                    this.contributors = response.contributors || [];
                })
                .catch(() => {
                })
                .finally(() => {
                    this.contributorsLoaded = true;
                });
        },
        actionLabel(plugin) {
            if (plugin.state === 'installed') {
                return this.$t('Activate');
            }

            return this.$t('Install and activate');
        },
        canAct(plugin) {
            if (plugin.state === 'installed') {
                return this.canActivate;
            }

            return this.canInstall && this.canActivate;
        },
        install(plugin) {
            this.busy = plugin.slug;

            this.$post('about/install-plugin', {slug: plugin.slug})
                .then(response => {
                    const index = this.plugins.findIndex(row => row.slug === plugin.slug);
                    if (index > -1) {
                        this.plugins[index] = response.plugin;
                    }
                    this.$notify.success(response.message);
                })
                .catch(errors => this.$handleError(errors))
                .finally(() => {
                    this.busy = '';
                });
        }
    },
    mounted() {
        this.fetch();
    }
}
</script>

<template>
    <div class="fls_page">
        <div class="fls_page_inner">
            <div class="fls_page_main">
                <div class="fls_page_head">
                    <div>
                        <h1 class="fls_page_title">{{ $t('About FluentAuth') }}</h1>
                        <p class="fls_page_desc">{{ $t('Login security for WordPress, from the people who make it.') }}</p>
                    </div>
                </div>

                <section class="fls_card fls_about_story">
                    <div class="fls_card_body">
                        <p>{{ $t('__about_story_1__') }}</p>
                        <p>{{ $t('__about_story_2__') }}</p>
                        <p>{{ $t('__about_story_3__') }}</p>
                    </div>
                </section>

                <section class="fls_card">
                    <div class="fls_card_head">
                        <div>
                            <h2>{{ $t('More from the same team') }}</h2>
                            <p class="fls_about_sub">{{ $t('Free on WordPress.org. Each one installs in a click.') }}</p>
                        </div>
                    </div>

                    <el-skeleton v-if="loading" :animated="true" :rows="5" class="fls_about_pad"/>

                    <ul v-else class="fls_about_plugins">
                        <li v-for="plugin in plugins" :key="plugin.slug" class="fls_about_plugin">
                            <img :src="plugin.icon" alt="" width="48" height="48" loading="lazy"/>
                            <div class="fls_about_plugin_text">
                                <a :href="plugin.info_url" target="_blank" rel="noopener" class="fls_about_plugin_name">{{ plugin.name }}</a>
                                <p>{{ plugin.pitch }}</p>
                            </div>
                            <div class="fls_about_plugin_action">
                                <el-button v-if="plugin.state === 'active'" tag="a" :href="plugin.admin_url" size="small">
                                    {{ $_x('Open', 'Verb: go to the plugin') }}
                                </el-button>
                                <el-button v-else-if="canAct(plugin)" size="small" type="primary"
                                           :loading="busy === plugin.slug" :disabled="!!busy && busy !== plugin.slug"
                                           @click="install(plugin)">
                                    {{ actionLabel(plugin) }}
                                </el-button>
                                <el-button v-else tag="a" :href="plugin.info_url" target="_blank" rel="noopener" size="small">
                                    {{ $t('View on WordPress.org') }}
                                </el-button>
                            </div>
                        </li>
                    </ul>
                </section>
            </div>

            <aside class="fls_page_aside fls_about_aside">
                <h3 class="fls_eyebrow">{{ $t('Help and feedback') }}</h3>
                <ul class="fls_about_links">
                    <li v-for="link in links" :key="link.url">
                        <a :href="link.url" target="_blank" rel="noopener">{{ link.label }}</a>
                    </li>
                </ul>

                <h3 class="fls_eyebrow">{{ $t('Contributors') }}</h3>
                <p class="fls_about_note">{{ $t('Everyone who has improved FluentAuth on GitHub. Thank you.') }}</p>
                <el-skeleton v-if="!contributorsLoaded" :animated="true" :rows="2"/>
                <div v-else-if="contributors.length" class="fls_about_people">
                    <a v-for="person in contributors" :key="person.login" :href="person.url"
                       target="_blank" rel="noopener" :title="person.login">
                        <img :src="person.avatar" :alt="person.login" width="40" height="40" loading="lazy"/>
                    </a>
                </div>
                <p v-else class="fls_about_note">
                    <a href="https://github.com/WPManageNinja/fluent-security/graphs/contributors" target="_blank" rel="noopener">
                        {{ $t('See the contributors on GitHub') }}
                    </a>
                </p>

                <!-- translators: %s is the plugin's version number -->
                <p v-if="version" class="fls_about_version">{{ $t('FluentAuth version %s', version) }}</p>
            </aside>
        </div>
    </div>
</template>
