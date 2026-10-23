<script type="text/babel">
import SettingsHeader from '../_SettingsHeader.vue';
import SettingsCard from '../_SettingsCard.vue';
import SettingRow from '../_SettingRow.vue';
import SettingToggle from '../_SettingToggle.vue';

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

let scriptPromise = null;

function loadTurnstile() {
    if (window.turnstile) {
        return Promise.resolve(window.turnstile);
    }

    if (!scriptPromise) {
        scriptPromise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = SCRIPT_URL;
            script.async = true;
            script.onload = () => resolve(window.turnstile);
            script.onerror = () => {
                scriptPromise = null;
                reject();
            };
            document.head.appendChild(script);
        });
    }

    return scriptPromise;
}

/**
 * Cloudflare Turnstile on the signup, login and WooCommerce account forms.
 *
 * Its own option and its own save, like the IP rules. New keys are only saved with a
 * token from a widget rendered here with the new site key, which proves the pair works
 * on this domain before any login form depends on it.
 */
export default {
    name: 'BotProtectionSettings',
    components: {SettingsHeader, SettingsCard, SettingRow, SettingToggle},
    data() {
        return {
            loading: true,
            saving: false,
            settings: {site_key: '', secret_key: '', signup: 'no', login: 'no', woo: 'no'},
            saved: {site_key: '', secret_key: ''},
            sources: [],
            has_woo: false,
            disabled_by_constant: false,
            hostnames: [],
            showSteps: false,
            token: '',
            widgetId: null,
            widgetFailed: false,
            renderTimer: null
        }
    },
    computed: {
        keysChanged() {
            return this.settings.site_key !== this.saved.site_key ||
                this.settings.secret_key !== this.saved.secret_key;
        },
        needsTest() {
            return this.keysChanged && !!this.settings.site_key && !!this.settings.secret_key;
        },
        hasKeys() {
            return !!this.saved.site_key && !!this.saved.secret_key;
        },
        offeredSources() {
            return this.sources.filter(source => source.site_key !== this.settings.site_key ||
                source.secret_key !== this.settings.secret_key);
        }
    },
    watch: {
        'settings.site_key'() {
            this.scheduleRender();
        },
        needsTest() {
            this.scheduleRender();
        }
    },
    methods: {
        fetchSettings() {
            this.loading = true;

            this.$get('turnstile')
                .then(response => {
                    this.applyState(response);
                    this.sources = response.sources || [];
                    this.has_woo = !!response.has_woo;
                    this.disabled_by_constant = !!response.disabled_by_constant;
                    this.hostnames = response.hostnames || [];
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        applyState(response) {
            this.settings = {...response.settings};
            this.saved = {
                site_key: response.settings.site_key,
                secret_key: response.settings.secret_key
            };
        },
        useSource(source) {
            this.settings.site_key = source.site_key;
            this.settings.secret_key = source.secret_key;
        },
        scheduleRender() {
            clearTimeout(this.renderTimer);
            this.renderTimer = setTimeout(() => this.renderWidget(), 400);
        },
        removeWidget() {
            if (this.widgetId !== null && window.turnstile) {
                window.turnstile.remove(this.widgetId);
            }

            this.widgetId = null;
            this.token = '';
        },
        renderWidget() {
            this.removeWidget();
            this.widgetFailed = false;

            if (!this.needsTest) {
                return;
            }

            loadTurnstile()
                .then(turnstile => {
                    this.$nextTick(() => {
                        const el = this.$refs.testWidget;

                        if (!el || !this.needsTest) {
                            return;
                        }

                        this.widgetId = turnstile.render(el, {
                            sitekey: this.settings.site_key,
                            theme: 'auto',
                            callback: (token) => {
                                this.token = token;
                                this.widgetFailed = false;
                            },
                            'expired-callback': () => {
                                this.token = '';
                            },
                            'error-callback': () => {
                                this.token = '';
                                this.widgetFailed = true;
                                return true;
                            }
                        });
                    });
                })
                .catch(() => {
                    this.widgetFailed = true;
                });
        },
        /*
         * Clears both keys and every switch in one save, so nothing is left switched on
         * against keys that are gone.
         */
        removeKeys() {
            this.$confirm(
                this.$t('Your forms will stop checking for bots. You can add keys again at any time.'),
                this.$t('Remove the Turnstile keys?'),
                {
                    confirmButtonText: this.$t('Remove keys'),
                    cancelButtonText: this.$t('Cancel'),
                    type: 'warning'
                }
            )
                .then(() => {
                    this.settings = {site_key: '', secret_key: '', signup: 'no', login: 'no', woo: 'no'};
                    this.removeWidget();
                    this.saveSettings();
                })
                .catch(() => {
                });
        },
        saveSettings() {
            this.saving = true;

            this.$post('turnstile', {settings: this.settings, token: this.token})
                .then(response => {
                    this.$notify.success(response.message);
                    this.applyState(response);
                })
                .catch(errors => {
                    this.$handleError(errors);

                    if (this.needsTest) {
                        this.renderWidget();
                    }
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    },
    mounted() {
        this.fetchSettings();
    },
    beforeUnmount() {
        clearTimeout(this.renderTimer);
        this.removeWidget();
    }
};
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Bot Protection')"
                        :description="$t('Stop bots from signing up, logging in and asking for password resets.')"
                        :saving="saving" :disabled="loading || (needsTest && !token)" @save="saveSettings()"/>

        <div class="fls_settings_content" v-loading="loading">
            <!--
                First on the screen, because switches that are on but not applied look exactly
                like switches that work.
            -->
            <el-alert v-if="disabled_by_constant" type="warning" :closable="false" show-icon
                      class="fls_row_alert"
                      :title="$t('Bot protection is switched off in wp-config.php')">
                <!-- translators: %s is the PHP constant name FLUENT_AUTH_DISABLE_TURNSTILE -->
                {{ $t('%s is set in wp-config.php, so no form checks for bots. Remove that line once your keys are fixed.', 'FLUENT_AUTH_DISABLE_TURNSTILE') }}
            </el-alert>

            <SettingsCard :title="$t('Cloudflare Turnstile keys')"
                          :description="$t('Turnstile is a free check from Cloudflare. Most people never see a puzzle.')">
                <template v-if="hasKeys" #actions>
                    <el-button size="small" :disabled="saving" @click="removeKeys()">
                        {{ $t('Remove keys') }}
                    </el-button>
                </template>

                <el-alert v-for="source in offeredSources" :key="source.key" type="info" :closable="false"
                          show-icon class="fls_row_alert"
                          :title="/* translators: %s is a plugin name, like Fluent Forms */ $t('%s already has Turnstile keys', source.title)">
                    <p>{{ $t('You can use the same keys here. You do not need new ones from Cloudflare.') }}</p>
                    <el-button size="small" @click="useSource(source)">
                        <!-- translators: %s is a plugin name, like Fluent Forms -->
                        {{ $t('Use the keys from %s', source.title) }}
                    </el-button>
                </el-alert>

                <a v-if="hasKeys" href="#" class="fls_setup_steps_toggle" @click.prevent="showSteps = !showSteps">
                    {{ showSteps ? $t('Hide the setup steps') : $t('How to set up the widget in Cloudflare') }}
                </a>

                <!--
                    Follows Cloudflare's own screen, field by field. The hostname is the step
                    that matters: a widget without this site's domain never hands out a token,
                    and with login guarded that is a login form nobody gets through.
                -->
                <ol v-if="!hasKeys || showSteps" class="fls_setup_steps">
                    <li>
                        {{ $t('Open Turnstile in your Cloudflare account and click Add widget.') }}
                        <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noopener">
                            {{ $t('Open Cloudflare Turnstile') }}
                        </a>
                    </li>
                    <li>{{ $t('Give the widget any name, such as the name of your site.') }}</li>
                    <li>
                        {{ $t('Under Hostnames, add the address of this site:') }}
                        <code v-for="host in hostnames" :key="host" class="fls_code_inline">{{ host }}</code>
                    </li>
                    <li>{{ $t('Under Widget Mode, choose Managed. It is the recommended mode. Choose Invisible if you do not want visitors to see anything.') }}</li>
                    <li>{{ $t('Leave "Skip future security rule challenges" off. You do not need it.') }}</li>
                    <li>{{ $t('Click Create. Then copy the site key and the secret key into the fields below.') }}</li>
                </ol>

                <SettingRow :label="$t('Site key')">
                    <el-input v-model="settings.site_key" type="text" spellcheck="false"/>
                </SettingRow>

                <SettingRow :label="$t('Secret key')">
                    <el-input v-model="settings.secret_key" type="password" show-password spellcheck="false"/>
                </SettingRow>

                <SettingRow v-if="needsTest" :label="$t('Test the keys')"
                            :description="$t('Complete this check so we know the keys work on this site. Then save.')">
                    <div ref="testWidget"></div>

                    <p v-if="widgetFailed" class="fls_note">
                        {{ $t('The check could not load. The site key may be wrong, or this domain is not added to the widget in Cloudflare.') }}
                    </p>
                </SettingRow>
            </SettingsCard>

            <SettingsCard :title="$t('Where to use it')"
                          :description="$t('Turn it on only where bots are a problem.')">
                <p v-if="!hasKeys" class="fls_note">
                    {{ $t('Save working keys first. Until then, these settings do nothing.') }}
                </p>

                <SettingToggle v-model="settings.signup" :label="$t('Signup forms')"
                               :description="$t('The signup shortcode and the WordPress registration page.')"/>

                <SettingToggle v-model="settings.login" :label="$t('Login and password reset forms')"
                               :description="$t('The login and password reset shortcodes, and wp-login.php.')">
                    <el-alert v-if="settings.login === 'yes'" type="warning" :closable="false" show-icon
                              class="fls_row_alert"
                              :title="$t('If you move this site to a new domain, update Turnstile first')">
                        {{ $t('Add the new domain to your widget in Cloudflare before you move. Otherwise nobody can log in with a password. Passkeys, magic links and social login still work.') }}
                        <br>
                        <!-- translators: %s is a line of PHP code to paste into wp-config.php -->
                        {{ $t('If you are ever locked out, add %s to wp-config.php to switch bot protection off and get back in.', "define('FLUENT_AUTH_DISABLE_TURNSTILE', true);") }}
                    </el-alert>
                </SettingToggle>

                <SettingToggle v-if="has_woo" v-model="settings.woo" :label="$t('WooCommerce account forms')"
                               :description="$t('Login and signup on the My Account page. Checkout is not changed.')"/>
            </SettingsCard>
        </div>
    </div>
</template>
