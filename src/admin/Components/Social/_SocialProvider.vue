<script type="text/babel">
import SettingsCard from '../Settings/_SettingsCard.vue';
import SettingRow from '../Settings/_SettingRow.vue';
import SettingToggle from '../Settings/_SettingToggle.vue';
import ProviderMark from './_ProviderMark.vue';

/**
 * One social provider's settings.
 *
 * GitHub, Google and Facebook are configured identically - a switch, a choice of where
 * the credentials live, the credentials themselves and the redirect URL to paste into
 * the provider's own console. They were three copies of the same forty lines, which is
 * how they had drifted into three slightly different wordings for the same thing.
 *
 * The keys are derived from the provider name because that is how they are stored:
 * `enable_github`, `github_key_method`, `github_client_id`, `github_client_secret`.
 */
export default {
    name: 'SocialProvider',
    components: {SettingsCard, SettingRow, SettingToggle, ProviderMark},
    props: {
        settings: {type: Object, required: true},
        provider: {type: String, required: true},
        title: {type: String, required: true},
        description: {type: String, default: ''},
        idLabel: {type: String, required: true},
        secretLabel: {type: String, required: true},
        info: {type: Object, default: () => ({})},
        // Google is only offered when the server can actually reach it.
        available: {type: Boolean, default: true},
        unavailableNote: {type: String, default: ''}
    },
    computed: {
        enabled() {
            return this.settings['enable_' + this.provider] === 'yes';
        },
        storesInWpConfig() {
            return this.settings[this.provider + '_key_method'] === 'wp_config';
        },
        /**
         * Whether this provider has both halves of a credential to sign anyone in with.
         *
         * Each half is checked where it can be seen: the fields are in the form, so the
         * browser reads those itself and the badge answers as they are typed, while the
         * wp-config.php constants are only visible to PHP and arrive as a flag with the
         * settings.
         */
        hasCredentials() {
            if (this.storesInWpConfig) {
                return !!this.info.has_wp_config_keys;
            }

            return !!this.settings[this.provider + '_client_id']
                && !!this.settings[this.provider + '_client_secret'];
        },
        /**
         * The wp-config.php lines to paste, named after the provider the same way the
         * plugin reads them back.
         */
        wpConfigSnippet() {
            const name = this.provider.toUpperCase();

            return `define('FLUENT_AUTH_${name}_CLIENT_ID', '******');\n`
                + `define('FLUENT_AUTH_${name}_CLIENT_SECRET', '******');`;
        }
    }
};
</script>

<template>
    <SettingsCard :title="title" :description="description">
        <template #icon>
            <ProviderMark :provider="provider"/>
        </template>

        <!--
            Said on the head rather than left to be found out at a sign-in: a provider
            switched on without a client ID and secret is switched on and broken, and
            nothing else on the screen says so.
        -->
        <template #badge>
            <span v-if="enabled && available" class="fls_tag is_round"
                  :class="hasCredentials ? 'is_success' : 'is_warning'">
                {{ hasCredentials ? $t('Ready') : $t('Credentials needed') }}
            </span>
        </template>

        <template #actions>
            <el-switch v-model="settings['enable_' + provider]" :disabled="!available"
                       active-value="yes" inactive-value="no"/>
        </template>

        <template v-if="!available">
            <p class="fls_note">{{ unavailableNote }}</p>
        </template>

        <template v-else-if="enabled">
            <slot name="extra"/>

            <SettingRow :label="$t('Credential storage')"
                        :description="$t('Keeping the secret in wp-config.php keeps it out of the database and out of a database backup.')">
                <el-radio-group v-model="settings[provider + '_key_method']">
                    <el-radio-button value="db" :label="$t('Database')"/>
                    <el-radio-button value="wp_config" label="wp-config.php"/>
                </el-radio-group>
            </SettingRow>

            <SettingRow v-if="storesInWpConfig" :label="$t('Add to wp-config.php')"
                        :description="$t('Replace the stars with the values from your app.')">
                <pre class="fls_code">{{ wpConfigSnippet }}</pre>
            </SettingRow>

            <template v-else>
                <SettingRow :label="idLabel">
                    <el-input v-model="settings[provider + '_client_id']" type="text" :placeholder="idLabel"/>
                </SettingRow>

                <SettingRow :label="secretLabel">
                    <el-input v-model="settings[provider + '_client_secret']" type="password"
                              show-password :placeholder="secretLabel"/>
                </SettingRow>
            </template>

            <SettingRow :label="$t('Redirect URL')"
                        :description="$t('Paste this into the app you created with the provider. Sign-in fails if it does not match exactly.')">
                <code class="fls_code_inline">{{ info.app_redirect }}</code>
                <p>
                    <a :href="info.doc_url" target="_blank" rel="noopener">
                        {{ $t('How to set up this app') }}
                    </a>
                </p>
            </SettingRow>
        </template>
    </SettingsCard>
</template>
