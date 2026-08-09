<script type="text/babel">
import SettingsHeader from './Settings/_SettingsHeader.vue';
import SettingsCard from './Settings/_SettingsCard.vue';
import SettingRow from './Settings/_SettingRow.vue';

/**
 * The shortcodes that put a login, signup or password reset form on a page.
 *
 * This screen used to render the social login and login page design settings inline as
 * well, which put both of them on screen twice once they became sidebar entries of their
 * own. It now covers the forms and links to the designer rather than embedding it.
 */
export default {
    name: 'AuthShortcodes',
    components: {SettingsHeader, SettingsCard, SettingRow},
    data() {
        return {
            loading: false,
            settings: false,
            saving: false,
            errors: false,
            roles: {},
            design: null,
            savingDesign: false,
            shortcodes: [
                {
                    code: '[fluent_auth]',
                    title: this.$t('Everything'),
                    description: this.$t('Login, registration and password reset in one place, showing whichever the visitor needs.')
                },
                {
                    code: '[fluent_auth_login]',
                    title: this.$t('Login only'),
                    description: this.$t('Just the login form.')
                },
                {
                    code: '[fluent_auth_signup]',
                    title: this.$t('Registration only'),
                    description: this.$t('Just the registration form.')
                },
                {
                    code: '[fluent_auth_reset_password]',
                    title: this.$t('Password reset'),
                    description: this.$t('Requests a reset link and sets the new password.')
                },
                {
                    code: '[fluent_auth_magic_login]<h3>Type your email address to log in</h3>[/fluent_auth_magic_login]',
                    title: this.$t('Magic login'),
                    description: this.$t('Emails a sign-in link. The heading between the tags is yours to change or remove.')
                }
            ]
        }
    },
    computed: {
        enabled() {
            return this.settings && this.settings.enabled === 'yes';
        },
        designOn() {
            return this.design && this.design.status === 'yes';
        }
    },
    methods: {
        saveSettings() {
            // Nothing loaded means nothing to save - posting now would overwrite with blanks.
            if (!this.settings) {
                return;
            }

            this.errors = false;
            this.saving = true;

            this.$post('auth-forms-settings', {settings: this.settings})
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch((errors) => {
                    this.$handleError(errors);
                    this.errors = errors.data;
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        getSettings() {
            this.loading = true;

            this.$get('auth-forms-settings')
                .then(response => {
                    this.settings = response.settings;
                    this.roles = response.roles;
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        getDesign() {
            this.$get('auth-customizer')
                .then(response => {
                    this.design = response.settings;
                })
                .catch(error => {
                    this.$handleError(error);
                });
        },
        /*
         * Saved on its own the moment it is switched, because it is the switch that
         * decides whether the designer button below it means anything.
         */
        saveDesign() {
            this.savingDesign = true;

            this.$post('auth-customizer', {settings: this.design})
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch(error => {
                    this.$handleError(error);
                })
                .finally(() => {
                    this.savingDesign = false;
                });
        },
        copy(text) {
            navigator.clipboard.writeText(text)
                .then(() => this.$notify.success(this.$t('Copied to clipboard')))
                .catch(() => this.$notify.error(this.$t('Could not copy to clipboard')));
        }
    },
    mounted() {
        this.getSettings();
        this.getDesign();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Login & Signup Forms')"
                        :description="$t('Put a sign-in form on any page of your site.')"
                        :saving="saving" :disabled="!settings" @save="saveSettings()"/>

        <div class="fls_settings_content">
            <el-skeleton v-if="!settings" :animated="true" :rows="6"/>

            <el-form v-else label-position="top">
                <SettingsCard :title="$t('Shortcode forms')"
                              :description="$t('Turn this on to use the shortcodes below. With it off they render nothing.')">
                    <template #actions>
                        <el-switch v-model="settings.enabled" active-value="yes" inactive-value="no"/>
                    </template>
                </SettingsCard>

                <SettingsCard v-if="enabled" :title="$t('Shortcodes')"
                              :description="$t('Paste one into a page. Add redirect_to=\'your URL\' to any of them to choose where people land afterwards.')">
                    <SettingRow v-for="shortcode in shortcodes" :key="shortcode.code"
                                :label="shortcode.title" :description="shortcode.description">
                        <div class="fls_shortcode">
                            <code class="fls_code_inline">{{ shortcode.code }}</code>
                            <el-button size="small" @click="copy(shortcode.code)">{{ $t('Copy') }}</el-button>
                        </div>
                    </SettingRow>
                </SettingsCard>

                <SettingsCard v-if="design" :title="$t('Login page design')"
                              :description="$t('Replaces the default WordPress login screen with a styled one you lay out yourself.')">
                    <template #actions>
                        <el-switch v-model="design.status" :disabled="savingDesign"
                                   active-value="yes" inactive-value="no" @change="saveDesign()"/>
                    </template>

                    <SettingRow v-if="designOn" :label="$t('Design the page')"
                                :description="$t('Choose the layout, background and wording for the login and sign-up screens.')">
                        <el-button @click="$router.push({name: 'settings_auth_customizer'})">
                            {{ $t('Open the designer') }}
                        </el-button>
                    </SettingRow>
                </SettingsCard>

                <div class="fls_errors" v-if="errors">
                    <ul>
                        <li v-for="(error, errorKey) in errors" :key="errorKey" v-html="convertToText(error)"></li>
                    </ul>
                </div>
            </el-form>
        </div>
    </div>
</template>
