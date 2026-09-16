<script type="text/babel">
import SettingsHeader from './Settings/_SettingsHeader.vue';
import SettingsCard from './Settings/_SettingsCard.vue';
import SettingRow from './Settings/_SettingRow.vue';
import SettingToggle from './Settings/_SettingToggle.vue';
import SocialProvider from './Social/_SocialProvider.vue';

export default {
    name: 'SocialAuthSettings',
    components: {SettingsHeader, SettingsCard, SettingRow, SettingToggle, SocialProvider},
    data() {
        return {
            loading: false,
            settings: false,
            saving: false,
            errors: false,
            auth_info: false
        }
    },
    computed: {
        enabled() {
            return this.settings && this.settings.enabled === 'yes';
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

            this.$post('social-auth-settings', {settings: this.settings})
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

            this.$get('social-auth-settings')
                .then(response => {
                    this.settings = response.settings;
                    this.auth_info = response.auth_info;
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        convertToText(error) {
            if (typeof error === 'string') {
                return error;
            }

            if (Array.isArray(error)) {
                return error.join('<br />');
            }

            return JSON.stringify(error);
        }
    },
    mounted() {
        this.getSettings();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Social Login')"
                        :description="$t('Let people sign in with an account they already have.')"
                        :saving="saving" :disabled="!settings" @save="saveSettings()"/>

        <div class="fls_settings_content">
            <el-skeleton v-if="!settings || !auth_info" :animated="true" :rows="6"/>

            <el-form v-else label-position="top">
                <SettingsCard :title="$t('Social login')"
                              :description="$t('With this off, none of the sign-in buttons below appear on the login page, whatever their own switches say.')">
                    <template #actions>
                        <el-switch v-model="settings.enabled" active-value="yes" inactive-value="no"/>
                    </template>
                </SettingsCard>

                <template v-if="enabled">
                    <SocialProvider :settings="settings" provider="google"
                                    :title="$t('Google')"
                                    :description="$t('Needs an app you create in Google Cloud Console.')"
                                    :id-label="$t('Google Client ID')"
                                    :secret-label="$t('Google Client Secret')"
                                    :info="auth_info.google"
                                    :available="!!auth_info.google.is_available"
                                    :unavailable-note="$t('Google sign-in is not available on this server.')">
                        <template #extra>
                            <SettingToggle v-model="settings.google_one_tap"
                                           :label="$t('One-tap sign-in')"
                                           :description="$t('Google pops up its own sign-in prompt, so there is no button to press. Your site\'s address has to be listed under Authorized JavaScript origins in your Google app.')"/>
                        </template>
                    </SocialProvider>

                    <SocialProvider :settings="settings" provider="github"
                                    :title="$t('GitHub')"
                                    :description="$t('Needs an app from your GitHub developer settings.')"
                                    :id-label="$t('GitHub Client ID')"
                                    :secret-label="$t('GitHub Client Secret')"
                                    :info="auth_info.github"/>

                    <SocialProvider :settings="settings" provider="facebook"
                                    :title="$t('Facebook')"
                                    :description="$t('Needs an app from the Meta developer dashboard.')"
                                    :id-label="$t('Facebook App ID')"
                                    :secret-label="$t('Facebook App Secret')"
                                    :info="auth_info.facebook"/>
                </template>

                <div class="fls_errors" v-if="errors">
                    <ul>
                        <li v-for="(error, errorKey) in errors" :key="errorKey" v-html="convertToText(error)"></li>
                    </ul>
                </div>
            </el-form>
        </div>
    </div>
</template>
