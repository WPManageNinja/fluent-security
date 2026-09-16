<script type="text/babel">
import settingsPage from '../settingsPage';
import SettingsHeader from '../_SettingsHeader.vue';
import SettingsCard from '../_SettingsCard.vue';

import CoreSecuritySection from '../Sections/_CoreSecurity.vue';
import LoginSecuritySection from '../Sections/_LoginSecurity.vue';
import MagicLoginSection from '../Sections/_MagicLogin.vue';
import NotificationsSection from '../Sections/_Notifications.vue';
import AdvancedSection from '../Sections/_Advanced.vue';
import TwoFaSettings from '../../TwoFa/_TwoFaSettings.vue';
import ProxySettings from '../../_ProxySettings.vue';

/**
 * Every setting that lives in the one saved option, on one page.
 *
 * They are together because they are saved together - one Save button writes the whole
 * option - and split into separate routes they would each have had to load and post
 * the entire thing anyway. The sidebar scrolls between them instead.
 */
export default {
    name: 'GeneralSettings',
    mixins: [settingsPage],
    components: {
        SettingsHeader,
        SettingsCard,
        CoreSecuritySection,
        LoginSecuritySection,
        MagicLoginSection,
        NotificationsSection,
        AdvancedSection,
        TwoFaSettings,
        ProxySettings
    },
    methods: {
        applyRecommended() {
            /*
             * The recommendations come from the server, not from a literal here. They are
             * also what the security screen scores a site against, and this button used to
             * carry its own copy of them - which is exactly how the two came to disagree
             * about what a well configured site looks like. See
             * Helper::getRecommendedSettings(), which documents what it leaves out and why.
             *
             * Spread what is already saved first: saving replaces the whole option, so a
             * key missing from the result is a key erased.
             */
            this.settings = {
                ...this.settings,
                ...this.appVars.recommended_settings
            };

            this.$notify.success(this.$t('Recommended settings have been applied. Review the sections and save.'));
        }
    }
};
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Settings')"
                        :description="$t('Everything saved together, in one place.')"
                        :saving="saving" :disabled="!settings" @save="saveSettings()">
            <template #actions>
                <el-button link size="large" @click="applyRecommended()">
                    {{ $t('Apply recommended') }}
                </el-button>
            </template>
        </SettingsHeader>

        <div class="fls_settings_content">
            <el-skeleton v-if="!settings" :animated="true" :rows="8"/>

            <el-form v-else label-position="top">
                <SettingsCard id="core" :title="$t('Core Security')"
                                 :description="$t('The parts of WordPress that are open by default.')">
                    <CoreSecuritySection :settings="settings"/>
                </SettingsCard>

                <SettingsCard id="login_security" :title="$t('Login Security')"
                                 :description="$t('What happens when an address keeps getting the password wrong.')">
                    <LoginSecuritySection :settings="settings"/>
                </SettingsCard>

                <SettingsCard id="two_fa" :title="$t('Two-Factor Authentication')"
                                 :description="$t('A second proof of identity at sign-in. Each method says what it proves.')">
                    <TwoFaSettings :settings="settings" :user_roles="user_roles"/>
                </SettingsCard>

                <SettingsCard id="magic_login" :title="$t('Magic Login')"
                                 :description="$t('Signing in from an emailed link instead of a password.')">
                    <MagicLoginSection :settings="settings" :user_roles="user_roles"/>
                </SettingsCard>

                <SettingsCard id="notifications" :title="$t('Notifications')"
                                 :description="$t('What the plugin emails you about, and where it sends it.')">
                    <NotificationsSection :settings="settings" :user_roles="user_roles"/>
                </SettingsCard>

                <SettingsCard id="visitor_ip" :title="$t('Visitor IP')"
                                 :description="$t('Where a visitor\'s address is read from. The attempt limit counts per address.')">
                    <ProxySettings :settings="settings" :detection="proxy_detection"
                                   :config_locked="proxy_config_locked"/>
                </SettingsCard>

                <SettingsCard id="advanced" :title="$t('Advanced')"
                                 :description="$t('Log retention and admin area access.')">
                    <AdvancedSection :settings="settings" :low_level_roles="low_level_roles"/>
                </SettingsCard>
            </el-form>
        </div>
    </div>
</template>
