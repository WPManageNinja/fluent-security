<script type="text/babel">
import SettingRow from '../_SettingRow.vue';
import SettingToggle from '../_SettingToggle.vue';
import InlineSentence from '../_InlineSentence.vue';

export default {
    name: 'SessionsSection',
    components: {SettingRow, SettingToggle, InlineSentence},
    props: {
        settings: {type: Object, required: true},
        userRoles: {type: Array, default: () => []}
    },
    computed: {
        persistentRoles: {
            get() { return Array.isArray(this.settings.persistent_login_roles) ? this.settings.persistent_login_roles : []; },
            set(roles) { this.settings.persistent_login_roles = roles.length ? roles : ''; }
        }
    }
};
</script>

<template>
    <div>
        <SettingRow :description="$t('Closing the browser also signs people out, unless the browser reopens the last session.')">
            <template #label>
                <!-- translators: %s is a number field for days -->
                <InlineSentence :text="$t('If Remember Me is off, sign people out after %s days')">
                    <template #field1>
                        <el-input type="number" :min="1" :max="365" v-model="settings.session_days"/>
                    </template>
                </InlineSentence>
            </template>
        </SettingRow>

        <SettingRow :description="$t('Sign-ins with Google, GitHub, Facebook or a passkey always use this length. So do new accounts after sign-up.')">
            <template #label>
                <!-- translators: %s is a number field for days -->
                <InlineSentence :text="$t('If Remember Me is on, keep people signed in for %s days')">
                    <template #field1>
                        <el-input type="number" :min="1" :max="365" v-model="settings.remember_days"/>
                    </template>
                </InlineSentence>
            </template>
        </SettingRow>

        <SettingToggle v-model="settings.remember_default"
                       :label="$t('Check Remember Me by default')"
                       :description="$t('Magic links follow this choice too. On a login form, people can still uncheck the box.')"/>

        <SettingToggle v-model="settings.persistent_login" :label="$t('Persistent login')"
                       :description="$t('Use a fixed duration even when Remember Me is off.')">
            <div v-if="settings.persistent_login === 'yes'">
                <SettingRow :label="$t('Session duration')">
                    <el-select v-model="settings.persistent_login_days" :aria-label="$t('Session duration')">
                        <!-- translators: %s is the number of days -->
                        <el-option v-for="days in [30, 90, 180]" :key="days" :value="days" :label="$t('%s days', days)"/>
                    </el-select>
                </SettingRow>
                <SettingRow :label="$t('Apply to')">
                    <el-select v-model="settings.persistent_login_scope" :aria-label="$t('Apply to')">
                        <el-option value="selected" :label="$t('Selected roles')"/>
                        <el-option value="all" :label="$t('All users')"/>
                    </el-select>
                </SettingRow>
                <SettingRow v-if="settings.persistent_login_scope === 'selected'" :label="$t('Selected roles')"
                            :description="$t('An empty selection applies to nobody. A person with any selected role is included.')">
                    <el-select v-model="persistentRoles" multiple :aria-label="$t('Selected roles')">
                        <el-option v-for="role in userRoles" :key="role.id" :value="role.id" :label="role.title"/>
                    </el-select>
                </SettingRow>
                <SettingToggle v-model="settings.persistent_login_renew" :label="$t('Renew while active')"
                               :disabled="settings.persistent_renewal_supported === false"
                               :description="$t('Renew at most once a day on page visits. Active users can stay signed in indefinitely. Background requests do not renew a session.')"/>
                <p v-if="settings.persistent_renewal_supported === false" class="fls_note">
                    {{ $t('Renewal is unavailable while another plugin manages login sessions. Fixed-duration persistence still applies.') }}
                </p>
            </div>
        </SettingToggle>

        <p class="fls_note">
            <template v-if="settings.persistent_login === 'yes'">
                {{ $t('Changes apply to the next sign-in or renewal. Switching this policy off stops renewals but does not sign people out.') }}
            </template>
            <template v-else>
                {{ $t('Changes apply to the next sign-in. People who are signed in now keep their current session.') }}
            </template>
        </p>
    </div>
</template>
