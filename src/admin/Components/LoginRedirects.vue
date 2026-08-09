<script type="text/babel">
import RedirectRule from './_RedirectRule';
import SettingsHeader from './Settings/_SettingsHeader.vue';
import SettingsCard from './Settings/_SettingsCard.vue';
import SettingRow from './Settings/_SettingRow.vue';
import {Delete} from '@element-plus/icons-vue'
import {markRaw} from 'vue';

export default {
    name: 'LoginRedirectSettings',
    components: {RedirectRule, SettingsHeader, SettingsCard, SettingRow},
    data() {
        return {
            loading: false,
            Delete: markRaw(Delete),
            settings: false,
            conditionProviders: {
                user_role: {
                    title: this.$t('User Role'),
                    type: 'role_selector',
                    is_multiple: true
                },
                user_capability: {
                    title: this.$t('User Capability'),
                    type: 'capability_selector',
                    is_multiple: true
                }
            },
            saving: false,
            errors: false,
            roles: {},
            user_capabilities: {}
        }
    },
    computed: {
        enabled() {
            return this.settings && this.settings.login_redirects === 'yes';
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

            this.$post('auth-forms-settings', {redirect_settings: this.settings})
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
                    this.user_capabilities = response.user_capabilities;
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        addNewRule() {
            this.settings.redirect_rules.push({
                conditions: [
                    {
                        condition: 'user_role',
                        operator: 'in',
                        values: []
                    }
                ],
                login: '',
                logout: ''
            });
        },
        deleteRule(index) {
            this.settings.redirect_rules.splice(index, 1);
        }
    },
    mounted() {
        this.getSettings();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Login Redirects')"
                        :description="$t('Where people land after signing in and after signing out.')"
                        :saving="saving" :disabled="!settings" @save="saveSettings()"/>

        <div class="fls_settings_content">
            <el-skeleton v-if="!settings" :animated="true" :rows="6"/>

            <el-form v-else label-position="top">
                <SettingsCard :title="$t('Custom redirects')"
                              :description="$t('With this off, WordPress decides where people go, which is usually the dashboard.')">
                    <template #actions>
                        <el-switch v-model="settings.login_redirects" active-value="yes" inactive-value="no"/>
                    </template>
                </SettingsCard>

                <template v-if="enabled">
                    <SettingsCard :title="$t('Default destinations')"
                                  :description="$t('Used for anyone no rule below applies to. A redirect_to parameter on the login URL still wins over both.')">
                        <SettingRow :label="$t('After signing in')">
                            <el-input type="url" v-model="settings.default_login_redirect"
                                      :placeholder="appVars.site_url"/>
                        </SettingRow>

                        <SettingRow :label="$t('After signing out')">
                            <el-input type="url" v-model="settings.default_logout_redirect"
                                      :placeholder="appVars.site_url"/>
                        </SettingRow>
                    </SettingsCard>

                    <SettingsCard :title="$t('Rules')"
                                  :description="$t('Send particular people somewhere else. The first rule that matches is the one used, so put the most specific first.')">
                        <template #actions>
                            <el-button size="small" @click="addNewRule()">{{ $t('Add rule') }}</el-button>
                        </template>

                        <p v-if="!settings.redirect_rules.length" class="fls_note">
                            {{ $t('No rules yet. Everyone follows the defaults above.') }}
                        </p>

                        <div v-for="(rule, ruleIndex) in settings.redirect_rules" :key="ruleIndex"
                             class="fls_rule">
                            <div class="fls_rule_head">
                                <span class="fls_rule_number">{{ $t('Rule %s', ruleIndex + 1) }}</span>
                                <el-button :text="true" :icon="Delete" size="small"
                                           @click="deleteRule(ruleIndex)">
                                    {{ $t('Remove') }}
                                </el-button>
                            </div>

                            <redirect-rule v-for="(ruleItem, ruleItemIndex) in rule.conditions"
                                           :rule="ruleItem"
                                           :providers="conditionProviders"
                                           :roles="roles"
                                           :capabilities="user_capabilities"
                                           :key="ruleItemIndex"/>

                            <div class="fls_then">{{ $t('then send them to') }}</div>

                            <el-row :gutter="20">
                                <el-col :md="12" :xs="24">
                                    <el-form-item :label="$t('After signing in')">
                                        <el-input type="url" v-model="rule.login" :placeholder="appVars.site_url"/>
                                    </el-form-item>
                                </el-col>
                                <el-col :md="12" :xs="24">
                                    <el-form-item :label="$t('After signing out')">
                                        <el-input type="url" v-model="rule.logout" :placeholder="appVars.site_url"/>
                                    </el-form-item>
                                </el-col>
                            </el-row>
                        </div>
                    </SettingsCard>
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
