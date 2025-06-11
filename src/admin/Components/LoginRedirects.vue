<template>
    <div class="dashboard box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div v-loading="loading" class="box_header" style="padding: 15px;font-size: 16px;">
                {{$t('Login Redirects Settings')}}
                <div class="box_actions">
                    <el-button size="small" v-loading="saving" :disabled="saving" @click="saveSettings()"
                               type="success">
                        {{$t('Save Settings')}}
                    </el-button>
                </div>
            </div>
            <div v-if="settings" class="box_body">
                <el-form :data="settings" label-position="top">

                    <el-form-item class="fls_switch">
                        <el-switch v-model="settings.login_redirects" active-value="yes" inactive-value="no"/>
                        {{$t('Enable Custom Login Redirects')}}
                    </el-form-item>

                    <template v-if="settings.login_redirects == 'yes'">
                        <div class="fls_login_settings">
                            <el-row :gutter="20">
                                <el-col :md="12" :xs="24">
                                    <el-form-item :label="$t('Default Login Redirect URL')">
                                        <el-input type="url" :placeholder="$t('Default Login Redirect URL')"
                                                  v-model="settings.default_login_redirect"/>
                                    </el-form-item>
                                </el-col>
                                <el-col :md="12" :xs="24">
                                    <el-form-item :label="$t('Default Logout Redirect URL')">
                                        <el-input type="url" :placeholder="$t('Default Logout Redirect URL')"
                                                  v-model="settings.default_logout_redirect"/>
                                    </el-form-item>
                                </el-col>
                            </el-row>

                            <p style="margin-bottom: 10px;">
                                {{$t('Please note, If there has redirect_to query parameter in the Login Page URL, it will be used for redirection instead of these set rule.')}}
                            </p>
                        </div>



                        <h3>{{$t('Advanced Redirect Rules')}}</h3>
                        <div class="fls_advanced_rules">
                            <div v-for="(rule, ruleIndex) in settings.redirect_rules" :key="ruleIndex"
                                 class="fls_rule_group">
                                <div class="fls_rule_number">
                                    <span class="fls_number">#{{ ruleIndex + 1 }}</span>
                                    <el-button :text="true" @click="deleteRule(ruleIndex)" :icon="Delete" size="small"></el-button>
                                </div>
                                <redirect-rule v-for="(ruleItem, ruleItemIndex) in rule.conditions"
                                               :rule="ruleItem"
                                               :providers="conditionProviders"
                                               :roles="roles"
                                               :capabilities="user_capabilities"
                                               :key="ruleItemIndex"/>
                                <div class="fls_then_arrow">{{$t('then')}}</div>
                                <el-row style="margin-top: 20px;" :gutter="20">
                                    <el-col :md="12" :xs="24">
                                        <el-form-item :label="$t('Login Redirect URL')">
                                            <el-input type="url" :placeholder="$t('Login Redirect URL')" v-model="rule.login"/>
                                        </el-form-item>
                                    </el-col>
                                    <el-col :md="12" :xs="24">
                                        <el-form-item :label="$t('Logout Redirect URL')">
                                            <el-input type="url" :placeholder="$t('Logout Redirect URL')"
                                                      v-model="rule.logout"/>
                                        </el-form-item>
                                    </el-col>
                                </el-row>
                            </div>
                        </div>
                        <div style="margin-bottom: 20px;" class="fls_controls text-align-right">
                            <el-button type="default" size="small" @click="addNewRule()">{{$t('Add Rule')}}</el-button>
                        </div>
                        <hr style="margin-bottom: 20px"/>
                    </template>

                    <el-form-item>
                        <el-button v-loading="saving" :disabled="saving" @click="saveSettings()" type="success">
                            {{$t('Save Settings')}}
                        </el-button>
                    </el-form-item>

                    <div class="fls_errors" v-if="errors">
                        <ul>
                            <li v-for="(error, errorKey) in errors" :key="errorKey" v-html="convertToText(error)"></li>
                        </ul>
                    </div>
                </el-form>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
import RedirectRule from './_RedirectRule';
import {Delete} from '@element-plus/icons-vue'
import {markRaw} from 'vue';

export default {
    name: 'LoginRedirectSettings',
    components: {
        RedirectRule
    },
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
    methods: {
        saveSettings() {
            this.errors = false;
            this.saving = false;
            this.$post('auth-forms-settings', {
                redirect_settings: this.settings
            })
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
                    this.settings = response.settings
                    this.roles = response.roles
                    this.user_capabilities = response.user_capabilities
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
