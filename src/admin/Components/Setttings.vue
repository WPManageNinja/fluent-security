<template>
    <div class="dashboard box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div v-loading="loading" class="box_header" style="padding: 15px;font-size: 16px;">
                {{ $t('Settings') }}
                <div class="box_actions">
                    <el-button @click="applyRecommended()" size="small">{{ $t('Apply recommended settings') }}</el-button>
                </div>
            </div>
            <div v-if="settings" class="box_body">
                <el-form :data="settings" label-position="top">
                    <div class="fls_login_settings">
                        <h3>{{ $t('Core Security Settings') }}</h3>
                        <el-form-item>
                            <el-checkbox true-label="yes" false-label="no" v-model="settings.disable_xmlrpc">
                                {{ $t('Disable XML-RPC (Most of the sites don\'t need XMLRPC)') }}
                            </el-checkbox>
                        </el-form-item>
                        <el-form-item>
                            <el-checkbox true-label="yes" false-label="no" v-model="settings.disable_app_login">
                                {{ $t('Disable App Login (Rest API) for Remote Access. (Recommended: Disable)') }}
                            </el-checkbox>
                        </el-form-item>
                        <el-form-item>
                            <el-checkbox true-label="yes" false-label="no" v-model="settings.disable_users_rest">
                                {{ $t('Disable REST Endpoint for wp users query for public (Recommended: Disable)') }}
                            </el-checkbox>
                        </el-form-item>

                        <el-form-item>
                            <el-checkbox true-label="yes" false-label="no" v-model="settings.secure_signup_form">
                                {{ $t('Replace Default Signup Form with Secure form with Email Verfication (Recommended: Enable)') }}
                            </el-checkbox>
                        </el-form-item>
                    </div>

                    <div class="fls_login_settings">
                        <h3>{{ $t('Login Security Settings') }}</h3>
                        <el-form-item class="fls_switch">
                            <el-switch v-model="settings.enable_auth_logs" active-value="yes" inactive-value="no"/>
                            {{ $t('Enable Login Security and Login Limit (recommended)') }}
                        </el-form-item>
                        <p v-if="settings.enable_auth_logs !== 'yes'" style="color: red;">
                            {{ $t('We recommend to enable login logs as well as set login try limit') }}
                        </p>

                        <template v-else>
                            <el-row :gutter="30">
                                <el-col :md="12" :sm="24">
                                    <el-form-item :label="$t('Login Try Limit per IP address in certain defined minutes')">
                                        <el-input type="number" v-model="settings.login_try_limit"/>
                                        <p>{{ $t('How many times user can try login in') }} {{ settings.login_try_timing }} {{ $t('minutes') }}</p>
                                    </el-form-item>
                                </el-col>
                                <el-col :md="12" :sm="24">
                                    <el-form-item :label="$t('Time limit for login try in minutes')">
                                        <el-input type="number" v-model="settings.login_try_timing"/>
                                        <p>
                                            {{$t('If a user fails to log in %1s times within %2s minutes minutes, the system will block the user for %3s minutes.', settings.login_try_limit, settings.login_try_timing, settings.login_try_timing)}}
                                        </p>
                                    </el-form-item>
                                </el-col>
                            </el-row>
                        </template>
                    </div>

                    <div class="fls_login_settings">
                        <h3>{{ $t('Extended Login Options') }}</h3>

                        <div class="fls_inner_group" :class="'fls_inner_group_' + settings.magic_login">
                            <el-form-item>
                                <el-checkbox v-model="settings.magic_login" true-label="yes" false-label="no">
                                    {{ $t('Enable Magic Login (User can login via url sent to email)') }}
                                </el-checkbox>
                            </el-form-item>
                            <template v-if="settings.magic_login == 'yes'">
                                <el-form-item style="background: white; padding: 10px 20px;">
                                    <template #label>
                                        {{ $t('Disable Magic Login for specific user roles (Leave blank to enable magic login for all users)') }}
                                    </template>
                                    <el-select :placeholder="$t('Select disable roles')" clearable
                                               v-model="settings.magic_restricted_roles" :multiple="true">
                                        <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                                   :key="role.id"></el-option>
                                    </el-select>
                                </el-form-item>
                                <el-form-item>
                                    <el-checkbox true-value="yes" false-value="no" v-model="settings.magic_link_primary">
                                        {{ $t('Make magic login as primary login method') }}
                                    </el-checkbox>
                                </el-form-item>
                            </template>
                        </div>

                        <div class="fls_inner_group" :class="'fls_inner_group_' + settings.email2fa">
                            <el-form-item>
                                <el-checkbox v-model="settings.email2fa" true-label="yes" false-label="no">
                                    {{ $t('Enable Two-Factor Authentication via Email') }}
                                </el-checkbox>
                            </el-form-item>
                            <el-form-item style="background: white; padding: 10px 20px;"
                                          v-if="settings.email2fa == 'yes'">
                                <template #label>
                                    {{ $t('Select Roles that requires Two-Factor Authentication') }}
                                </template>
                                <el-select :placeholder="$t('Enabled for all user roles')" clearable
                                           v-model="settings.email2fa_roles" :multiple="true">
                                    <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                               :key="role.id"></el-option>
                                </el-select>
                            </el-form-item>
                        </div>

                    </div>

                    <div class="fls_login_settings">
                        <h3>{{ $t('Other Settings') }}</h3>

                        <el-row :gutter="30">
                            <el-col :sm="24" :md="12">
                                <el-form-item>
                                    <template #label>
                                        {{ $t('Send Email notification if any of the following user roles login') }}
                                    </template>
                                    <el-select clearable v-model="settings.notification_user_roles" :multiple="true">
                                        <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                                   :key="role.id"></el-option>
                                    </el-select>
                                </el-form-item>
                            </el-col>
                            <el-col :sm="24" :md="12">
                                <el-form-item
                                    v-if="settings.notification_user_roles.length || settings.notify_on_blocked == 'yes' || settings.digest_summary">
                                    <template #label>
                                        {{ $t('Notification Send to Email Address') }}
                                        <el-tooltip
                                            class="box-item"
                                            effect="dark"
                                            :content="$t('For multiple emails, please use comma separated values')"
                                            placement="top"
                                        >
                                            <el-icon>
                                                <InfoFilled/>
                                            </el-icon>
                                        </el-tooltip>
                                    </template>
                                    <el-input type="text" v-model="settings.notification_email"></el-input>
                                    <p></p>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-row :gutter="30">
                            <el-col :sm="24" :md="12">
                                <el-form-item class="fls_switch">
                                    <el-switch v-model="settings.notify_on_blocked" active-value="yes"
                                               inactive-value="no"/>
                                    {{ $t('Send email notification when a user get blocked') }}
                                </el-form-item>
                                <el-form-item :label="$t('Send Digest Email Report Summary')">
                                    <el-select v-model="settings.digest_summary">
                                        <el-option value="" :label="$t('Do not send digest email summary')"></el-option>
                                        <el-option v-for="(day, dayName) in digest_items" :value="dayName" :label="day"></el-option>
                                    </el-select>
                                </el-form-item>
                            </el-col>
                            <el-col :sm="24" :md="12">
                                <el-form-item>
                                    <template #label>
                                        {{ $t('Automatically delete logs older than (in days)') }}
                                        <el-tooltip
                                            class="box-item"
                                            effect="dark"
                                            :content="$t('Use 0 if you do not want to delete the logs')"
                                            placement="top"
                                        >
                                            <el-icon>
                                                <InfoFilled/>
                                            </el-icon>
                                        </el-tooltip>
                                    </template>
                                    <el-input v-model="settings.auto_delete_logs_day" type="number" :min="0"/>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <hr style="margin-bottom: 15px;"/>

                        <el-row :gutter="30">
                            <el-col :sm="24" :md="12">
                                <el-form-item class="fls_switch fls_checkbox">
                                    <el-switch v-model="settings.disable_admin_bar" active-value="yes"
                                               inactive-value="no"/>
                                    <span v-html="$t('Disable admin bar and %s access for selected user roles.', '<code>/wp-admin/</code>')"></span>
                                </el-form-item>
                            </el-col>
                            <el-col :sm="24" :md="12">
                                <el-form-item v-if="settings.disable_admin_bar == 'yes'">
                                    <template #label>
                                        <span v-html="$t('Roles to disable %s access and hide admin bar', '<code>wp-admin</code>')"></span>
                                    </template>
                                    <el-select clearable v-model="settings.disable_bar_roles" :multiple="true">
                                        <el-option v-for="(role, roleId) in low_level_roles" :value="roleId"
                                                   :label="role"
                                                   :key="roleId"></el-option>
                                    </el-select>
                                </el-form-item>
                            </el-col>
                        </el-row>

                    </div>

                    <div class="fls_login_settings">
                        <h3>{{ $t('Custom CSS') }}</h3>
                        <div>
                            <v-ace-editor
                                v-model:value="settings.custom_css"
                                @init="editorInit"
                                lang="css"
                                theme="monokai"
                                style="height: 350px" />
                        </div>
                        <p style="color: #666; font-size: 13px; margin: 10px 0;">
                            {{ $t('Add your custom CSS here. This will be applied to the login pages. Don\'t add the <style> tag') }}
                        </p>
                    </div>

                    <el-form-item>
                        <el-button size="large" @click="saveSettings()" :disabled="saving" v-loading="saving"
                                   type="success">
                            {{ $t('Save Settings') }}
                        </el-button>
                    </el-form-item>

                    <div class="fls_errors" v-if="errors">
                        <ul>
                            <li v-for="(error, errorKey) in errors" :key="errorKey">{{ convertToText(error) }}</li>
                        </ul>
                    </div>

                </el-form>
            </div>
            <div v-else-if="loading" class="box_body">
                <el-skeleton :animated="true" :rows="4"/>
                <el-skeleton :animated="true" :rows="4"/>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
import {InfoFilled} from '@element-plus/icons-vue'
import { VAceEditor } from 'vue3-ace-editor';

export default {
    name: 'Settings',
    components: {
        InfoFilled,
        VAceEditor
    },

    data() {
        return {
            settings: false,
            plugins: [],
            loading: false,
            activated: false,
            saving: false,
            errors: false,
            user_roles: [],
            low_level_roles: {},
            digest_items: {
                daily: 'Daily',
                sun: 'Every Sunday',
                mon: 'Every Monday',
                tue: 'Every Tuesday',
                wed: 'Every Wednesday',
                thu: 'Every Thursday',
                fri: 'Every Friday',
                sat: 'Every Saturday',
                monthly: 'Every Month (1st day of every month)'
            },
            app_ready: false
        }
    },
    methods: {
        editorInit(editor) {
            editor.setOptions({
                fontSize: "13px",
                showLineNumbers: true,
                tabSize: 2
            });
            
            editor.session.setMode("ace/mode/css");
            
            if (this.settings && this.settings.custom_css) {
                editor.session.setValue(this.settings.custom_css);
            }

            editor.session.on('change', () => {
                if (this.settings) {
                    this.settings.custom_css = editor.session.getValue();
                }
            });
        },
        fetchSettings() {
            this.loading = true;
            this.$get('settings')
                .then(response => {
                    this.settings = response.settings;
                    this.user_roles = response.user_roles;
                    this.low_level_roles = response.low_level_roles;
                    this.app_ready = true;
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
                    console.log(this.settings);
                });
        },
        saveSettings() {
            this.errors = false;
            this.saving = false;
            this.$post('settings', {
                settings: this.settings
            })
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings = response.settings;
                    this.appVars.auth_settings = response.settings;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                    this.errors = errors.data;
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        applyRecommended() {
            this.settings = {
                disable_xmlrpc: 'yes',
                disable_app_login: 'no',
                enable_auth_logs: 'yes',
                login_try_limit: 5,
                login_try_timing: 30,
                disable_users_rest: 'yes',
                auto_delete_logs_day: 30,
                secure_signup_form: 'yes',
                notification_user_roles: ['administrator', 'editor', 'author'],
                notification_email: '{admin_email}',
                notify_on_blocked: 'no',
                magic_login: 'no',
                magic_restricted_roles: [],
                magic_link_primary: 'no',
                email2fa: 'yes',
                email2fa_roles: ['administrator', 'editor', 'author'],
                disable_admin_bar: 'yes',
                disable_bar_roles: ['subscriber']
            }
            this.$notify.success('Recommended settings has been applied. Please review and save the settings');
        }
    },
    mounted() {
        this.fetchSettings();
    }
};
</script>
