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
                        <p>
                            {{ $t('Login activity is always recorded. The attempt limit, the audit log and the login notifications all read from it, so it is not something that can be switched off here.') }}
                        </p>

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
                                        {{$t('__login_try_limit_desc__', settings.login_try_limit, settings.login_try_timing, settings.login_try_timing)}}
                                    </p>
                                </el-form-item>
                            </el-col>
                        </el-row>
                    </div>

                    <div class="fls_login_settings">
                        <h3>{{ $t('Visitor IP Detection') }}</h3>
                        <p>
                            {{ $t('Cloudflare is detected and handled automatically. Only configure this if your site sits behind another reverse proxy (for example nginx in front of Apache, Varnish or a load balancer), otherwise every visitor may look like the same IP address.') }}
                        </p>

                        <el-alert v-if="proxy_config_locked" type="info" :closable="false" show-icon
                                  style="margin-bottom: 15px;">
                            {{ $t('These values are defined in wp-config.php and take precedence over the fields below.') }}
                        </el-alert>

                        <el-row :gutter="30">
                            <el-col :md="12" :sm="24">
                                <el-form-item :label="$t('Trusted proxy IP addresses or ranges')">
                                    <el-input type="textarea" :rows="3" v-model="settings.trusted_proxies"
                                              placeholder="127.0.0.1, 10.0.0.0/8"/>
                                    <p>
                                        {{ $t('One per line or comma separated. CIDR ranges and IPv6 are supported. Leave empty to always use the direct connection address, which cannot be spoofed.') }}
                                    </p>
                                </el-form-item>
                            </el-col>
                            <el-col :md="12" :sm="24">
                                <el-form-item :label="$t('Header the proxy sends the visitor IP in')">
                                    <el-input v-model="settings.proxy_ip_header" placeholder="X-Forwarded-For"/>
                                    <p>
                                        {{ $t('Defaults to X-Forwarded-For. This header is only read for requests arriving from one of the trusted proxies above.') }}
                                    </p>
                                </el-form-item>
                            </el-col>
                        </el-row>
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

                        <div class="fls_inner_group" :class="'fls_inner_group_' + settings.passkeys">
                            <el-form-item>
                                <el-checkbox v-model="settings.passkeys" true-label="yes" false-label="no">
                                    {{ $t('Enable Passkey Login') }}
                                </el-checkbox>
                            </el-form-item>
                            <template v-if="settings.passkeys == 'yes'">
                                <el-form-item>
                                    <el-checkbox v-model="settings.passkey_login_button" true-label="yes" false-label="no">
                                        {{ $t('Show passkey login button on login forms') }}
                                    </el-checkbox>
                                </el-form-item>
                                <el-form-item style="background: white; padding: 10px 20px;">
                                    <template #label>
                                        {{ $t('Passkey user verification') }}
                                    </template>
                                    <el-select v-model="settings.passkey_user_verification">
                                        <el-option :label="$t('Preferred')" value="preferred"></el-option>
                                        <el-option :label="$t('Required')" value="required"></el-option>
                                        <el-option :label="$t('Discouraged')" value="discouraged"></el-option>
                                    </el-select>
                                    <p>{{ $t('Passkeys require HTTPS or localhost. Required verification asks the authenticator for PIN, biometric, or equivalent device verification.') }}</p>
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

export default {
    name: 'Settings',
    components: {
        InfoFilled
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
                daily: this.$t('Daily'),
                sun: this.$t('Every Sunday'),
                mon: this.$t('Every Monday'),
                tue: this.$t('Every Tuesday'),
                wed: this.$t('Every Wednesday'),
                thu: this.$t('Every Thursday'),
                fri: this.$t('Every Friday'),
                sat: this.$t('Every Saturday'),
                monthly: this.$t('Every Month (1st day of every month)')
            },
            app_ready: false,
            proxy_config_locked: false
        }
    },
    methods: {
        fetchSettings() {
            this.loading = true;
            this.$get('settings')
                .then(response => {
                    console.log(response);
                    this.settings = response.settings;
                    this.user_roles = response.user_roles;
                    this.low_level_roles = response.low_level_roles;
                    this.proxy_config_locked = response.proxy_config_locked;
                    this.app_ready = true;
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
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
                passkeys: 'no',
                passkey_login_button: 'yes',
                passkey_user_verification: 'preferred',
                email2fa: 'yes',
                email2fa_roles: ['administrator', 'editor', 'author'],
                disable_admin_bar: 'yes',
                disable_bar_roles: ['subscriber'],
                // Server topology, not a preference - never overwrite it with a default.
                trusted_proxies: this.settings.trusted_proxies || '',
                proxy_ip_header: this.settings.proxy_ip_header || ''
            }
            this.$notify.success(this.$t('Recommended settings have been applied. Please review and save the settings.'));
        }
    },
    mounted() {
        this.fetchSettings();
    }
};
</script>
