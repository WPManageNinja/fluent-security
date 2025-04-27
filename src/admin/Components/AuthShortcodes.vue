<template>
    <auth-customizer-settings />
    <social-auth-settings />
    <div class="dashboard box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div v-loading="loading" class="box_header" style="padding: 15px;font-size: 16px;">
                {{$t('Login or Signup Forms Shortcodes')}}
                <div class="box_actions">
                    <el-button size="small" v-loading="saving" :disabled="saving" @click="saveSettings()" type="success">
                        {{$t('Save Settings')}}
                    </el-button>
                </div>
            </div>
            <div v-if="settings" class="box_body">
                <el-form :data="settings" label-position="top">
                    <el-form-item class="fls_switch">
                        <el-switch v-model="settings.enabled" active-value="yes" inactive-value="no"/>
                        {{$t('Enable Custom Login / Signup Shortcodes')}}
                    </el-form-item>

                    <div v-if="settings.enabled == 'yes'" class="fls_login_settings">
                        <div class="fls_shortcode_section">
                            <h3>{{$t('Full Authentication Flow ShortCode (includes Login Form, Registration Form and Password Reset Form)')}}</h3>
                            <textarea readonly>[fluent_auth]</textarea>
                            <p class="help">{{$t('If you want to define customized redirect URL then use shortcode:')}} <code>[fluent_auth redirect_to="your_URL"]</code></p>
                        </div>
                        <div class="fls_shortcode_section">
                            <h3>{{$t('Only Registration Form ShortCode')}}</h3>
                            <textarea readonly>[fluent_auth_signup]</textarea>
                            <p class="help">{{$t('If you want to define customized redirect URL then use shortcode:')}} <code>[fluent_auth_signup redirect_to="your_URL"]</code></p>
                        </div>
                        <div class="fls_shortcode_section">
                            <h3>{{$t('Only Login Form ShortCode')}}</h3>
                            <textarea readonly>[fluent_auth_login]</textarea>
                            <p class="help">{{$t('If you want to define customized redirect URL then use shortcode:')}} <code>[fluent_auth_login redirect_to="your_URL"]</code></p>
                        </div>
                        <div class="fls_shortcode_section">
                            <h3>{{$t('Password Reset Form ShortCode')}}</h3>
                            <textarea readonly>[fluent_auth_reset_password]</textarea>
                            <p class="help">{{$t('If you want to define customized redirect URL then use shortcode:')}} <code>[fluent_auth_reset_password redirect_to="your_URL"]</code></p>
                        </div>

                        <div class="fls_shortcode_section">
                            <h3>{{$t('Magic Login Form Shortcode')}}</h3>
                            <textarea readonly>[fluent_auth_magic_login]<h3>Type your email address to get login</h3>[/fluent_auth_magic_login]</textarea>
                            <p class="help">{{$t('You may remove the h3 content or change it. If you want to define customized redirect URL then use shortcode:')}} <code>[fluent_auth_magic_login redirect_to="your_URL"]</code></p>
                        </div>
                    </div>

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
import SocialAuthSettings from "./SocialAuthSettings.vue";
import AuthCustomizerSettings from "./AuthCustomizer/AuthCustomizerSettings.vue";
export default {
    name: 'AuthShortcodes',
    components : {
        SocialAuthSettings,
        AuthCustomizerSettings
    },
    data() {
        return {
            loading: false,
            settings: false,
            saving: false,
            errors: false,
            roles: {}
        }
    },
    methods: {
        saveSettings() {
            this.errors = false;
            this.saving = false;
            this.$post('auth-forms-settings', {
                settings: this.settings
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
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
                });
        }
    },
    mounted() {
        this.getSettings();
    }
}
</script>
