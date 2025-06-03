<template>
    <div class="dashboard box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div v-loading="loading" class="box_header" style="padding: 15px;font-size: 16px;">
                {{ $t('Social Login/Signup Settings') }}
                <div class="box_actions">

                </div>
            </div>
            <div v-if="settings" class="box_body">
                <el-form :data="settings" label-position="top">

                    <el-form-item class="fls_switch">
                        <el-switch v-model="settings.enabled" active-value="yes" inactive-value="no"/>
                        {{ $t('Enable Social Login / Signup') }}
                    </el-form-item>

                    <div v-if="settings.enabled == 'yes'" class="fls_login_settings">
                        <h3>{{$t('Login with Github Settings')}}</h3>
                        <el-form-item class="fls_switch">
                            <el-switch v-model="settings.enable_github" active-value="yes" inactive-value="no"/>
                            {{ $t('Enable Login with Github') }}
                        </el-form-item>
                        <template v-if="settings.enable_github == 'yes'">
                            <el-form-item :label="$t('Credential Storage Method')">
                                <el-radio-group v-model="settings.github_key_method">
                                    <el-radio-button :label="$t('Database')" value="db" />
                                    <el-radio-button label="wp-config" value="wp_config" />
                                </el-radio-group>
                            </el-form-item>
                            <div class="fls_code_instruction" v-if="settings.github_key_method == 'wp_config'">
                                <h3>{{$t('__wp_config_instruction__')}}</h3>
                                <textarea readonly>define('FLUENT_AUTH_GITHUB_CLIENT_ID', '******');
define('FLUENT_AUTH_GITHUB_CLIENT_SECRET', '******');
                                </textarea>
                            </div>
                            <template v-else>
                                <el-form-item :label="$t('Github Client ID')">
                                    <el-input v-model="settings.github_client_id" type="text"
                                              :placeholder="$t('Github Client ID')"/>
                                </el-form-item>
                                <el-form-item :label="$t('Github Client Secret')">
                                    <el-input v-model="settings.github_client_secret" type="password"
                                              :placeholder="$t('Github Client Secret')"/>
                                </el-form-item>
                            </template>
                            <p>{{$t('Please set your Github app Redirect URL:')}} <code>{{auth_info.github.app_redirect}}</code>. {{$t('For more information how to setup Github app for social authentication please')}} <a target="_blank" rel="noopener" :href="auth_info.github.doc_url">{{$t('read this documentation')}}.</a></p>
                        </template>
                    </div>

                    <div v-if="settings.enabled == 'yes'" class="fls_login_settings">
                        <h3>{{ $t('Login with Google Settings') }}</h3>
                        <el-form-item class="fls_switch">
                            <el-switch :disabled="!auth_info.google.is_available" v-model="settings.enable_google" active-value="yes" inactive-value="no"/>
                            {{ $t('Enable Login with Google') }}
                        </el-form-item>
                        <template v-if="settings.enable_google == 'yes'">
                            <el-form-item :label="$t('Credential Storage Method')">
                                <el-radio-group v-model="settings.google_key_method">
                                    <el-radio-button value="db" :label="$t('Database')" />
                                    <el-radio-button value="wp_config" label="wp-config" />
                                </el-radio-group>
                            </el-form-item>
                            <div class="fls_code_instruction" v-if="settings.google_key_method == 'wp_config'">
                                <h3>{{$t('Please add the following code in your wp-config.php file (please replace the *** with your app values)')}}</h3>
                                <textarea readonly>define('FLUENT_AUTH_GOOGLE_CLIENT_ID', '******');
define('FLUENT_AUTH_GOOGLE_CLIENT_SECRET', '******');
                                </textarea>
                            </div>
                            <template v-else>
                                <el-form-item :label="$t('Google Client ID')">
                                    <el-input v-model="settings.google_client_id" type="text"
                                              :placeholder="$t('Google Client ID')"/>
                                </el-form-item>
                                <el-form-item :label="$t('Google Client Secret')">
                                    <el-input v-model="settings.google_client_secret" type="password"
                                              :placeholder="$t('Google Client Secret')"/>
                                </el-form-item>
                            </template>
                            <p>{{$t('Please set your Google app Redirect URL:')}} <code>{{auth_info.google.app_redirect}}</code>. {{$t('For more information how to setup google app for social authentication please')}} <a target="_blank" rel="noopener" :href="auth_info.google.doc_url">{{$t('read this documentation')}}.</a></p>
                        </template>
                    </div>

                   <div v-if="settings.enabled == 'yes'" class="fls_login_settings">
                    <h3>{{ $t('Login with Facebook Settings') }}</h3>
                    <el-form-item class="fls_switch">
                      <el-switch v-model="settings.enable_facebook" active-value="yes" inactive-value="no"/>
                      {{ $t('Enable Login with Facebook') }}
                    </el-form-item>
                    <template v-if="settings.enable_facebook == 'yes'">
                      <el-form-item :label="$t('Credential Storage Method')">
                        <el-radio-group v-model="settings.facebook_key_method">
                          <el-radio-button value="db" :label="$t('Database')" />
                          <el-radio-button value="wp_config" label="wp-config" />
                        </el-radio-group>
                      </el-form-item>
                      <div class="fls_code_instruction" v-if="settings.facebook_key_method == 'wp_config'">
                        <h3>{{$t('Please add the following code in your wp-config.php file (please replace the *** with your app values)')}}</h3>
                        <textarea readonly>define('FLUENT_AUTH_FACEBOOK_CLIENT_ID', '******');
define('FLUENT_AUTH_FACEBOOK_CLIENT_SECRET', '******');
                                </textarea>
                      </div>
                      <template v-else>
                        <el-form-item :label="$t('Facebook App ID')">
                          <el-input v-model="settings.facebook_client_id" type="text"
                                    :placeholder="$t('Facebook App ID')"/>
                        </el-form-item>
                        <el-form-item :label="$t('Facebook App Secret')">
                          <el-input v-model="settings.facebook_client_secret" type="password"
                                    :placeholder="$t('Facebook App Secret')"/>
                        </el-form-item>
                        <el-form-item :label="$t('Facebook API Version')">
                          <el-input v-model="settings.facebook_api_version" type="text"
                                    :placeholder="$t('e.g. v12.0')"/>
                        </el-form-item>
                      </template>
                      <p>{{$t('Please set your Facebook app Redirect URL:')}} <code>{{auth_info.facebook.app_redirect}}</code>. {{$t('For more information how to setup Facebook app for social authentication please')}} <a target="_blank" rel="noopener" :href="auth_info.facebook.doc_url">{{$t('read this documentation')}}.</a></p>
                    </template>
                  </div>

                    <el-form-item>
                        <el-button v-loading="saving" :disabled="saving" @click="saveSettings()" type="success">
                            {{ $t('Save Settings') }}
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
export default {
    name: 'SocialAuthSettings',
    data() {
        return {
            loading: false,
            settings: false,
            saving: false,
            errors: false,
            auth_info: false
        }
    },
    methods: {
        saveSettings() {
            this.errors = false;
            this.saving = false;
            this.$post('social-auth-settings', {
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
            this.$get('social-auth-settings')
                .then(response => {
                    this.settings = response.settings
                    this.auth_info = response.auth_info
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
