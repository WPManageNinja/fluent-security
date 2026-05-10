<template>
    <div class="fls_register_box">
        <h2>{{$t('Let\'s Secure your site by checking unauthorized changes of WP Core Files')}}</h2>
        <p style="border-bottom: 1px solid #dddfe6;padding-bottom: 20px;">
            {{$t('__free_api_desc__')}}
        </p>

        <div v-if="settings" class="fls_onboard_form">
            <el-form label-position="top" v-model="onboardForm">
                <template v-if="settings.status == 'unregistered' || settings.status == 'self'">
                    <el-row :gutter="30">
                        <el-col :md="12" sm="12" xs="24">
                            <el-form-item :label="$t('Your Name')" prop="full_name">
                                <el-input size="large" v-model="onboardForm.full_name" type="text"
                                          :placeholder="$t('Your Full Name')"/>
                            </el-form-item>
                        </el-col>
                        <el-col :md="12" sm="12" xs="24">
                            <el-form-item :label="$t('Your Email Address')" prop="email">
                                <el-input size="large" v-model="onboardForm.email" type="text"
                                          :placeholder="$t('Your Email')"/>
                            </el-form-item>
                        </el-col>
                    </el-row>
                    <el-form-item>
                        <el-button @click="registerSite" :loading="submitting" :disabled="submitting" size="large"
                                   type="primary">
                            {{ $t('Continue & Set API Key') }}
                        </el-button>
                    </el-form-item>
                    <p style="margin-top: 40px; font-size: 12px;">
                        <span v-html="$t('__api_key_form_consent__', `<a target=&quot;_blank&quot; rel=&quot;noopener&quot; style=&quot;color:#3c434a;&quot; href=&quot;https://fluentauth.com/privacy-policy/&quot;>` + $t('privacy policy and terms and conditions') + `</a>`)"></span>
                    </p>
                </template>
                <template v-else>
                    <h3>{{$t('The Last Step!')}}</h3>
                    <p>
                        <span v-html="$t('__api_key_email_sent__', settings.account_email_id)"></span>
                    </p>
                    <el-form-item>
                        <el-input size="large" :placeholder="$t('Provide API Key')" v-model="onboardForm.api_key"/>
                    </el-form-item>
                    <el-form-item>
                        <el-button @click="registerSite" :loading="submitting" :disabled="submitting" size="large"
                                   type="primary">
                            {{ $t('Start Scan Your Site') }}
                        </el-button>
                    </el-form-item>
                    <p style="margin-top: 40px; font-size: 12px;">
                        {{ $t('__api_key_spam_check__') }}
                        <a href="#" @click.prevent="startOver()">{{ $t('start over with a different email address') }}</a>.
                    </p>
                </template>
            </el-form>

            <template v-if="is_main">
                <hr style="margin-top: 20px"/>
                <p>
                    {{ $t('Or if you don\'t want automatic scanning with the API service,') }}
                    <a @click.prevent="processRegularScanService()" href="#">{{ $t('click here') }}</a>
                    {{ $t('to use the regular scan service.') }}
                </p>
            </template>
        </div>
        <div v-else-if="loading">
            <el-skeleton :animated="true" :rows="5"/>
        </div>
        <div v-else>
            <el-empty :description="$t('Sorry! Settings could not be loaded. Please reload the page')"/>
        </div>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'RegisterPrompt',
    props: ['pre_settings', 'is_main'],
    emits: ['registered'],
    data() {
        return {
            onboardForm: {
                full_name: '',
                email: '',
                api_key: '',
                api_id: ''
            },
            submitting: false,
            settings: null,
            loading: false
        }
    },
    methods: {
        getSettings() {
            this.loading = true;
            this.$get('security-scan-settings')
                .then(response => {
                    this.settings = response.settings;
                    this.onboardForm.api_key = response.settings.api_key;
                    this.onboardForm.api_id = response.settings.api_id;
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        registerSite() {
            if (!this.onboardForm.full_name || !this.onboardForm.email) {
                this.$notify.error(this.$t('Please provide valid name and email address'));
                return;
            }

            if (this.settings.status == 'pending' && !this.onboardForm.api_key) {
                this.$notify.error(this.$t('Please provide valid API key'));
                return;
            }

            if(this.settings.status == 'self') {
                this.settings.status = 'unregistered';
            }

            this.submitting = true;
            this.$post('security-scan-settings/register', {
                info: this.onboardForm,
                status: this.settings.status
            })
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings.status = response.settings.status;
                    this.settings.api_key = response.settings.api_key;
                    this.settings.api_id = response.settings.api_id;
                    this.settings.account_email_id = response.settings.account_email_id;
                    if (response.settings.status == 'active') {
                        this.$router.push({name: 'security_scans', query: {auto_scan: 'yes'}});
                        this.$emit('registered', response.settings);
                    }
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.submitting = false;
                });
        },
        startOver() {
            this.settings.status = 'unregistered';
            this.onboardForm.api_key = '';
            this.onboardForm.api_id = '';
            this.settings.api_id = '';
        },
        processRegularScanService() {
            this.submitting = true;
            this.$post('security-scan-settings/register', {
                status: 'self'
            })
                .then(response => {
                    this.$notify.success(response.message);
                    // reload the page
                    window.location.reload();
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.submitting = false;
                });
        }
    },
    mounted() {
        if (this.pre_settings) {
            this.settings = this.pre_settings;
            this.onboardForm.api_key = this.pre_settings.api_key;
            this.onboardForm.api_id = this.pre_settings.api_id;
        } else {
            this.getSettings();
        }

        this.onboardForm.full_name = this.appVars.me.full_name
        this.onboardForm.email = this.appVars.me.email
    }
}
</script>
