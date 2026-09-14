<script type="text/babel">
import icons from './icons';

/*
 * Getting the free API key that the scanning service needs.
 *
 * Two ways in, and the same form either way: inline on the scans screen when the site has
 * never registered, and on its own route when someone goes back to change the address the
 * alerts are sent to. `is_main` says which - inline it is one card in a column that already
 * has a heading, standalone it has to draw its own page.
 */
export default {
    name: 'RegisterPrompt',
    props: ['pre_settings', 'is_main'],
    emits: ['registered'],
    data() {
        return {
            icons,
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
    computed: {
        /* The key has been emailed and is waiting to be pasted back in. */
        awaitingKey() {
            return this.settings && this.settings.status === 'pending';
        },
        /*
         * Both halves of this screen - the disclosure and the way out of it - belong to the
         * one moment where connecting is still a decision. Keyed on that state rather than on
         * which route drew the form, so the choice is not reachable from one and hidden on the
         * other.
         */
        isDeciding() {
            return this.settings && this.settings.status === 'unregistered';
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
                .catch(errors => {
                    this.$handleError(errors);
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

            if (this.settings.status === 'pending' && !this.onboardForm.api_key) {
                this.$notify.error(this.$t('Please provide valid API key'));
                return;
            }

            if (this.settings.status === 'self') {
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
                    /*
                     * Connecting switches daily scanning on at the server. Carried over so the
                     * panel behind this one says so straight away, instead of offering to
                     * enable something that is already running until the next page load.
                     */
                    this.settings.auto_scan = response.settings.auto_scan;
                    this.settings.scan_interval = response.settings.scan_interval;

                    if (response.settings.status === 'active') {
                        this.$router.push({name: 'security_scans', query: {auto_scan: 'yes'}});
                        this.$emit('registered', response.settings);
                    }
                })
                .catch(errors => {
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
        /* Scanning without the service: no key, no alerts, everything else the same. */
        processRegularScanService() {
            this.submitting = true;

            this.$post('security-scan-settings/register', {status: 'self'})
                .then(response => {
                    this.$notify.success(response.message);
                    window.location.reload();
                })
                .catch(errors => {
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

        this.onboardForm.full_name = this.appVars.me.full_name;
        this.onboardForm.email = this.appVars.me.email;
    }
}
</script>

<template>
    <div :class="{fls_page: !is_main}">
        <div :class="{fls_scan_register_page: !is_main}">
            <div v-if="!is_main" class="fls_page_head">
                <div>
                    <h1 class="fls_page_title">{{ $t('Scanning Service') }}</h1>
                    <p class="fls_page_desc">
                        {{ $t('The free API key that lets FluentAuth scan on a schedule and email you when a core file changes.') }}
                    </p>
                </div>
                <div class="fls_page_actions">
                    <el-button @click="$router.push({name: 'security_scans'})">
                        {{ $t('Back to Scans') }}
                    </el-button>
                </div>
            </div>

            <div class="fls_dcard">
                <div v-if="settings" class="fls_scan_register">
                    <div class="fls_scan_register_head">
                        <span class="fls_scan_register_icon" v-html="icons.shield"></span>
                        <h2 v-if="awaitingKey">{{ $t('The Last Step!') }}</h2>
                        <h2 v-else>
                            {{ $t('Let\'s Secure your site by checking unauthorized changes of WP Core Files') }}
                        </h2>
                        <p v-if="awaitingKey">
                            <span v-html="$t('__api_key_email_sent__', settings.account_email_id)"></span>
                        </p>
                        <p v-else>{{ $t('__free_api_desc__') }}</p>
                    </div>

                    <!--
                        What connecting actually sends, before the form rather than linked from
                        it. The decision being made on this screen is whether to send it, and a
                        disclosure somebody has to go looking for is not one. The second column
                        is the half that answers what people actually worry about.
                    -->
                    <div v-if="isDeciding" class="fls_scan_disclosure">
                        <div class="fls_scan_disclosure_col">
                            <h4>{{ $t('What this site would send') }}</h4>
                            <ul>
                                <li>{{ $t('Your name and email address') }}</li>
                                <li>{{ $t('This site\'s address, title and admin link') }}</li>
                                <li>{{ $t('Scan results: paths of files and folders that differ from the official release') }}</li>
                                <li>{{ $t('Installed plugins and themes, with their version numbers') }}</li>
                            </ul>
                        </div>
                        <div class="fls_scan_disclosure_col is_never">
                            <h4>{{ $t('What it never sends') }}</h4>
                            <ul>
                                <li>{{ $t('The contents of any file') }}</li>
                                <li>{{ $t('Anything from your database, including users and passwords') }}</li>
                                <li>{{ $t('Anything about your visitors or their activity') }}</li>
                            </ul>
                        </div>
                    </div>

                    <el-form label-position="top">
                        <template v-if="!awaitingKey">
                            <el-row :gutter="20">
                                <el-col :md="12" :sm="12" :xs="24">
                                    <el-form-item :label="$t('Your Name')" prop="full_name">
                                        <el-input v-model="onboardForm.full_name" type="text"
                                                  :placeholder="$t('Your Full Name')"/>
                                    </el-form-item>
                                </el-col>
                                <el-col :md="12" :sm="12" :xs="24">
                                    <el-form-item :label="$t('Your Email Address')" prop="email">
                                        <el-input v-model="onboardForm.email" type="text"
                                                  :placeholder="$t('Your Email')"/>
                                    </el-form-item>
                                </el-col>
                            </el-row>
                            <el-form-item>
                                <el-button type="primary" :loading="submitting" :disabled="submitting"
                                           @click="registerSite">
                                    {{ $t('Continue & Set API Key') }}
                                </el-button>
                            </el-form-item>
                        </template>

                        <template v-else>
                            <el-form-item :label="$t('API Key')">
                                <el-input :placeholder="$t('Provide API Key')" v-model="onboardForm.api_key"/>
                            </el-form-item>
                            <el-form-item>
                                <el-button type="primary" :loading="submitting" :disabled="submitting"
                                           @click="registerSite">
                                    {{ $t('Start Scan Your Site') }}
                                </el-button>
                            </el-form-item>
                        </template>
                    </el-form>

                    <div class="fls_scan_register_foot">
                        <p v-if="awaitingKey">
                            {{ $t('__api_key_spam_check__') }}
                            <a href="#" @click.prevent="startOver()">
                                {{ $t('start over with a different email address') }}
                            </a>.
                        </p>
                        <p v-else>
                            <span v-html="$t('__api_key_form_consent__', `<a target=&quot;_blank&quot; rel=&quot;noopener&quot; href=&quot;https://fluentauth.com/privacy-policy/&quot;>` + $t('privacy policy and terms and conditions') + `</a>`)"></span>
                        </p>

                    </div>

                    <!--
                        The way out, kept as a real choice rather than a sentence with a link in
                        it - somebody who does not want to connect should not have to read past
                        it twice to find out they do not have to. Secondary on purpose all the
                        same: the cost of this option is the part that is easy to miss, so it is
                        stated rather than implied.
                    -->
                    <div v-if="isDeciding" class="fls_scan_alt">
                        <h4>{{ $t('Prefer not to connect?') }}</h4>
                        <p>{{ $t('__scan_without_connecting__') }}</p>
                        <el-button size="small" :loading="submitting" :disabled="submitting"
                                   @click="processRegularScanService()">
                            {{ $t('Scan without connecting') }}
                        </el-button>
                    </div>
                </div>

                <el-skeleton v-else-if="loading" class="fls_scan_register" :animated="true" :rows="6"/>

                <el-empty v-else
                          :description="$t('Sorry! Settings could not be loaded. Please reload the page')"/>
            </div>
        </div>
    </div>
</template>
