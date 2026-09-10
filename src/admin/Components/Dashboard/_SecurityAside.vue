<script type="text/babel">
import icons from './icons';

export default {
    name: 'SecurityAside',
    props: {
        protection: {
            type: Object,
            required: true
        }
    },
    data() {
        return {
            icons,
            loading: false,
            loadError: false,
            installing: false,
            findings: [],
            counts: {open: 0, to_fix: 0, look: 0, passed: 0, accepted: 0},
            score: {done: 0, total: 0, percent: 100}
        }
    },
    computed: {
        attention() {
            return this.findings.filter(finding => finding.severity !== 'advice')
                .sort((a, b) => (a.severity === 'fix' ? 0 : 1) - (b.severity === 'fix' ? 0 : 1));
        },
        recommendations() {
            return this.findings.filter(finding => finding.severity === 'advice').length;
        },
        /*
         * Three, and never the fourth. This is a preview of a list that lives elsewhere, and
         * a preview long enough to work down is just the list again in the wrong place.
         */
        preview() {
            return this.attention.slice(0, 3);
        },
        remaining() {
            return Math.max(0, this.attention.length - this.preview.length);
        },
        /*
         * A handful of standing facts, each with the same shape: a label, an answer, and
         * whether that answer is one to act on. Built here rather than in the template so
         * the ones that do not apply can simply be filtered out.
         */
        facts() {
            const twoFa = this.protection.two_fa;
            const scan = this.protection.scan;

            const items = [
                {
                    key: 'two_fa',
                    label: this.$t('Authenticator app'),
                    value: this.protection.two_fa_enabled ? this.$t('%1s of %2s enrolled', twoFa.enrolled, twoFa.total) : this.$t('Disabled'),
                    warning: !this.protection.two_fa_enabled || twoFa.enrolled === 0,
                    route: this.protection.two_fa_enabled ? 'settings_two_fa_enrollment' : 'settings_general'
                },
                {
                    key: 'scan',
                    label: this.$t('Last file scan'),
                    value: scan.last_checked || (scan.registered ? this.$t('Not run yet') : this.$t('Not set up')),
                    warning: !scan.registered || !scan.last_checked || !scan.is_ok,
                    route: 'security_scans'
                },
                {
                    key: 'retention',
                    label: this.$t('Logs kept for'),
                    value: this.protection.retention
                        ? this.$_n('%s day', '%s days', this.protection.retention)
                        : this.$t('Forever'),
                    warning: false,
                    route: 'settings_general'
                }
            ];

            if (this.protection.digest) {
                items.push({
                    key: 'digest',
                    label: this.$t('Summary email'),
                    value: ({
                        daily: this.$t('Daily'), mon: this.$t('Monday'), tue: this.$t('Tuesday'),
                        wed: this.$t('Wednesday'), thu: this.$t('Thursday'), fri: this.$t('Friday'),
                        sat: this.$t('Saturday'), sun: this.$t('Sunday'),
                        weekly: this.$t('Monday'), monthly: this.$t('Monthly')
                    })[this.protection.digest] || this.protection.digest,
                    warning: false,
                    route: 'settings_general'
                });
            }

            return items;
        }
    },
    methods: {
        async getFindings() {
            if (this.loading) return;
            this.loading = true;
            this.loadError = false;
            try {
                const response = await this.$get('security-findings');
                this.findings = response.findings || [];
                this.counts = response.counts || this.counts;
                this.score = response.score || this.score;
            } catch (errors) {
                this.loadError = true;
            } finally {
                this.loading = false;
            }
        },
        installPlugin(plugin) {
            this.installing = true;

            this.$post('install-plugin', {plugin: plugin})
                .then(() => {
                    window.location.reload();
                })
                .catch(errors => {
                    this.$handleError(errors);
                    this.installing = false;
                });
        }
    },
    mounted() {
        this.getFindings();
    }
}
</script>

<template>
    <aside class="fls_page_aside">
        <div class="fls_aside_block fls_dashboard__security">
            <h2>{{ $t('Security status') }}</h2>
            <el-skeleton v-if="loading" :animated="true" :rows="3"/>
            <div v-else-if="loadError" class="fls_dashboard__security-error" role="alert">
                <p>{{ $t('Security status is unavailable. Try loading the checks again.') }}</p>
                <el-button size="small" @click="getFindings">{{ $t('Try again') }}</el-button>
            </div>
            <template v-else>
                <div class="fls_dashboard__verdict" :class="{is_clear: !attention.length}">
                    <span class="fls_dashboard__verdict-icon" aria-hidden="true" v-html="attention.length ? icons.threat : icons.check"></span>
                    <div>
                        <strong>{{ attention.length ? $_n('%s item needs attention', '%s items need attention', attention.length) : $t('No open issues found') }}</strong>
                        <p>{{ $t('Based on the latest security checks') }}</p>
                    </div>
                </div>
                <ul v-if="preview.length" class="fls_dash_findings">
                    <li v-for="finding in preview" :key="finding.id"
                        :class="'is_' + (finding.severity === 'fix' ? 'fix' : 'look')">
                        <router-link :to="{name: 'security_findings'}">{{ finding.title }}</router-link>
                    </li>
                </ul>
                <p v-if="remaining" class="fls_dashboard__caption">{{ $_n('%s more item to review', '%s more items to review', remaining) }}</p>
                <p v-if="recommendations" class="fls_dashboard__caption">{{ $_n('%s optional recommendation', '%s optional recommendations', recommendations) }}</p>
                <el-button type="primary" class="fls_dashboard__review" @click="$router.push({name: 'security_findings'})">
                    {{ attention.length ? $t('Review security issues') : $t('View security checks') }}
                </el-button>
                <div v-if="score.total" class="fls_dashboard__checks">
                    <span>{{ $t('Recommended checks addressed') }}</span><b>{{ $t('%1s of %2s', score.done, score.total) }}</b>
                </div>
                <p v-if="score.total" class="fls_dashboard__caption">{{ $t('Passed or dismissed checks. File findings are reviewed separately.') }}</p>
            </template>
        </div>

        <div class="fls_aside_block">
            <h3>{{ $t('Protection at a glance') }}</h3>

            <ul class="fls_dash_facts">
                <li v-for="fact in facts" :key="fact.key" :class="{is_warning: fact.warning}">
                    <span class="fls_dash_fact_label">{{ fact.label }}</span>
                    <router-link class="fls_dash_fact_value" :to="{name: fact.route}">
                        {{ fact.value }}
                    </router-link>
                </li>
            </ul>
        </div>

        <div v-if="!appVars.fluent_smtp_url" class="fls_aside_block fls_dash_promo">
            <h3>{{ $t('Are your emails arriving?') }}</h3>

            <p>
                {{ $t('Login alerts, magic links and two-factor codes are only as reliable as the email that carries them.') }}
            </p>

            <el-button :loading="installing" @click="installPlugin('fluent-smtp')" type="primary">
                {{ $t('Install FluentSMTP') }}
            </el-button>
        </div>
    </aside>
</template>
