<script type="text/babel">
import icons from './icons';
import OptinForm from '../Optin/_OptinForm.vue';

export default {
    name: 'SecurityAside',
    components: {OptinForm},
    props: {
        protection: {
            type: Object,
            required: true
        }
    },
    data() {
        return {
            icons,
            /*
             * Whether the signup card is still on the page. Seeded from the app-wide flag
             * and lowered locally when it is answered, so the column closes up at once
             * rather than on the next load - see Optin::isRequired() for what sets it.
             */
            askOptin: this.appVars.optin_required,
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
                    value: this.protection.two_fa_enabled ? this.$t('%1s of %2s users set up', twoFa.enrolled, twoFa.total) : this.$t('Disabled'),
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
                    key: 'auto_scan',
                    label: this.$t('Scheduled scans'),
                    value: this.autoScanLabel,
                    /*
                     * A site that deliberately scans without the alerts service has no schedule
                     * to be missing, so "Off" there is the arrangement rather than something to
                     * put right.
                     */
                    warning: !scan.self_managed && !scan.scheduled,
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

            return items.filter(item => item.key !== 'auto_scan' || scan.registered || scan.disconnected);
        },
        /*
         * How often, or why never. Kept apart from the fact list so the four cases read as four
         * cases rather than as a nested ternary inside an object literal.
         */
        autoScanLabel() {
            const scan = this.protection.scan;

            if (scan.disconnected) {
                return this.$t('Disconnected');
            }

            if (!scan.scheduled) {
                return this.$t('Off');
            }

            return {
                hourly: this.$t('Every hour'),
                six_hourly: this.$t('Every 6 hours'),
                twelve_hourly: this.$t('Every 12 hours'),
                daily: this.$t('Every day')
            }[scan.interval] || this.$t('Every day');
        }
    },
    methods: {
        /*
         * Only a refusal takes the card away. Hiding it on any answer at all destroyed the
         * form's own success state in the same tick it was set - "check your inbox" is an
         * instruction somebody has to act on, and it was being unmounted before it could be
         * read, leaving a toast that vanishes as the only trace. Declining has nothing to
         * leave behind, so that still closes the block.
         */
        onOptinAnswered(answer) {
            if (answer === 'dismissed') {
                this.askOptin = false;
            }
        },
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
                <p>{{ $t('Could not load the security checks.') }}</p>
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
                    <span>{{ $t('Recommendations done') }}</span><b>{{ $t('%1s of %2s', score.done, score.total) }}</b>
                </div>
                <p v-if="score.total" class="fls_dashboard__caption">{{ $t('Counts recommendations that passed or that you dismissed. File scan results are not included.') }}</p>
            </template>
        </div>

        <div class="fls_aside_block">
            <h3>{{ $t('Current protection') }}</h3>

            <ul class="fls_dash_facts">
                <li v-for="fact in facts" :key="fact.key" :class="{is_warning: fact.warning}">
                    <span class="fls_dash_fact_label">{{ fact.label }}</span>
                    <router-link class="fls_dash_fact_value" :to="{name: fact.route}">
                        {{ fact.value }}
                    </router-link>
                </li>
            </ul>
        </div>

        <!--
            Last of the useful blocks and before the promo, which is where an ask belongs:
            everything above it answers a question about this site, and this one does not.
            Dismissing it parks it for a week rather than for good - see Optin::dismiss().
        -->
        <div v-if="askOptin" class="fls_aside_block fls_dash_optin">
            <h3>{{ $t('Stay updated') }}</h3>
            <optin-form @answered="onOptinAnswered"/>
        </div>

        <div v-if="!appVars.fluent_smtp_url" class="fls_aside_block fls_dash_promo">
            <h3>{{ $t('Are your emails arriving?') }}</h3>

            <p>
                {{ $t('Login alerts, magic links and two-factor codes all go out by email. FluentSMTP sends your site\'s email through a mail service you choose, which is far more reliable than the web server.') }}
            </p>

            <el-button :loading="installing" @click="installPlugin('fluent-smtp')" type="primary">
                {{ $t('Install FluentSMTP') }}
            </el-button>
        </div>
    </aside>
</template>
