<script type="text/babel">
import icons from './icons';

/*
 * The right-hand column: what is protecting this site, and what is not yet.
 *
 * Deliberately not a second set of counters. The main column is what happened over a date
 * range; this is the site's standing configuration, which does not change when the range
 * does - so the two never say the same thing twice.
 *
 * The checklist that used to live here was its own list, built from settings alone, with its
 * own score and its own buttons. It is now the top of the security screen's list, fetched
 * from the same endpoint that screen uses. That is the point of the change rather than a
 * side effect of it: two lists of what is wrong with a site will eventually disagree about
 * it, and a security tool that contradicts itself has spent the only thing it has. There is
 * one list, shown in full in one place and previewed here.
 *
 * Fetched here rather than carried on the dashboard's own payload, so that the reader is not
 * waiting on the checks to see their logins, and so the numbers cannot drift from the ones
 * the security screen shows.
 */
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
            loading: true,
            installing: false,
            findings: [],
            counts: {open: 0, to_fix: 0, look: 0, passed: 0, accepted: 0},
            score: {done: 0, total: 0, percent: 100}
        }
    },
    computed: {
        percent() {
            return this.score.total ? this.score.percent : 100;
        },
        /*
         * Three, and never the fourth. This is a preview of a list that lives elsewhere, and
         * a preview long enough to work down is just the list again in the wrong place.
         */
        preview() {
            return this.findings.slice(0, 3);
        },
        remaining() {
            return Math.max(0, this.findings.length - this.preview.length);
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
                    value: this.$t('%1s of %2s users', twoFa.enrolled, twoFa.total),
                    warning: twoFa.enrolled === 0,
                    route: 'settings_two_fa_enrollment'
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
                    value: this.protection.digest,
                    warning: false,
                    route: 'settings_general'
                });
            }

            return items;
        }
    },
    methods: {
        getFindings() {
            this.$get('security-findings')
                .then(response => {
                    this.findings = response.findings || [];
                    this.counts = response.counts || this.counts;
                    this.score = response.score || this.score;
                })
                .catch(() => {
                    /* The dashboard is worth showing without this; not worth a banner over. */
                })
                .finally(() => {
                    this.loading = false;
                });
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
        <div class="fls_aside_block">
            <h3>
                {{ $t('Security Score') }}
                <small v-if="!loading">{{ $t('%1s of %2s', score.done, score.total) }}</small>
            </h3>

            <el-skeleton v-if="loading" :animated="true" :rows="3"/>

            <template v-else>
                <div class="fls_dash_score">
                    <div class="fls_dash_score_track">
                        <div class="fls_dash_score_fill" :style="{width: percent + '%'}"></div>
                    </div>
                </div>

                <!--
                    A preview of the security screen's list, not a second copy of it - so the
                    rows are links to where the work is done rather than buttons that do it.
                    One place to act on a finding, and it is the place that shows all of them.
                -->
                <ul v-if="preview.length" class="fls_dash_findings">
                    <li v-for="finding in preview" :key="finding.id"
                        :class="'is_' + (['fix', 'look', 'advice'].includes(finding.severity) ? finding.severity : 'look')">
                        <router-link :to="{name: 'security_findings'}">{{ finding.title }}</router-link>
                    </li>
                </ul>

                <p v-else class="fls_note">
                    {{ $t('Nothing on this site needs your attention right now.') }}
                </p>

                <div class="fls_scan_aside_actions">
                    <el-button size="small" @click="$router.push({name: 'security_findings'})">
                        <template v-if="remaining">
                            {{ $_n('See 1 more', 'See %s more', remaining) }}
                        </template>
                        <template v-else>{{ $t('Open Security') }}</template>
                    </el-button>
                </div>
            </template>
        </div>

        <div class="fls_aside_block">
            <h3>{{ $t('At a Glance') }}</h3>

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

            <ul>
                <li>
                    <span v-html="icons.tickSmall"></span>
                    {{ $t('Sends through your own provider, not the web server') }}
                </li>
                <li>
                    <span v-html="icons.tickSmall"></span>
                    {{ $t('Logs every email, with a resend button') }}
                </li>
                <li>
                    <span v-html="icons.tickSmall"></span>
                    {{ $t('Free, with no premium version') }}
                </li>
            </ul>

            <el-button :loading="installing" @click="installPlugin('fluent-smtp')" type="primary">
                {{ $t('Install FluentSMTP') }}
            </el-button>
        </div>
    </aside>
</template>
