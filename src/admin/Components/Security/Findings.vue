<script type="text/babel">
import icons from '../SecurityScan/icons';
import SecurityTabs from './_SecurityTabs.vue';
import FindingRow from './_FindingRow.vue';
import FindingsAside from './_FindingsAside.vue';

/*
 * The security screen's first tab: everything outstanding, worst first.
 *
 * One flat list rather than sections. Sections are what you build when the list is a
 * taxonomy; this is a queue, and the reader works down it. What the sections used to do -
 * letting somebody look at one subject - the filter chips do, without imposing an order that
 * puts a serious file finding below a settings one because F comes before L.
 *
 * Nothing here waits on a button. The checks behind this list answer from local state, so
 * they run on arrival and the screen is never a blank page with a call to action on it. The
 * expensive ones - checksums, file hashing - report through the Monitoring tab and their own
 * schedule; the aside says when they last ran so this list cannot imply it knows more than
 * it does.
 */
export default {
    name: 'SecurityFindings',
    components: {
        SecurityTabs,
        FindingRow,
        FindingsAside
    },
    data() {
        return {
            icons,
            loading: true,
            findings: [],
            counts: {open: 0, to_fix: 0, look: 0, passed: 0, accepted: 0},
            score: {done: 0, total: 0, percent: 100},
            /* The scan's own settings, for the honest note in the aside. */
            scan: null,
            /* Things the site has said it is happy with. Kept out of the way, not hidden. */
            accepted: [],
            showAccepted: false,
            group: 'all',
            /* Which finding is mid-request, so only its own button spins. */
            acting: ''
        }
    },
    computed: {
        /*
         * Only the groups that actually produced something. A chip for a subject with nothing
         * under it is a filter that can only ever empty the screen.
         */
        groups() {
            const labels = {
                files: this.$t('Files'),
                config: this.$t('Configuration'),
                login: this.$t('Login'),
                users: this.$t('Users'),
                plugins: this.$t('Plugins & Themes')
            };

            const present = [];

            this.findings.forEach(finding => {
                if (!present.includes(finding.group)) {
                    present.push(finding.group);
                }
            });

            return present.map(group => ({
                key: group,
                label: labels[group] || group,
                count: this.findings.filter(finding => finding.group === group).length
            }));
        },
        visibleFindings() {
            if (this.group === 'all') {
                return this.findings;
            }

            return this.findings.filter(finding => finding.group === this.group);
        },
        /*
         * Named after the worst thing on the list, and said as a number of things to do rather
         * than as a verdict on the site. "Your site is at risk" is not information; "2 things
         * need fixing" is, and it is the same sentence whether the reader is technical or not.
         */
        verdict() {
            if (this.counts.to_fix) {
                return {
                    tone: 'is_danger',
                    icon: icons.alert,
                    title: this.$_n('%s thing needs fixing', '%s things need fixing', this.counts.to_fix),
                    body: this.counts.look
                        ? this.$_n(
                            'One more is worth a look when you have a minute.',
                            '%s more are worth a look when you have a minute.',
                            this.counts.look
                        )
                        : this.$t('Everything else on this site checked out.')
                };
            }

            if (this.counts.open) {
                return {
                    tone: 'is_warning',
                    icon: icons.shield,
                    title: this.$t('Nothing urgent'),
                    body: this.$_n(
                        'One thing is worth a look when you have a minute.',
                        '%s things are worth a look when you have a minute.',
                        this.counts.open
                    )
                };
            }

            return {
                tone: 'is_success',
                icon: icons.tick,
                title: this.$t('Everything checked out'),
                body: this.$t('Nothing on this site needs your attention right now.')
            };
        }
    },
    methods: {
        load() {
            return this.$get('security-findings')
                .then(response => {
                    this.apply(response);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /*
         * Every write comes back with the recalculated list, so the screen redraws from the
         * server's answer rather than striking a row out locally. Turning one thing on can move
         * another - blocking application passwords changes what the two-factor row has to say -
         * and a list that only ever removes the row you pressed drifts away from the truth.
         */
        apply(response) {
            this.findings = response.findings || [];
            this.accepted = response.accepted || [];
            this.counts = response.counts || this.counts;
            this.score = response.score || this.score;

            /* A filter whose subject has just been cleared would otherwise show an empty list. */
            if (this.group !== 'all' && !this.findings.some(finding => finding.group === this.group)) {
                this.group = 'all';
            }
        },
        getScanState() {
            return this.$get('security-scan-settings')
                .then(response => {
                    this.scan = response.settings;
                })
                .catch(() => {
                    /* Worth showing when it can be; not worth an error banner over. */
                });
        },
        fix(finding) {
            this.acting = finding.id;

            this.$post('security-findings/fix', {check: finding.check, finding: finding.id})
                .then(response => {
                    this.$notify.success(response.message || this.$t('Done.'));

                    if (response.settings) {
                        this.appVars.auth_settings = response.settings;
                    }

                    this.apply(response);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.acting = '';
                });
        },
        accept(finding) {
            this.acting = finding.id;

            this.$post('security-findings/accept', {check: finding.check, finding: finding.id})
                .then(response => {
                    this.$notify.success(response.message || this.$t('Done.'));
                    this.apply(response);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.acting = '';
                });
        },
        /*
         * Put something back on the list. Offered in the place it was taken off, because a
         * dismissal whose only way back is a Reset button on another screen is not a decision
         * anybody can revise - only one they can undo wholesale.
         */
        unaccept(finding) {
            this.acting = finding.id;

            this.$post('security-findings/unaccept', {check: finding.check, finding: finding.id})
                .then(response => {
                    this.$notify.success(response.message || this.$t('Done.'));
                    this.apply(response);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.acting = '';
                });
        },
        navigate(finding) {
            const target = {name: finding.route};

            if (finding.section) {
                target.query = {section: finding.section};
            }

            this.$router.push(target);
        }
    },
    mounted() {
        this.load();
        this.getScanState();
    }
}
</script>

<template>
    <div class="fls_page">
        <div class="fls_page_inner">
            <div class="fls_page_main">
                <div class="fls_page_head">
                    <div>
                        <h1 class="fls_page_title">{{ $t('Security') }}</h1>
                        <p class="fls_page_desc">
                            {{ $t('Everything on this site that needs your attention, and what to do about each one.') }}
                        </p>
                    </div>
                </div>

                <security-tabs :open-count="counts.open"/>

                <el-skeleton v-if="loading" :animated="true" :rows="6"/>

                <template v-else>
                    <div class="fls_scan_verdict" :class="verdict.tone">
                        <span class="fls_scan_verdict_icon" v-html="verdict.icon"></span>
                        <div>
                            <h2>{{ verdict.title }}</h2>
                            <p>{{ verdict.body }}</p>
                        </div>
                    </div>

                    <!-- Only worth drawing when there is more than one subject to sort by. -->
                    <div v-if="groups.length > 1" class="fls_find_filters">
                        <button type="button" class="fls_find_chip"
                                :class="{is_on: group === 'all'}" @click="group = 'all'">
                            {{ $t('All') }}
                            <span class="fls_find_chip_count">{{ findings.length }}</span>
                        </button>
                        <button v-for="item in groups" :key="item.key" type="button"
                                class="fls_find_chip" :class="{is_on: group === item.key}"
                                @click="group = item.key">
                            {{ item.label }}
                            <span class="fls_find_chip_count">{{ item.count }}</span>
                        </button>
                    </div>

                    <div v-if="visibleFindings.length" class="fls_find_list">
                        <finding-row v-for="finding in visibleFindings" :key="finding.id"
                                     :finding="finding" :busy="acting === finding.id"
                                     @fix="fix" @accept="accept" @navigate="navigate"/>
                    </div>

                    <!--
                        What was checked and found to be fine. Never a row of its own - a screen
                        of ticks buries the one thing that is not one - but said, because a list
                        with nothing on it should not read as a list nobody has run.
                    -->
                    <p v-if="counts.passed || accepted.length" class="fls_find_passed">
                        <span v-if="counts.passed">
                            {{ $_n('%s check passed', '%s checks passed', counts.passed) }}
                        </span>
                        <template v-if="accepted.length">
                            <span v-if="counts.passed" class="fls_find_sep">·</span>
                            <button type="button" class="fls_find_link"
                                    @click="showAccepted = !showAccepted">
                                {{ $_n('%s marked as expected', '%s marked as expected', accepted.length) }}
                            </button>
                        </template>
                    </p>

                    <!--
                        What the site has said it is happy with. Below the fold of the list and
                        collapsed, because these are settled - but on the screen, with the way
                        back beside them, because they are decisions somebody made rather than
                        checks that never ran.
                    -->
                    <div v-if="showAccepted && accepted.length" class="fls_find_list fls_find_accepted">
                        <div v-for="item in accepted" :key="item.id" class="fls_finding is_accepted">
                            <span class="fls_finding_stripe"></span>
                            <div class="fls_finding_body">
                                <h3 class="fls_finding_title">{{ item.title }}</h3>
                                <p v-if="item.why" class="fls_finding_why">{{ item.why }}</p>
                                <ul v-if="item.details && item.details.length" class="fls_finding_details">
                                    <li v-for="(detail, index) in item.details" :key="index">{{ detail }}</li>
                                </ul>
                            </div>
                            <div class="fls_finding_actions">
                                <el-button size="small" :loading="acting === item.id"
                                           @click="unaccept(item)">
                                    {{ $t('Undo') }}
                                </el-button>
                            </div>
                        </div>
                    </div>
                </template>
            </div>

            <findings-aside v-if="!loading" :score="score" :counts="counts" :scan="scan"/>
        </div>
    </div>
</template>
