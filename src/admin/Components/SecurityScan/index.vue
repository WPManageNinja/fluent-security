<script type="text/babel">
import icons from './icons';
import RegisterPromt from './RegisterPromt.vue';
import ScanResults from './_ScanResults.vue';
import ScannerWidgets from './_ScannerWidgets.vue';
import {counts as subNavCounts} from '@/Bits/subNav';

/*
 * The security scans screen.
 *
 * Two columns on the shared page shell: what the scan found on the left, how the scanning
 * is set up on the right - the same split as the dashboard, for the same reason. The right
 * column is the site's standing configuration, which a single scan has nothing to say
 * about, so it stays put while the left one changes.
 *
 * The scan itself is run from here rather than from the panel that shows the result: the
 * button that starts it belongs in the page heading, above both columns' worth of content,
 * and there is only ever one scan in flight.
 *
 * A scan is four phases - core, every plugin, every theme, and then the site's own snapshot
 * of the extensions WordPress.org has no copy of - and every walk after the first is driven
 * from here, one request at a time. That is not a stylistic choice: a site with forty plugins
 * cannot be checked inside one request without hitting max_execution_time, and a scan that
 * dies half way reports nothing at all. Driving it from the browser also means the wait can
 * show its real progress instead of a spinner.
 *
 * The snapshot phase is skipped when there is no snapshot. Comparing against one is the only
 * check this site can make of a premium plugin, so leaving it to the nightly job meant a scan
 * somebody pressed the button for reported on everything except the files it was the only
 * thing watching.
 *
 * This screen owns two things the panels below only read: the list of what is installed, and
 * the verdict for each item. They are kept apart - `targets` from the inventory, `results`
 * keyed by the same identity - and joined here, so a row can distinguish "checked and fine"
 * from "not checked yet", which is the distinction the whole summary rests on.
 */
export default {
    name: 'SecurityScan',
    components: {
        RegisterPromt,
        ScanResults,
        ScannerWidgets,
    },
    data() {
        return {
            icons,
            loading: true,
            settings: null,
            ignores: {
                files: [],
                folders: []
            },
            /* idle -> scanning -> done. Nothing else drives what the column shows. */
            scanState: 'idle',
            /* Core's findings. Not persisted server-side, so this is per visit. */
            results: null,
            hasIssues: false,
            /*
             * Whether the changes are ones the site has not already accepted. Findings that
             * are all on the ignore list are still findings, but they are not an alarm.
             */
            willAlert: false,
            errorMessage: '',
            /* Everything installed, from the inventory. */
            targets: {
                plugins: [],
                themes: []
            },
            /* Verdicts, keyed "type:key" to match the server's own result keys. */
            extensionResults: {},
            /*
             * The site's own snapshot of the extensions WordPress.org cannot vouch for.
             *
             * Owned here rather than by the panel that shows it, because three things now read
             * it - the aside panel, the premium list, and the scan's own verdict - and a
             * snapshot taken from one of them has to be the snapshot the other two see.
             */
            baseline: {exists: false, units: 0, files: 0, changed: 0, taken_at: '', coverable: 0},
            baselineUnits: [],
            baselineBusy: false,
            /* In flight right now - more than one, because the walk runs a few at a time. */
            checkingKeys: [],
            coverage: null,
            progress: {
                phase: 'core',
                done: 0,
                total: 0,
                current: ''
            }
        }
    },
    computed: {
        /*
         * Scanning is available once the site has an API key, or has opted out of needing one.
         *
         * `disabled` counts. Scanning is local - checksums, hashes, the filesystem - and none
         * of it needs the relay; what a disabled site loses is the reporting, which the server
         * already withholds on the same flag. Left out, a site switched off on the dashboard
         * fell through every branch of this screen to "Settings could not be loaded", with the
         * Resume button that fixes it rendered inside the aside that was not drawn either.
         */
        isReady() {
            return this.settings && ['active', 'self', 'disabled'].includes(this.settings.status);
        },
        needsRegistration() {
            return this.settings && (this.settings.status === 'unregistered' || this.settings.status === 'pending');
        },
        /*
         * The last scan found something and nobody has re-run it since. Worth saying on
         * arrival, because otherwise the screen looks like nothing has ever happened.
         */
        hasStaleWarning() {
            return this.isReady && this.scanState === 'idle' && this.settings.is_ok === 'no';
        },
        scanButtonLabel() {
            if (this.scanState === 'done') {
                return this.$t('Scan again');
            }

            return this.settings && this.settings.last_checked_human
                ? this.$t('Scan again')
                : this.$t('Run a scan');
        },
        /* Each installed extension with whatever is known about it. */
        allTargets() {
            return [...this.targets.plugins, ...this.targets.themes].map(target => ({
                ...target,
                result: this.extensionResults[this.keyOf(target)] || null
            }));
        },
        pluginRows() {
            return this.allTargets.filter(item => item.type === 'plugin' && !this.isPremium(item));
        },
        themeRows() {
            return this.allTargets.filter(item => item.type === 'theme' && !this.isPremium(item));
        },
        /*
         * Only the extensions that never had an official copy to compare against.
         *
         * Deliberately not "everything we could not verify". An extension the directory does
         * publish, at a version it does not, stays in the plugins or themes list where it will be
         * read - see severityOf. Filing that under "premium & custom" would bury the single most
         * telling sign of tampering the scan can produce among a dozen paid plugins.
         */
        unverified() {
            return this.allTargets.filter(item => this.isPremium(item)).map(item => ({
                ...item,
                reason_label: (item.result && item.result.reason_label) || item.reason_label
            }));
        },
        /*
         * The last scan came back clean, so the moment to take a snapshot can be named when it
         * is the right one. A snapshot of a site that has already been broken into records the
         * break-in as normal, which is the single way this feature fails its owner.
         */
        isClean() {
            return !!this.settings && this.settings.is_ok === 'yes' && !!this.settings.last_checked_human;
        },
        /* Snapshot rows with something to say, keyed by scope so a row can find its own. */
        baselineByScope() {
            const map = {};

            this.baselineUnits.forEach(unit => {
                map[unit.scope] = unit;
            });

            return map;
        },
        /*
         * Files that have changed under a snapshotted extension without its version moving.
         *
         * Counted into the scan's verdict rather than left to the aside, because a scan that
         * says "everything looks good" while the snapshot is holding changed files is telling
         * somebody the one thing this feature exists to stop it telling them.
         */
        baselineChanged() {
            return this.baselineUnits.reduce((total, unit) => total + (unit.changed || 0), 0);
        },
        /* Extensions on a version WordPress.org has never published, and not marked expected. */
        suspicious() {
            return this.allTargets.filter(item =>
                this.severityOf(item) === 'suspicious' && !this.isIgnored(item)
            );
        }
    },
    methods: {
        keyOf(target) {
            return target.type + ':' + target.key;
        },
        isUnverified(item) {
            return !item.verifiable || !!(item.result && !item.result.verifiable);
        },
        /* Whichever of the two knows more: the attempt, if one was made, else the inventory. */
        severityOf(item) {
            if (!this.isUnverified(item)) {
                return '';
            }

            return (item.result && item.result.severity) || item.severity || 'unknown';
        },
        /* Nothing to compare against, ever - a paid or hand-written extension. */
        isPremium(item) {
            return this.severityOf(item) === 'benign';
        },
        /*
         * Marked as expected. The ignore list holds it under `folders`, because what is accepted
         * is the extension's directory rather than any one file in it.
         */
        isIgnored(item) {
            const path = '/' + String(item.rel_path || '').replace(/^\/+|\/+$/g, '');

            return (this.ignores.folders || []).includes(path);
        },
        getSettings() {
            this.loading = true;

            this.$get('security-scan-settings')
                .then(response => {
                    this.settings = response.settings;
                    this.ignores = response.ignores;
                    this.coverage = response.extension_summary;

                    /*
                     * Verdicts from the last scan, so arriving on the screen shows the standing
                     * picture rather than a page of "not checked yet". Overwritten by a scan
                     * when one runs; until then this is the answer, and it is the same answer
                     * the findings list and the recovery screen are reading.
                     */
                    this.results = response.core_results || null;

                    const stored = {};
                    (response.extension_results || []).forEach(result => {
                        stored[this.keyOf(result)] = result;
                    });
                    this.extensionResults = stored;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /*
         * The work list. Fetched on arrival as well as during a scan: the list of what is
         * installed is what makes the summary a summary, and it should be there before anybody
         * presses anything.
         */
        getTargets() {
            return this.$get('security-scan-settings/scan/targets')
                .then(response => {
                    this.targets = {
                        plugins: response.plugins,
                        themes: response.themes
                    };

                    return response;
                });
        },
        async startScanning() {
            this.errorMessage = '';
            this.scanState = 'scanning';
            this.progress = {phase: 'core', done: 0, total: 0, current: ''};

            try {
                /* Phase one: core, which is a single request and its own verdict. */
                const core = await this.$get('security-scan-settings/scan');

                this.results = core.scan_results;

                /* Phases two and three: everything in wp-content, one at a time. */
                const targets = await this.getTargets();

                await this.scanExtensions('plugins', targets.plugins.filter(item => item.verifiable));
                await this.scanExtensions('themes', targets.themes.filter(item => item.verifiable));

                /* Phase four: the snapshot, if this site has taken one. */
                await this.compareBaseline();

                this.finishScan(core);
            } catch (errors) {
                this.$handleError(errors);
                this.errorMessage = errors && errors.message ? errors.message : '';
                this.scanState = 'idle';
            } finally {
                this.checkingKeys = [];
            }
        },
        /*
         * Walk one phase's list, a few at a time.
         *
         * Three at once rather than one: a plugin check is mostly spent waiting on
         * wordpress.org, so serialising the whole list would make a big site take minutes for
         * no reason. Three rather than all of them because each theme pulls down a multi-
         * megabyte zip, and a site's own server is on the other end of every one of these.
         *
         * A single extension that fails is recorded and stepped over. One plugin whose
         * checksums cannot be reached is not a reason to abandon the other thirty.
         */
        async scanExtensions(phase, items) {
            this.progress = {phase, done: 0, total: items.length, current: ''};

            if (!items.length) {
                return;
            }

            const queue = [...items];
            const concurrency = Math.min(3, queue.length);

            const worker = async () => {
                while (queue.length) {
                    const item = queue.shift();
                    const key = this.keyOf(item);

                    this.progress.current = item.name;
                    this.checkingKeys.push(key);

                    try {
                        const response = await this.$post('security-scan-settings/scan/extension', {
                            type: item.type,
                            key: item.key
                        });

                        this.extensionResults[key] = response.result;
                    } catch (errors) {
                        /* Recorded as unverifiable so the row says so rather than staying blank. */
                        this.extensionResults[key] = {
                            ...item,
                            verifiable: false,
                            reason: 'download_failed',
                            reason_label: this.$t('Could not be checked'),
                            files: {}
                        };
                    }

                    this.checkingKeys = this.checkingKeys.filter(pending => pending !== key);
                    this.progress.done++;
                }
            };

            await Promise.all(Array.from({length: concurrency}, worker));
        },
        /*
         * Everything the snapshot knows, from the one endpoint that answers for all of it.
         *
         * Every snapshot action returns the same shape, so taking one, clearing one and
         * comparing against one all land here and no screen has to fetch again to catch up.
         */
        applyBaseline(response) {
            if (response && response.baseline) {
                this.baseline = response.baseline;
                this.baselineUnits = response.units || [];
            }

            return response;
        },
        loadBaseline() {
            return this.$get('baseline')
                .then(response => this.applyBaseline(response))
                .catch(() => {
                    /* The snapshot is worth showing when it can be; not worth an error banner. */
                });
        },
        /*
         * Walk the snapshot, one budgeted pass at a time.
         *
         * The server hashes for as long as it is allowed to and says what is left, exactly as
         * it does for the nightly job - so a site with sixty premium plugins is covered across
         * several requests instead of timing out on one and reporting nothing. The loop is
         * capped because a pass that never reduces the remainder is a bug, and a bug should
         * stall a scan rather than spin the browser against the server for ever.
         */
        async compareBaseline() {
            if (!this.baseline.exists) {
                return;
            }

            const total = this.baseline.coverable || this.baseline.units;

            this.progress = {phase: 'baseline', done: 0, total, current: ''};

            for (let pass = 0; pass <= total + 2; pass++) {
                const response = await this.$post('baseline/compare', {budget: 10});

                this.applyBaseline(response);

                const remaining = (response.result && response.result.remaining) || 0;

                this.progress.done = Math.max(0, total - remaining);

                if (!remaining) {
                    return;
                }
            }
        },
        /*
         * Record these extensions as they stand.
         *
         * Takes the scopes rather than assuming all of them, because the premium list offers
         * this per row as well as for the section: somebody who has just reviewed one plugin
         * should be able to vouch for that one without also vouching for the other twelve
         * they have not looked at.
         */
        takeSnapshot(scopes) {
            this.baselineBusy = true;

            return this.$post('baseline/snapshot', scopes && scopes.length ? {scopes} : {})
                .then(response => {
                    this.applyBaseline(response);
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.baselineBusy = false;
                });
        },
        clearBaseline() {
            this.baselineBusy = true;

            return this.$post('baseline/clear')
                .then(response => {
                    this.applyBaseline(response);
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.baselineBusy = false;
                });
        },
        /*
         * Check one extension again, on its own.
         *
         * What a row asks for after putting the official copy back: the reinstall says what it
         * did, and this is what settles whether the files now match. The same request the walk
         * makes, so the row updates the way it does during a scan - but outside the progress
         * counters, because this is not part of one.
         */
        async recheckExtension(item) {
            const key = this.keyOf(item);

            if (this.checkingKeys.includes(key)) {
                return;
            }

            this.checkingKeys.push(key);

            try {
                const response = await this.$post('security-scan-settings/scan/extension', {
                    type: item.type,
                    key: item.key
                });

                this.extensionResults[key] = response.result;
            } catch (errors) {
                this.$handleError(errors);
            } finally {
                this.checkingKeys = this.checkingKeys.filter(pending => pending !== key);
            }
        },
        /*
         * The whole scan's verdict, once every phase has reported.
         *
         * Core's own verdict comes from the server, which knows the ignore list. Extension
         * findings are weighed here, against the same list - a path is named the way the
         * ignore list names it, root-relative with a leading slash, so one list covers both.
         */
        finishScan(core) {
            const ignored = this.ignores.files || [];
            let findings = 0;
            let unaccepted = 0;
            let checked = 0;
            let withIssues = 0;

            this.allTargets.forEach(item => {
                const result = item.result;

                if (!result || !result.verifiable) {
                    return;
                }

                checked++;

                const files = result.files || {};
                const root = '/' + String(result.rel_path || '').replace(/^\/+|\/+$/g, '') + '/';
                let own = 0;

                Object.keys(files).forEach(file => {
                    own++;

                    if (!ignored.includes(root + file)) {
                        unaccepted++;
                    }
                });

                /* Findings past the storage cap are still findings. */
                own += result.truncated || 0;
                unaccepted += result.truncated || 0;

                findings += own;

                if (own) {
                    withIssues++;
                }
            });

            /*
             * An extension on a version WordPress.org never published produced no file list -
             * there was no official copy to diff against - but it is a finding, and the loudest
             * one available. Counted here or the screen would report a clean scan for it.
             */
            const suspicious = this.suspicious.length;

            /*
             * And whatever the snapshot found. There is no accepted/unaccepted distinction to
             * draw here: accepting a snapshot finding re-takes the snapshot, so anything still
             * standing after a comparison is by definition something nobody has agreed to.
             */
            const snapshotFindings = this.baselineChanged;

            this.hasIssues = core.hasIssues || findings > 0 || suspicious > 0 || snapshotFindings > 0;
            this.willAlert = core.willAlert || unaccepted > 0 || suspicious > 0 || snapshotFindings > 0;
            this.scanState = 'done';

            /* The aside reports the last scan, and this was one. */
            this.settings.is_ok = this.willAlert ? 'no' : 'yes';
            this.settings.last_checked_human = this.$t('a moment');
            this.coverage = {
                total: this.allTargets.length,
                verifiable: checked,
                checked: checked,
                unverifiable: this.allTargets.filter(item => this.isUnverified(item)).length,
                suspicious: suspicious,
                with_issues: withIssues,
                files: findings
            };
        }
    },
    mounted() {
        this.getSettings();
        this.loadBaseline();
        this.getTargets().catch(() => {
            /* The installed list is worth showing when it can be; not worth an error banner. */
        });

        /*
         * How many findings the Findings tab is holding, fetched purely so the bar above
         * reads the same from both sides - a badge that appears only once you are already
         * looking at the list is a badge that never told anybody anything. The bar is drawn
         * by the shell, above this screen, so the number is published rather than passed up.
         */
        this.$get('security-findings')
            .then(response => {
                subNavCounts.findings = response.counts.attention;
            })
            .catch(() => {
                /* The badge is a convenience; its absence is not worth reporting. */
            });
    },
    watch: {
        /*
         * Registering ends by sending you back here with auto_scan=yes, so the first scan
         * runs without asking again. Watched rather than done on mount, because the settings
         * that say whether scanning is possible arrive after the component does.
         */
        isReady(ready) {
            if (ready && this.$route.query.auto_scan === 'yes' && this.scanState === 'idle') {
                this.startScanning();
            }
        }
    }
}
</script>

<template>
    <div class="fls_page">
        <div class="fls_page_inner">
            <div class="fls_page_main">
                <div class="fls_page_head">
                    <div>
                        <h1 class="fls_page_title">{{ $t('Monitoring') }}</h1>
                        <p class="fls_page_desc">
                            {{ $t('Compares every WordPress core file, plugin and theme on this site against the official release on WordPress.org, so an unauthorised change cannot sit there unnoticed.') }}
                        </p>
                    </div>

                    <div v-if="isReady" class="fls_page_actions">
                        <el-button type="primary" :loading="scanState === 'scanning'"
                                   :disabled="scanState === 'scanning'" @click="startScanning">
                            {{ scanButtonLabel }}
                        </el-button>
                    </div>
                </div>

                <el-skeleton v-if="loading" :animated="true" :rows="8"/>

                <register-promt v-else-if="needsRegistration" :is_main="true"
                                :pre_settings="settings" @registered="getSettings()"/>

                <scan-results v-else-if="isReady"
                              :scan-state="scanState"
                              :results="results"
                              :has-issues="hasIssues"
                              :will-alert="willAlert"
                              :ignores="ignores"
                              :settings="settings"
                              :error-message="errorMessage"
                              :stale-warning="hasStaleWarning"
                              :plugins="pluginRows"
                              :themes="themeRows"
                              :unverified="unverified"
                              :checking-keys="checkingKeys"
                              :progress="progress"
                              :baseline="baseline"
                              :baseline-by-scope="baselineByScope"
                              :baseline-busy="baselineBusy"
                              :is-clean="isClean"
                              @scan="startScanning"
                              @recheck="recheckExtension"
                              @snapshot="takeSnapshot"/>

                <div v-else class="fls_dcard">
                    <el-empty :description="$t('Sorry! Settings could not be loaded. Please reload the page.')"/>
                </div>
            </div>

            <scanner-widgets v-if="isReady" :settings="settings" :ignores="ignores"
                             :coverage="coverage"
                             :baseline="baseline"
                             :baseline-busy="baselineBusy"
                             @snapshot="takeSnapshot"
                             @clear-baseline="clearBaseline"/>
        </div>
    </div>
</template>
