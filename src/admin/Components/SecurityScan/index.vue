<script type="text/babel">
import icons from './icons';
import RegisterPromt from './RegisterPromt.vue';
import ScanResults from './_ScanResults.vue';
import ScannerWidgets from './_ScannerWidgets.vue';
import SecurityTabs from '../Security/_SecurityTabs.vue';

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
 * A scan is three phases - core, then every plugin, then every theme - and the walk across
 * plugins and themes is driven from here, one request per extension. That is not a stylistic
 * choice: a site with forty plugins cannot be checked inside one request without hitting
 * max_execution_time, and a scan that dies half way reports nothing at all. Driving it from
 * the browser also means the wait can show its real progress instead of a spinner.
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
        SecurityTabs
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
            /* In flight right now - more than one, because the walk runs a few at a time. */
            checkingKeys: [],
            coverage: null,
            /*
             * How many findings the other tab is holding. Fetched here purely so the tab bar
             * reads the same from both sides - a badge that appears only once you are already
             * looking at the list is a badge that never told anybody anything.
             */
            openFindings: 0,
            progress: {
                phase: 'core',
                done: 0,
                total: 0,
                current: ''
            }
        }
    },
    computed: {
        /* Scanning is available once the site has an API key, or has opted out of needing one. */
        isReady() {
            return this.settings && (this.settings.status === 'active' || this.settings.status === 'self');
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
                     * picture rather than a page of "not checked yet".
                     */
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

            this.hasIssues = core.hasIssues || findings > 0 || suspicious > 0;
            this.willAlert = core.willAlert || unaccepted > 0 || suspicious > 0;
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
        this.getTargets().catch(() => {
            /* The installed list is worth showing when it can be; not worth an error banner. */
        });

        this.$get('security-findings')
            .then(response => {
                this.openFindings = response.counts.attention;
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
                        <h1 class="fls_page_title">{{ $t('Security') }}</h1>
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

                <security-tabs :open-count="openFindings"/>

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
                              @scan="startScanning"/>

                <div v-else class="fls_dcard">
                    <el-empty :description="$t('Sorry! Settings could not be loaded. Please reload the page.')"/>
                </div>
            </div>

            <scanner-widgets v-if="isReady" :settings="settings" :ignores="ignores"
                             :coverage="coverage"/>
        </div>
    </div>
</template>
