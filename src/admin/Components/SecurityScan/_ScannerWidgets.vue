<script type="text/babel">
import isEmpty from 'lodash/isEmpty';
import icons from './icons';
import BaselinePanel from './_BaselinePanel.vue';

/*
 * The right-hand column: how scanning is set up on this site.
 *
 * Deliberately not a second copy of the result. The column beside it is what one scan
 * found; this is the standing arrangement - whether it runs on its own, where the alert
 * goes, and what it has been told to stop mentioning.
 */
export default {
    name: 'ScannerWidgets',
    components: {
        BaselinePanel
    },
    props: {
        settings: {
            type: Object,
            required: true
        },
        ignores: {
            type: Object,
            required: true
        },
        /* How much of wp-content the last scan could actually vouch for. */
        coverage: {
            type: Object,
            default: null
        },
        /* The site's own record of what the directory cannot vouch for. Owned by the screen. */
        baseline: {
            type: Object,
            default: () => ({exists: false, units: 0, files: 0, changed: 0, taken_at: '', coverable: 0})
        },
        baselineBusy: {
            type: Boolean,
            default: false
        }
    },
    emits: ['snapshot', 'clear-baseline'],
    data() {
        return {
            icons,
            scheduling: {
                auto_scan: this.settings.auto_scan,
                scan_interval: this.settings.scan_interval
            },
            /* Open only while the interval is being chosen, so the panel is not a form by default. */
            editingSchedule: false,
            saving: false
        }
    },
    computed: {
        hasIgnores() {
            return !isEmpty(this.ignores.folders) || !isEmpty(this.ignores.files);
        },
        hasCoverage() {
            return this.coverage && this.coverage.total > 0;
        },
        /*
         * Said as a fraction of everything installed, not of everything checkable. "14 of 14"
         * out of twenty-six installed plugins would be a true sentence and a misleading one.
         */
        coverageLabel() {
            return this.$t('%s of %s', this.coverage.checked, this.coverage.total);
        },
        isScheduled() {
            return this.settings.status === 'active' && this.settings.auto_scan === 'yes';
        },
        /*
         * Disowned from the alerts dashboard. Two states, because the way back differs: a
         * disabled site keeps a working key and needs one click, a deleted one has to be set
         * up from scratch.
         */
        relayDisabled() {
            return this.settings.relay_rejection === 'disabled';
        },
        relayRevoked() {
            return this.settings.relay_rejection === 'revoked';
        },
        /*
         * Why the relay refused, in the most specific words available.
         *
         * Three sources, in order. A reason we have a sentence for wins, because ours is
         * translated and the relay's is English whatever the site's language. Failing that,
         * the relay's own message - it knows things this build cannot, and a cause added
         * over there should reach the reader without waiting for a plugin release. Failing
         * both, null, and the generic paragraph stands as it always has.
         *
         * Interpolated as text, never v-html: this string arrives over the network.
         */
        relayReason() {
            const known = {
                superseded: '__relay_reason_superseded__',
                removed: '__relay_reason_removed__'
            };

            const key = known[this.settings.relay_rejection_reason];

            if (key) {
                return this.$t(key);
            }

            return this.settings.relay_rejection_note || null;
        },
        /*
         * One map, so the picker and the row that reports the choice cannot drift into naming
         * the same interval two different ways.
         */
        intervalLabels() {
            return {
                hourly: this.$t('Every hour'),
                six_hourly: this.$t('Every 6 hours'),
                twelve_hourly: this.$t('Every 12 hours'),
                daily: this.$t('Every day')
            };
        },
        intervalLabel() {
            return this.intervalLabels[this.settings.scan_interval] || this.intervalLabels.daily;
        },
        lastScan() {
            if (!this.settings.last_checked_human) {
                return this.$t('Not run yet');
            }

            return this.$t('%s ago', this.settings.last_checked_human);
        }
    },
    methods: {
        /*
         * Always opened on what is actually saved. The picker is reachable twice over now, and
         * a second visit that still showed the first visit's abandoned choice would be offering
         * to save something nobody asked for.
         */
        startEditingSchedule() {
            this.scheduling.scan_interval = this.settings.scan_interval;
            this.editingSchedule = true;
        },
        cancelEditingSchedule() {
            this.scheduling.scan_interval = this.settings.scan_interval;
            this.editingSchedule = false;
        },
        saveSchedulingSettings() {
            this.saving = true;
            this.scheduling.auto_scan = 'yes';

            this.$post('security-scan-settings/scan/update-schedule-scan', this.scheduling)
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings.auto_scan = response.settings.auto_scan;
                    this.settings.scan_interval = response.settings.scan_interval;
                    this.editingSchedule = false;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        disableSchedule() {
            this.saving = true;

            this.$post('security-scan-settings/scan/update-schedule-scan', {
                auto_scan: 'no',
                scan_interval: this.scheduling.scan_interval
            })
                .then(response => {
                    this.$notify.success(response.message);
                    this.scheduling.auto_scan = 'no';
                    this.settings.auto_scan = response.settings.auto_scan;
                    this.settings.scan_interval = response.settings.scan_interval;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        /*
         * Disconnecting, which is a good deal more than the link used to admit.
         *
         * It tells the relay to stop accepting this site and then clears the credentials here,
         * and the key is the only copy - there is no reconnecting afterwards, only registering
         * again and confirming a new key by email. It was a bare link reading "please click
         * here" at the end of a sentence about changing an email address, with no confirmation
         * at all, next to a reset of the ignore list that asks for one.
         */
        resetApi() {
            this.$confirm(this.$t('__disconnect_confirm__'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, disconnect')
            }).then(() => {
                this.saving = true;

                this.$post('security-scan-settings/scan/reset-api')
                    .then(response => {
                        this.$notify.success(response.message);
                        window.location.reload();
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.saving = false;
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        /*
         * The owner re-enabled this site on the dashboard; find out whether they actually did.
         *
         * The server posts a report as the probe rather than taking the click at its word - a
         * still-disabled site answers with the same refusal, and the panel goes back to saying
         * so instead of showing a connection that is not there.
         */
        resumeReporting() {
            this.saving = true;

            this.$post('security-scan-settings/scan/resume-reporting')
                .then(response => {
                    this.$notify.success(response.message);
                    window.location.reload();
                })
                .catch(errors => {
                    this.$handleError(errors);

                    /*
                     * A refusal still moves this site: still-disabled puts it back where it
                     * was, and an unreachable relay leaves it reporting but unconfirmed. Take
                     * the state the server reports rather than reloading, which would throw
                     * away the message explaining why.
                     */
                    const settings = errors && errors.data && errors.data.settings;

                    if (settings) {
                        Object.assign(this.settings, settings);
                    }
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        resetIgnores() {
            this.$confirm(this.$t('Are you sure you want to reset the ignored files and folders?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, Reset')
            }).then(() => {
                this.saving = true;

                this.$post('security-scan-settings/scan/reset-ignores')
                    .then(response => {
                        this.$notify.success(response.message);
                        window.location.reload();
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.saving = false;
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        }
    }
}
</script>

<template>
    <aside class="fls_page_aside" v-loading="saving">
        <div class="fls_aside_block">
            <h3>{{ $t('Scheduled Scanning') }}</h3>

            <!--
                Choosing the interval. Reached from either state - switching scheduling on for
                the first time, and changing how often it runs afterwards - so the form is one
                block rather than a copy inside each.
            -->
            <template v-if="editingSchedule">
                <el-form label-position="top">
                    <el-form-item :label="$t('Scanning Interval')">
                        <el-select v-model="scheduling.scan_interval"
                                   :placeholder="$t('Select Interval')">
                            <el-option v-for="(label, value) in intervalLabels"
                                       :key="value" :label="label" :value="value"/>
                        </el-select>
                    </el-form-item>
                </el-form>

                <div class="fls_scan_aside_actions">
                    <el-button type="primary" size="small" :disabled="saving"
                               @click="saveSchedulingSettings">
                        {{ $t('Save') }}
                    </el-button>
                    <el-button size="small" @click="cancelEditingSchedule">
                        {{ $t('Cancel') }}
                    </el-button>
                </div>
            </template>

            <!-- Running on a schedule: what it does, how often, and how to stop it. -->
            <template v-else-if="isScheduled">
                <ul class="fls_scan_facts">
                    <li>
                        <span class="fls_scan_fact_label">{{ $t('Runs') }}</span>
                        <span class="fls_scan_fact_value">{{ intervalLabel }}</span>
                    </li>
                    <li>
                        <span class="fls_scan_fact_label">{{ $t('Alerts go to') }}</span>
                        <span class="fls_scan_fact_value">{{ settings.account_email_id }}</span>
                    </li>
                </ul>

                <p class="fls_note">{{ $t('__autoscan_active_desc__') }}</p>

                <div class="fls_scan_aside_actions">
                    <el-button size="small" @click="startEditingSchedule">
                        {{ $t('Change interval') }}
                    </el-button>
                    <el-button size="small" :disabled="saving" @click="disableSchedule">
                        {{ $t('Turn off') }}
                    </el-button>
                </div>
            </template>

            <!-- Has an API key, has not switched scheduling on. -->
            <template v-else-if="settings.status === 'active'">
                <p>{{ $t('__autoscan_promo__') }}</p>

                <div class="fls_scan_aside_actions">
                    <el-button type="primary" size="small" @click="startEditingSchedule">
                        {{ $t('Enable Auto Scanning') }}
                    </el-button>
                </div>
            </template>

            <!-- Switched off on the dashboard. The key still works, so this is one click away. -->
            <template v-else-if="relayDisabled">
                <p v-if="relayReason" class="fls_relay_notice">{{ relayReason }}</p>
                <p class="fls_relay_notice">{{ $t('__relay_disabled_desc__') }}</p>

                <div class="fls_scan_aside_actions">
                    <el-button type="primary" size="small" :disabled="saving" @click="resumeReporting">
                        {{ $t('Resume Reporting') }}
                    </el-button>
                </div>
            </template>

            <!-- Scanning without the service: no key, so no alerts to send. -->
            <template v-else>
                <template v-if="relayRevoked">
                    <template v-if="relayReason">
                        <p class="fls_relay_notice">{{ relayReason }}</p>
                        <p class="fls_relay_notice">{{ $t('__relay_revoked_next__') }}</p>
                    </template>
                    <p v-else class="fls_relay_notice">{{ $t('__relay_revoked_desc__') }}</p>
                </template>
                <p v-else>
                    {{ $t('Please get a free API key to enable Scheduled Scanning and get notified when FluentAuth detects file changes.') }}
                </p>

                <div class="fls_scan_aside_actions">
                    <el-button type="primary" size="small"
                               @click="$router.push({name: 'security_scan_register'})">
                        {{ $t('Setup Auto Scanning') }}
                    </el-button>
                </div>
            </template>
        </div>

        <div class="fls_aside_block">
            <h3>{{ $t('Last Scan') }}</h3>

            <ul class="fls_scan_facts">
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Ran') }}</span>
                    <span class="fls_scan_fact_value">{{ lastScan }}</span>
                </li>
                <li v-if="settings.last_checked_human">
                    <span class="fls_scan_fact_label">{{ $t('Result') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag" :class="settings.is_ok === 'yes' ? 'is_success' : 'is_warning'">
                            {{ settings.is_ok === 'yes' ? $t('No changes') : $t('Found changes') }}
                        </span>
                    </span>
                </li>
            </ul>

            <p v-if="settings.status === 'active'" class="fls_note">
                {{ $t('__disconnect_note__') }}
                <a href="#" @click.prevent="resetApi()">{{ $t('Disconnect this site') }}</a>.
            </p>
        </div>

        <!--
            What the scan was able to cover. Only plugins and themes from the WordPress.org
            directory have an official copy to compare against, so this is where the shortfall
            gets stated plainly rather than left to be inferred from a clean result.
        -->
        <div v-if="hasCoverage" class="fls_aside_block">
            <h3>{{ $t('Plugins & Themes') }}</h3>

            <ul class="fls_scan_facts">
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Verified') }}</span>
                    <span class="fls_scan_fact_value">{{ coverageLabel }}</span>
                </li>
                <li v-if="coverage.with_issues">
                    <span class="fls_scan_fact_label">{{ $t('With changes') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag is_warning">{{ coverage.with_issues }}</span>
                    </span>
                </li>
                <!-- Its own line, above the coverage note: a finding, not a gap. -->
                <li v-if="coverage.suspicious">
                    <span class="fls_scan_fact_label">{{ $t('Unpublished versions') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag is_blocked">{{ coverage.suspicious }}</span>
                    </span>
                </li>
            </ul>

            <p v-if="coverage.unverifiable" class="fls_note">
                {{ $_n('%s item is not from the WordPress.org directory, so there are no official checksums to compare it against.', '%s items are not from the WordPress.org directory, so there are no official checksums to compare them against.', coverage.unverifiable) }}
            </p>
        </div>

        <!--
            Directly under the coverage it completes: the panel above says what cannot be
            checked against WordPress.org, and this is the only other thing there is to check
            those against - the site's own record of them.
        -->
        <baseline-panel :baseline="baseline" :busy="baselineBusy"
                        @snapshot="$emit('snapshot', $event)"
                        @clear="$emit('clear-baseline')"/>

        <div v-if="hasIgnores" class="fls_aside_block">
            <h3>
                {{ $t('Ignored Files & Folders') }}
                <el-button text size="small" @click="resetIgnores()">{{ $t('Reset') }}</el-button>
            </h3>

            <ul class="fls_scan_ignores">
                <li v-for="folder in ignores.folders" :key="folder">
                    <span v-html="icons.folder"></span>
                    <span>{{ folder }}</span>
                </li>
                <li v-for="file in ignores.files" :key="file">
                    <span v-html="icons.file"></span>
                    <span>{{ file }}</span>
                </li>
            </ul>
        </div>
    </aside>
</template>
