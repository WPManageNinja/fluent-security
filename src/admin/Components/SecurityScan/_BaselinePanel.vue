<script type="text/babel">
/*
 * The site's own snapshot, in the aside beside the coverage it completes.
 *
 * This is the answer to the sentence directly above it - "these did not come from the
 * WordPress.org directory, so there is nothing to compare them against". A snapshot is that
 * something: not an official copy, but the site's own record of what these files were when
 * somebody last looked and was happy.
 *
 * The offer is deliberately worded around when to take it rather than what it does. A
 * snapshot taken of a site that has already been broken into records the break-in as normal,
 * and that is the single way this feature can fail its owner - so the copy says "once you are
 * happy with a scan", and the button is quiet rather than a call to action.
 */
export default {
    name: 'BaselinePanel',
    props: {
        /* Whether the last scan came back clean, so the moment can be named when it is right. */
        isClean: {
            type: Boolean,
            default: false
        }
    },
    data() {
        return {
            loading: true,
            saving: false,
            baseline: {exists: false, units: 0, files: 0, changed: 0, taken_at: '', coverable: 0}
        }
    },
    computed: {
        /* Nothing to snapshot: every extension on this site is in the directory. */
        isRedundant() {
            return !this.baseline.exists && this.baseline.coverable === 0;
        },
        filesLabel() {
            return this.$_n('%s file', '%s files', this.baseline.files);
        },
        unitsLabel() {
            return this.$_n('%s plugin or theme', '%s plugins and themes', this.baseline.units);
        }
    },
    methods: {
        load() {
            this.$get('baseline')
                .then(response => {
                    this.baseline = response.baseline;
                })
                .catch(() => {
                    /* The panel is worth showing when it can be; not worth an error banner. */
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        takeSnapshot() {
            this.saving = true;

            this.$post('baseline/snapshot')
                .then(response => {
                    this.$notify.success(response.message);
                    this.baseline = response.baseline;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        clear() {
            this.$confirm(this.$t('__baseline_clear_confirm__'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, clear it')
            }).then(() => {
                this.saving = true;

                this.$post('baseline/clear')
                    .then(response => {
                        this.$notify.success(response.message);
                        this.baseline = response.baseline;
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
    },
    mounted() {
        this.load();
    }
}
</script>

<template>
    <div v-if="!loading && !isRedundant" class="fls_aside_block" v-loading="saving">
        <h3>
            {{ $t('Your Own Snapshot') }}
            <el-button v-if="baseline.exists" text size="small" @click="clear()">
                {{ $t('Clear') }}
            </el-button>
        </h3>

        <template v-if="baseline.exists">
            <ul class="fls_scan_facts">
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Covers') }}</span>
                    <span class="fls_scan_fact_value">{{ unitsLabel }}</span>
                </li>
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Watching') }}</span>
                    <span class="fls_scan_fact_value">{{ filesLabel }}</span>
                </li>
                <li v-if="baseline.changed">
                    <span class="fls_scan_fact_label">{{ $t('Changed since') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag is_blocked">{{ baseline.changed }}</span>
                    </span>
                </li>
            </ul>

            <p class="fls_note">{{ $t('__baseline_active_desc__') }}</p>

            <div class="fls_scan_aside_actions">
                <el-button size="small" :disabled="saving" @click="takeSnapshot">
                    {{ $t('Update snapshot') }}
                </el-button>
            </div>
        </template>

        <template v-else>
            <p>{{ $t('__baseline_promo__') }}</p>

            <!--
                Named as the right moment rather than as a warning, because it is advice about
                when, not a hazard. Taking one of a site that has already been broken into
                records the break-in as normal - the one way this feature fails its owner.
            -->
            <p class="fls_note">
                <template v-if="isClean">{{ $t('__baseline_when_clean__') }}</template>
                <template v-else>{{ $t('__baseline_when_unclean__') }}</template>
            </p>

            <div class="fls_scan_aside_actions">
                <el-button :type="isClean ? 'primary' : 'default'" size="small"
                           :disabled="saving" @click="takeSnapshot">
                    {{ $t('Take a snapshot') }}
                </el-button>
            </div>
        </template>
    </div>
</template>
