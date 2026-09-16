<script type="text/babel">
/*
 * The snapshot, as a standing fact in the configuration column.
 *
 * The offer to take one lives with the extensions it covers, under the sentence explaining why
 * they cannot be checked any other way - that is where somebody meets the problem, so that is
 * where the answer belongs. What is left here is what the right-hand column is for: how this
 * site is set up, stated plainly. When it covers nothing yet this says so in one line and
 * points at the list rather than making the same pitch twice on one screen.
 *
 * It holds no state of its own. The screen owns the snapshot, because three things read it and
 * a snapshot taken from one of them has to be the snapshot the other two see.
 */
export default {
    name: 'BaselinePanel',
    props: {
        baseline: {
            type: Object,
            default: () => ({
                exists: false, units: 0, files: 0, changed: 0, skipped: 0,
                partial_units: 0, taken_at: '', coverable: 0
            })
        },
        busy: {
            type: Boolean,
            default: false
        }
    },
    emits: ['snapshot', 'clear'],
    computed: {
        /* Nothing to snapshot: every extension on this site is in the directory. */
        isRedundant() {
            return !this.baseline.exists && !this.baseline.coverable;
        },
        /*
         * Grouped before it is pluralised - $_n strips the separators back out before counting,
         * so this stays correct and "29,726 files" stays readable, which five bare digits do not.
         */
        filesLabel() {
            return this.$_n('%s file', '%s files', Number(this.baseline.files || 0).toLocaleString());
        },
        unitsLabel() {
            return this.$_n('%s plugin or theme', '%s plugins and themes', this.baseline.units);
        },
        skippedLabel() {
            return this.$_n('%s file', '%s files', Number(this.baseline.skipped || 0).toLocaleString());
        },
        takenLabel() {
            if (!this.baseline.taken_at) {
                return '';
            }

            return new Date(this.baseline.taken_at.replace(' ', 'T')).toLocaleDateString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric'
            });
        }
    },
    methods: {
        clear() {
            this.$confirm(this.$t('__baseline_clear_confirm__'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, clear it')
            }).then(() => {
                this.$emit('clear');
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        }
    }
}
</script>

<template>
    <div v-if="!isRedundant" class="fls_aside_block" v-loading="busy">
        <h3>
            {{ $t('Your Snapshot') }}
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
                <li v-if="takenLabel">
                    <span class="fls_scan_fact_label">{{ $t('Taken') }}</span>
                    <span class="fls_scan_fact_value">{{ takenLabel }}</span>
                </li>
                <li v-if="baseline.changed">
                    <span class="fls_scan_fact_label">{{ $t('Changed') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag is_blocked">{{ baseline.changed }}</span>
                    </span>
                </li>
                <!--
                    Next to the number being watched, not folded into it. "Watching 29,726" and
                    "watching 29,726, missing 14,812" are different claims about the same site.
                -->
                <li v-if="baseline.skipped">
                    <span class="fls_scan_fact_label">{{ $t('Not watched') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag is_warning">{{ skippedLabel }}</span>
                    </span>
                </li>
            </ul>

            <p class="fls_note">{{ $t('__baseline_active_desc__') }}</p>

            <p v-if="baseline.skipped" class="fls_note is_warning">
                {{ $t('__baseline_partial_desc__') }}
            </p>

            <div class="fls_scan_aside_actions">
                <el-button size="small" :disabled="busy" @click="$emit('snapshot', [])">
                    {{ $t('Update snapshot') }}
                </el-button>
            </div>
        </template>

        <!--
            One line, not a second pitch. The full offer is beside the list it applies to, and
            saying it twice on one screen would make the screen look like it is asking for
            something rather than reporting on the site.
        -->
        <p v-else class="fls_note">{{ $t('__baseline_aside_promo__') }}</p>
    </div>
</template>
