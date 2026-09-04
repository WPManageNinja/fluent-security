<script type="text/babel">
import icons from '../SecurityScan/icons';

export default {
    name: 'FindingRow',
    props: {
        finding: {
            type: Object,
            required: true
        },
        /* This row's own request is in flight - only its button spins. */
        disabled: Boolean,
        busy: {
            type: Boolean,
            default: false
        }
    },
    emits: ['fix', 'accept', 'unaccept', 'navigate'],
    data() {
        return {
            icons,
            showDetails: false,
            confirmDismiss: false
        }
    },
    computed: {
        isPassed() {
            return this.finding.state === 'passed';
        },
        isAccepted() {
            return this.finding.state === 'accepted';
        },
        dismissExplanation() {
            if (this.finding.dismiss === 'expected') {
                return this.$t('Mark the current state as expected. This check can report a finding again when that state changes.');
            }
            if (this.finding.dismiss === 'aside') {
                return this.$t('Remove this item from the score. It will remain visible so you can keep track of it.');
            }
            return this.$t('This finding will stop being reported while it is dismissed. You can restore it from Dismissed. This does not fix the underlying issue.');
        },
        isCritical() {
            return this.finding.severity === 'fix';
        },
        isAdvice() {
            return this.finding.severity === 'advice';
        },
        /* Anything unrecognised reads as "worth a look" - the same fallback the server sorts by. */
        toneClass() {
            if (this.isPassed) return 'is_passed';
            if (this.isAccepted) return 'is_accepted';
            if (this.isCritical) {
                return 'is_fix';
            }

            return this.isAdvice ? 'is_advice' : 'is_look';
        },
        severityLabel() {
            if (this.isCritical) {
                return this.$t('Action needed');
            }

            return this.isAdvice ? this.$t('Recommendation') : this.$t('Review');
        },
        severityTagClass() {
            if (this.isCritical) {
                return 'is_blocked';
            }

            return this.isAdvice ? 'is_neutral' : 'is_warning';
        },
        groupLabel() {
            const labels = {
                files: this.$t('Files'),
                config: this.$t('Configuration'),
                login: this.$t('Login'),
                users: this.$t('Users'),
                plugins: this.$t('Plugins & Themes')
            };

            return labels[this.finding.group] || this.finding.group;
        },
        hasDetails() {
            return !!(this.finding.details && this.finding.details.length);
        },
        detailsLabel() {
            if (this.showDetails) {
                return this.$t('Hide details');
            }

            if (this.finding.action === 'none' && !this.isPassed && !this.isAccepted) return this.$t('View instructions');

            return this.$_n('Show detail', 'Show %s details', this.finding.details.length);
        },
        /*
         * A finding that can only point at where the work is done still gets a button, but it
         * says so. "Turn on" that navigates somewhere is the one label that would be a lie.
         */
        primaryLabel() {
            return this.finding.label || (this.finding.action === 'fix' ? this.$t('Turn on') : this.$t('Set up'));
        },
        /*
         * `undo` is the row after it has been set aside - the only dismissal state that draws
         * its own way back, because the row stays on the list rather than moving to the
         * settled ones where every other undo lives.
         */
        isSetAside() {
            return this.finding.dismiss === 'undo';
        },
        dismissLabel() {
            const labels = {
                expected: this.$t('Mark as expected'),
                aside: this.$t('Not mine to fix'),
                undo: this.$t('Count it again')
            };

            return labels[this.finding.dismiss] || this.$t('Dismiss');
        }
    },
    watch: {
        disabled(value) {
            if (value) this.confirmDismiss = false;
        }
    },
    methods: {
        requestDismiss() {
            if (this.disabled) return;
            if (this.isSetAside) {
                this.$emit('unaccept', this.finding);
            } else {
                this.confirmDismiss = true;
            }
        },
        onPrimary() {
            if (this.disabled) return;
            if (this.finding.action === 'fix') {
                this.$emit('fix', this.finding);
                return;
            }

            this.$emit('navigate', this.finding);
        }
    }
}
</script>

<template>
    <article class="fls_finding" :class="toneClass" :aria-label="finding.title">
        <span class="fls_finding_status" aria-hidden="true"
              v-html="isPassed ? icons.tick : isAccepted ? icons.mute : isCritical ? icons.alert : icons.shield"></span>
        <div class="fls_finding_body">
            <div class="fls_finding_meta">
                <span class="fls_finding_group">{{ groupLabel }}</span>
                <span v-if="!isPassed && !isAccepted" class="fls_tag" :class="severityTagClass">{{ severityLabel }}</span>
                <span v-if="isSetAside" class="fls_tag is_neutral">{{ $t('Excluded from score') }}</span>
            </div>
            <h3 class="fls_finding_title">{{ finding.title }}</h3>
            <p v-if="finding.why && !isPassed" class="fls_finding_why">{{ finding.why }}</p>
            <button v-if="hasDetails" type="button" class="fls_finding_toggle"
                    :aria-expanded="showDetails" :aria-controls="'finding-details-' + finding.id"
                    @click="showDetails = !showDetails">
                <span class="fls_finding_chev" :class="{is_open: showDetails}" aria-hidden="true" v-html="icons.chevron"></span>
                {{ detailsLabel }}
            </button>
        </div>
        <div v-if="!isPassed" class="fls_finding_actions">
            <el-button v-if="isAccepted" size="small" :loading="busy" :disabled="disabled" @click="$emit('unaccept', finding)">
                {{ $t('Restore finding') }}
            </el-button>
            <template v-else>
                <el-button v-if="finding.url" size="small" tag="a" :href="finding.url" target="_blank" rel="noopener noreferrer"
                           :aria-label="$t('%s (opens in a new tab)', primaryLabel)">
                    {{ primaryLabel }} <span aria-hidden="true">↗</span>
                </el-button>
                <el-button v-else-if="finding.action !== 'none'" :type="isCritical ? 'primary' : 'default'" size="small"
                           :loading="busy" :disabled="disabled" @click="onPrimary">
                    {{ primaryLabel }} <span v-if="finding.action === 'navigate'" aria-hidden="true">→</span>
                </el-button>
                <el-button v-if="finding.dismiss" text size="small" :disabled="disabled" @click="requestDismiss">
                    {{ dismissLabel }}
                </el-button>
            </template>
        </div>
        <ul v-if="hasDetails && showDetails" :id="'finding-details-' + finding.id" class="fls_finding_details">
            <li v-for="(detail, index) in finding.details" :key="index">{{ detail }}</li>
        </ul>
        <div v-if="confirmDismiss" class="fls_finding_confirm" role="group" :aria-label="$t('Dismiss finding')">
            <p>{{ dismissExplanation }}</p>
            <div>
                <el-button size="small" @click="confirmDismiss = false">{{ $t('Cancel') }}</el-button>
                <el-button size="small" type="primary" :disabled="disabled" @click="$emit('accept', finding)">{{ dismissLabel }}</el-button>
            </div>
        </div>
    </article>
</template>
