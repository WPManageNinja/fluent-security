<script type="text/babel">
/* One glyph, and it is the only one this component needs. */
import icons from '../SecurityScan/icons';

/*
 * One finding, and the whole vocabulary of the security screen.
 *
 * Three levels of disclosure, and the reader we are designing for stops at the second. The
 * title says what is true of this site, the line under it says why that matters, and the
 * button does the thing. Everything a developer would want - paths, hashes, dates, setting
 * names - is behind "Show details", present and not first.
 *
 * There is no severity word in the row beyond the pill. The stripe carries it, so the shape
 * of a list reads before any of it is read.
 */
export default {
    name: 'FindingRow',
    props: {
        finding: {
            type: Object,
            required: true
        },
        /* This row's own request is in flight - only its button spins. */
        busy: {
            type: Boolean,
            default: false
        }
    },
    emits: ['fix', 'accept', 'navigate'],
    data() {
        return {
            icons,
            showDetails: false
        }
    },
    computed: {
        isCritical() {
            return this.finding.severity === 'fix';
        },
        severityLabel() {
            return this.isCritical ? this.$t('Fix this') : this.$t('Worth a look');
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

            return this.$_n('Show detail', 'Show %s details', this.finding.details.length);
        },
        /*
         * A finding that can only point at where the work is done still gets a button, but it
         * says so. "Turn on" that navigates somewhere is the one label that would be a lie.
         */
        primaryLabel() {
            return this.finding.label || (this.finding.action === 'fix' ? this.$t('Turn on') : this.$t('Set up'));
        },
        dismissLabel() {
            return this.finding.dismiss === 'expected' ? this.$t('Expected') : this.$t('Ignore');
        }
    },
    methods: {
        onPrimary() {
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
    <div class="fls_finding" :class="isCritical ? 'is_fix' : 'is_look'">
        <span class="fls_finding_stripe"></span>

        <div class="fls_finding_body">
            <div class="fls_finding_meta">
                <span class="fls_tag" :class="isCritical ? 'is_blocked' : 'is_warning'">
                    {{ severityLabel }}
                </span>
                <span class="fls_finding_group">{{ groupLabel }}</span>
            </div>

            <h3 class="fls_finding_title">{{ finding.title }}</h3>
            <p v-if="finding.why" class="fls_finding_why">{{ finding.why }}</p>

            <button v-if="hasDetails" type="button" class="fls_finding_toggle"
                    :aria-expanded="showDetails ? 'true' : 'false'"
                    @click="showDetails = !showDetails">
                <span class="fls_finding_chev" :class="{is_open: showDetails}" v-html="icons.chevron"></span>
                {{ detailsLabel }}
            </button>

            <ul v-if="hasDetails && showDetails" class="fls_finding_details">
                <li v-for="(detail, index) in finding.details" :key="index">{{ detail }}</li>
            </ul>
        </div>

        <div class="fls_finding_actions">
            <el-button v-if="finding.action !== 'none'" type="primary" size="small"
                       :loading="busy" @click="onPrimary">
                {{ primaryLabel }}
            </el-button>
            <el-button v-if="finding.dismiss" size="small" :disabled="busy"
                       @click="$emit('accept', finding)">
                {{ dismissLabel }}
            </el-button>
        </div>
    </div>
</template>
