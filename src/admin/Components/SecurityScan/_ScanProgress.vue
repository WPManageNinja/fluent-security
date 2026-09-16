<script type="text/babel">
import icons from './icons';

/*
 * Where a running scan has got to.
 *
 * A core-only scan was one request, so a sweeping bar was honest enough. Checking every
 * plugin and theme takes one request each and can run to a minute or more on a large site,
 * and an indeterminate bar for that long reads as a hang. So this says the real thing: which
 * phase is running, and how far through its list it is.
 *
 * The snapshot phase is only listed on sites that have taken one. A greyed-out step somebody
 * can never reach is a permanent unfinished-looking thing on a screen whose whole job is to
 * say whether this site is finished and fine.
 *
 * The phases stay on screen after they finish rather than being replaced, because "core was
 * fine" is worth seeing while the plugins are still going.
 */
export default {
    name: 'ScanProgress',
    props: {
        /* core | plugins | themes | baseline */
        phase: {
            type: String,
            required: true
        },
        /* Whether this site has a snapshot, and so whether there is a fourth phase at all. */
        hasBaseline: {
            type: Boolean,
            default: false
        },
        done: {
            type: Number,
            default: 0
        },
        total: {
            type: Number,
            default: 0
        },
        /* The plugin or theme being checked right now, named so the wait is legible. */
        current: {
            type: String,
            default: ''
        }
    },
    data() {
        return {
            icons
        }
    },
    computed: {
        phases() {
            const steps = [
                {key: 'core', label: this.$t('Core')},
                {key: 'plugins', label: this.$t('Plugins')},
                {key: 'themes', label: this.$t('Themes')}
            ];

            if (this.hasBaseline) {
                steps.push({key: 'baseline', label: this.$t('Snapshot')});
            }

            const at = steps.findIndex(item => item.key === this.phase);

            return steps.map((item, index) => ({
                ...item,
                state: index < at ? 'done' : (index === at ? 'active' : 'waiting')
            }));
        },
        /*
         * Core has no count of its own - it is one request - so it shows as a phase that is
         * simply under way. Only the two that walk a list get a proportion.
         */
        percent() {
            if (!this.total) {
                return null;
            }

            return Math.min(100, Math.round((this.done / this.total) * 100));
        },
        headline() {
            if (this.phase === 'core') {
                return this.$t('Checking WordPress core…');
            }

            if (this.phase === 'themes') {
                return this.$t('Checking themes…');
            }

            if (this.phase === 'baseline') {
                return this.$t('Checking against your snapshot…');
            }

            return this.$t('Checking plugins…');
        },
        /*
         * What the wait is actually doing, which stops being true in the last phase. Nothing
         * is reaching WordPress.org by then - the comparison is entirely local, against this
         * site's own record, which is the point of it.
         */
        subhead() {
            return this.phase === 'baseline'
                ? this.$t('Comparing your premium and custom plugins and themes with your snapshot.')
                : this.$t('Comparing your files with the official copies on WordPress.org.');
        }
    }
}
</script>

<template>
    <div class="fls_scan_state is_working">
        <span class="fls_scan_state_icon" v-html="icons.radar"></span>
        <h2>{{ headline }}</h2>

        <p v-if="current" class="fls_scan_current">{{ current }}</p>
        <p v-else>{{ subhead }}</p>

        <!-- A real proportion where there is one to give, and the sweep where there is not. -->
        <div v-if="percent !== null" class="fls_scan_meter">
            <div class="fls_scan_meter_bar" :style="{width: percent + '%'}"></div>
        </div>
        <div v-else class="fls_scan_progress"></div>

        <p v-if="total" class="fls_scan_meter_count">{{ done }} / {{ total }}</p>

        <ol class="fls_scan_phases">
            <li v-for="item in phases" :key="item.key" :class="'is_' + item.state">
                <span class="fls_scan_phase_mark" v-html="item.state === 'done' ? icons.tick : ''"></span>
                <span>{{ item.label }}</span>
            </li>
        </ol>
    </div>
</template>
