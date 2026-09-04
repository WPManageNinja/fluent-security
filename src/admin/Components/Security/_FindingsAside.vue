<script type="text/babel">
/*
 * The right-hand column: how this site is doing overall, and what the list does not cover.
 *
 * The score is out of what the plugin recommends for every site, not out of everything it
 * knows how to check - so it stays reachable. The last block exists because the findings on
 * the left are only the instant checks: whether anyone has looked at the files lately is a
 * different question, answered on the other tab, and a screen that said "everything checked
 * out" without mentioning that would be overstating what it knows.
 */
export default {
    name: 'FindingsAside',
    props: {
        score: {
            type: Object,
            required: true
        },
        counts: {
            type: Object,
            required: true
        },
        /* The scan settings, so the file half of the picture can be summarised honestly. */
        scan: {
            type: Object,
            default: null
        }
    },
    computed: {
        percent() {
            return this.score.total ? this.score.percent : 100;
        },
        fileWatchLabel() {
            if (!this.scan || !this.scan.last_checked_human) {
                return this.$t('Never');
            }

            return this.$t('%s ago', this.scan.last_checked_human);
        },
        fileWatchWarning() {
            return !this.scan || !this.scan.last_checked_human || this.scan.is_ok === 'no';
        }
    }
}
</script>

<template>
    <aside class="fls_page_aside">
        <div class="fls_aside_block">
            <h3>
                {{ $t('Security Score') }}
                <small>{{ $t('%1s of %2s', score.done, score.total) }}</small>
            </h3>

            <div class="fls_dash_score">
                <div class="fls_dash_score_track">
                    <div class="fls_dash_score_fill" :style="{width: percent + '%'}"></div>
                </div>
            </div>

            <p class="fls_note">{{ $t('__security_score_desc__') }}</p>
        </div>

        <div class="fls_aside_block">
            <h3>{{ $t('At a Glance') }}</h3>

            <ul class="fls_scan_facts">
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Needs fixing') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag" :class="counts.to_fix ? 'is_blocked' : 'is_success'">
                            {{ counts.to_fix }}
                        </span>
                    </span>
                </li>
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Worth a look') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag" :class="counts.look ? 'is_warning' : 'is_neutral'">
                            {{ counts.look }}
                        </span>
                    </span>
                </li>
                <li v-if="counts.advice">
                    <span class="fls_scan_fact_label">{{ $t('Best practice') }}</span>
                    <span class="fls_scan_fact_value">
                        <span class="fls_tag is_neutral">{{ counts.advice }}</span>
                    </span>
                </li>
                <li>
                    <span class="fls_scan_fact_label">{{ $t('Checks passed') }}</span>
                    <span class="fls_scan_fact_value">{{ counts.passed }}</span>
                </li>
            </ul>
        </div>

        <div class="fls_aside_block">
            <h3>{{ $t('File Checks') }}</h3>

            <ul class="fls_scan_facts">
                <li :class="{is_warning: fileWatchWarning}">
                    <span class="fls_scan_fact_label">{{ $t('Last run') }}</span>
                    <span class="fls_scan_fact_value">{{ fileWatchLabel }}</span>
                </li>
            </ul>

            <p class="fls_note">{{ $t('__findings_deep_scan_note__') }}</p>

            <div class="fls_scan_aside_actions">
                <el-button size="small" @click="$router.push({name: 'security_scans'})">
                    {{ $t('Go to Monitoring') }}
                </el-button>
            </div>
        </div>
    </aside>
</template>
