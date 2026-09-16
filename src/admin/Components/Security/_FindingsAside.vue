<script type="text/babel">
export default {
    name: 'FindingsAside',
    emits: ['retry'],
    props: {
        score: {type: Object, required: true},
        scan: {type: Object, default: null},
        loading: Boolean,
        error: Boolean
    },
    computed: {
        percent() {
            return this.score.total ? Math.max(0, Math.min(100, this.score.percent || 0)) : 0;
        },
        fileWatchLabel() {
            if (this.loading) return this.$t('Loading…');
            if (this.error || !this.scan) return this.$t('Unavailable');
            return this.scan.last_checked_human ? this.$t('%s ago', this.scan.last_checked_human) : this.$t('Not run yet');
        }
    }
};
</script>

<template>
    <aside class="fls_security_aside">
        <section class="fls_security_coverage">
            <h2>{{ $t('Recommended checks') }}</h2>
            <p class="fls_security_coverage_value">
                <strong>{{ score.done }}</strong> <span>{{ $t('of %s addressed', score.total) }}</span>
            </p>
            <div class="fls_security_coverage_track" role="progressbar" :aria-label="$t('Recommended checks addressed')"
                 :aria-valuenow="percent" :aria-valuemin="0" :aria-valuemax="100">
                <span :style="{width: percent + '%'}"></span>
            </div>
            <p>{{ $t('Includes passed and accepted recommendations. Review other findings and file monitoring separately.') }}</p>
        </section>

        <section class="fls_security_monitoring">
            <h2>{{ $t('File monitoring') }}</h2>
            <dl>
                <dt>{{ $t('Last file check') }}</dt>
                <dd>{{ fileWatchLabel }}</dd>
            </dl>
            <p v-if="!loading && !error && scan && scan.is_ok === 'no'" class="fls_security_monitoring_warning">
                {{ $t('The last file check needs review.') }}
            </p>
            <p>{{ $t('Recheck refreshes these findings. File scans run separately in Monitoring.') }}</p>
            <el-button v-if="error" size="small" @click="$emit('retry')">{{ $t('Retry status') }}</el-button>
            <router-link :to="{name: 'security_scans'}" class="fls_security_aside_link">
                {{ $t('Review file monitoring') }} <span aria-hidden="true">→</span>
            </router-link>
        </section>
        <section class="fls_security_help">
            <h2>{{ $t('Suspect a compromised account?') }}</h2>
            <p>{{ $t('Review active sessions and account recovery options.') }}</p>
            <router-link :to="{name: 'security_recovery'}" class="fls_security_aside_link">{{ $t('Been Hacked?') }} <span aria-hidden="true">→</span></router-link>
        </section>
    </aside>
</template>
