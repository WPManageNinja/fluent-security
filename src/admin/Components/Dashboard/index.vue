<script type="text/babel">
import icons from './icons';
import RivalNotice from '../TwoFa/_RivalNotice.vue';
import ActivityChart from './_ActivityChart.vue';
import LogList from './_LogList.vue';
import SecurityAside from './_SecurityAside.vue';

export default {
    name: 'Dashboard',
    components: {
        RivalNotice,
        ActivityChart,
        LogList,
        SecurityAside
    },
    data() {
        return {
            icons,
            loading: false,
            loadError: false,
            loadedRange: '-30 days',
            recentView: 'threats',
            pendingBlock: null,
            dashboard: false,
            /* Which address is mid-request, so only its own button spins. */
            blocking: '',
            range: '-30 days',
            ranges: [
                {value: '-0 days', label: this.$t('Today')},
                {value: '-7 days', label: this.$t('Last 7 days')},
                {value: '-30 days', label: this.$t('Last 30 days')},
                {value: 'this_month', label: this.$t('This month')},
                {value: 'all_time', label: this.$t('All time')}
            ]
        }
    },
    computed: {
        activityStats() {
            return this.dashboard ? this.dashboard.stats.filter(stat => stat.key !== 'two_fa') : [];
        },
        rangeLabel() {
            return this.ranges.find(item => item.value === this.loadedRange)?.label || '';
        },
        recentLogs() {
            return this.dashboard.recent[this.recentView];
        },
        /*
         * Local time rather than the site's: this greets the person reading it, and they
         * are the one whose evening it is.
         */
        greeting() {
            const hour = new Date().getHours();

            if (hour < 12) {
                return this.$t('Good morning %s', this.appVars.me.full_name);
            }

            if (hour < 18) {
                return this.$t('Good afternoon %s', this.appVars.me.full_name);
            }

            return this.$t('Good evening %s', this.appVars.me.full_name);
        }
    },
    methods: {
        async fetchDashboard() {
            if (this.loading || this.blocking) return;
            this.loading = true;
            this.loadError = false;
            const requestedRange = this.range;
            try {
                const response = await this.$get('dashboard', {day_range: requestedRange});
                this.dashboard = response;
                this.loadedRange = requestedRange;
                this.pendingBlock = null;
            } catch (errors) {
                this.loadError = true;
                this.range = this.loadedRange;
                this.$handleError(errors);
            } finally {
                this.loading = false;
            }
        },
        /*
         * Refuses the address outright from here on. The row is marked blocked rather than
         * removed: it is still the evidence for why, and taking it away would leave the card
         * looking like the attempts had stopped.
         */
        blockIp(row) {
            if (this.blocking || this.loading || this.pendingBlock !== row) return;
            this.blocking = row.ip;

            return this.$post('ip-rules/add', {type: 'block', ip: row.ip})
                .then(response => {
                    this.$notify.success(response.message);
                    row.is_blocked = true;
                    this.pendingBlock = null;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.blocking = '';
                });
        },
        /* Tiles link into the logs table with their own status already selected. */
        statTarget(stat) {
            const target = {name: stat.route};

            if (stat.query) {
                target.query = stat.query;
            }

            return target;
        }
    },
    mounted() {
        this.fetchDashboard();
    }
}
</script>

<template>
    <div class="fls_page fls_dashboard">
        <header class="fls_dashboard__header">
            <div>
                <h1>{{ $t('Dashboard') }}</h1>
                <p>{{ greeting }}. {{ $t('Your site’s login activity and security status, in one place.') }}</p>
            </div>
            <div class="fls_dashboard__actions">
                <el-button @click="$router.push({name: 'settings_general'})">{{ $t('Security settings') }}</el-button>
                <el-button type="primary" @click="$router.push({name: 'security_scans'})">{{ $t('Scan files') }}</el-button>
            </div>
        </header>
        <div v-if="loadError" class="fls_dashboard__error" role="alert">
            <span>{{ dashboard ? $t('Could not refresh activity. Your last loaded results are still shown.') : $t('Could not load your dashboard. Please try again.') }}</span>
            <el-button size="small" :loading="loading" @click="fetchDashboard">{{ $t('Try again') }}</el-button>
        </div>
        <!--
            Above the whole dashboard, not in the aside. Sign-ins are failing; that outranks
            the week's login counts, and the aside is where standing arrangements live. Same
            component the settings page draws - see _RivalNotice.vue.
        -->
        <RivalNotice v-if="dashboard" :notice="dashboard.two_fa_conflict"/>

        <el-skeleton v-if="!dashboard && loading" :animated="true" :rows="12"/>
        <div v-if="dashboard" class="fls_page_inner">
            <div class="fls_page_main" :aria-busy="loading">
                <section class="fls_dcard fls_dashboard__activity" :aria-label="$t('Login activity')">
                    <div class="fls_dcard_head">
                        <div><h2>{{ $t('Login activity') }}</h2><p class="fls_dashboard__caption">{{ $t('Totals for the selected period') }}</p></div>
                        <div class="fls_dashboard__range">
                            <label for="fls-dashboard-range" class="screen-reader-text">{{ $t('Activity period') }}</label>
                            <select id="fls-dashboard-range" v-model="range" :disabled="loading || !!blocking" @change="fetchDashboard">
                                <option v-for="item in ranges" :key="item.value" :value="item.value">{{ item.label }}</option>
                            </select>
                            <el-button :loading="loading" :disabled="!!blocking" @click="fetchDashboard">{{ $t('Refresh') }}</el-button>
                        </div>
                    </div>
                    <div class="fls_stat_tiles" v-loading="loading">
                        <router-link v-for="stat in activityStats" :key="stat.key" class="fls_stat_tile"
                                     :class="'fls_stat_' + stat.key" :to="statTarget(stat)"
                                     :title="$t('Open these entries in the activity log. The log covers every date, not just this period.')">
                            <div class="fls_stat_title"><span class="fls_stat_icon" aria-hidden="true" v-html="icons[stat.key]"></span>{{ stat.title }}</div>
                            <div class="fls_stat_value">{{ stat.value }}<span class="fls_dashboard__arrow" aria-hidden="true">↗</span></div>
                        </router-link>
                    </div>
                    <div class="fls_dcard_body" v-loading="loading"><activity-chart :chart="dashboard.chart"/></div>
                </section>
                <section class="fls_dcard" :aria-label="$t('Recent activity')">
                    <div class="fls_dcard_head">
                        <div><h2>{{ $t('Recent activity') }}</h2><p class="fls_dashboard__caption">{{ $t('Latest entries · %s', rangeLabel) }}</p></div>
                        <router-link :to="{name: 'logs'}">{{ $t('Open the activity log') }} <span aria-hidden="true">↗</span></router-link>
                    </div>
                    <div class="fls_dashboard__views" :aria-label="$t('Recent activity view')">
                        <button type="button" :aria-pressed="recentView === 'threats'" :class="{is_active: recentView === 'threats'}" @click="recentView = 'threats'">{{ $t('Failed & blocked') }}</button>
                        <button type="button" :aria-pressed="recentView === 'successes'" :class="{is_active: recentView === 'successes'}" @click="recentView = 'successes'">{{ $t('Successful sign-ins') }}</button>
                    </div>
                    <div class="fls_dcard_body is_flush" v-loading="loading">
                        <log-list :logs="recentLogs" :empty-text="recentView === 'threats' ? $t('No failed or blocked attempts in this period') : $t('No successful sign-ins in this period')"/>
                    </div>
                </section>
                <section class="fls_dcard" :aria-label="$t('Top sources of failed and blocked attempts')">
                    <div class="fls_dcard_head">
                        <div><h2>{{ $t('Top sources of failed & blocked attempts') }}</h2><p class="fls_dashboard__caption">{{ rangeLabel }}</p></div>
                    </div>
                    <div class="fls_dcard_body is_flush" v-loading="loading">
                        <ul v-if="dashboard.top_ips.length" class="fls_dash_list">
                            <li v-for="row in dashboard.top_ips" :key="row.ip" class="fls_dashboard__ip">
                                <div class="fls_dashboard__ip-row">
                                    <div class="fls_dash_list_main">
                                        <div class="fls_dash_list_title"><span class="fls_dashboard__address">{{ row.ip }}</span></div>
                                        <div class="fls_dash_list_meta">{{ $_n('%s username tried', '%s usernames tried', row.usernames) }} · {{ row.last_seen }}</div>
                                    </div>
                                    <div class="fls_dash_list_aside"><span class="fls_dash_list_count">{{ row.attempts }}</span>{{ $t('attempts') }}</div>
                                    <span v-if="row.is_blocked" class="fls_tag is_blocked">{{ $t('Blocked') }}</span>
                                    <el-button v-else size="small" :disabled="!!blocking" :aria-label="$t('Block %s', row.ip)" @click="pendingBlock = pendingBlock === row ? null : row">{{ $t('Block IP') }}</el-button>
                                </div>
                                <div v-if="pendingBlock === row" class="fls_dashboard__confirm">
                                    <p>{{ $t('Block all sign-ins from %s? Anyone else sharing this address will be blocked too. You can undo this under IP Rules.', row.ip) }}</p>
                                    <el-button size="small" :disabled="!!blocking" @click="pendingBlock = null">{{ $t('Cancel') }}</el-button>
                                    <el-button size="small" type="danger" :loading="blocking === row.ip" @click="blockIp(row)">{{ $t('Confirm block') }}</el-button>
                                </div>
                            </li>
                        </ul>
                        <div v-else class="fls_empty"><span aria-hidden="true" v-html="icons.empty"></span>{{ $t('No failed or blocked attempts in this period') }}</div>
                    </div>
                </section>
                <section class="fls_dcard">
                    <div class="fls_dcard_head"><h2>{{ $t('Sign-in methods') }}</h2><span class="fls_dcard_meta">{{ rangeLabel }}</span></div>
                    <div class="fls_dcard_body" v-loading="loading">
                        <div v-if="dashboard.methods.length" class="fls_dash_bars">
                            <div v-for="method in dashboard.methods" :key="method.key">
                                <div class="fls_dash_bar_head"><b>{{ method.label }}</b><span>{{ method.count }} · {{ method.percent }}%</span></div>
                                <div class="fls_dash_bar_track"><div class="fls_dash_bar_fill" :style="{width: method.percent + '%'}"></div></div>
                            </div>
                        </div>
                        <div v-else class="fls_empty">{{ $t('Once people sign in, this shows which methods they used.') }}</div>
                    </div>
                </section>
            </div>
            <security-aside :protection="dashboard.protection"/>
        </div>
    </div>
</template>
