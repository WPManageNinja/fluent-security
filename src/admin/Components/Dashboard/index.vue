<script type="text/babel">
import icons from './icons';
import ActivityChart from './_ActivityChart.vue';
import LogList from './_LogList.vue';
import SecurityAside from './_SecurityAside.vue';

/*
 * The dashboard.
 *
 * Two columns, following FluentCart: what happened on the left, what is configured on the
 * right. The date range at the top governs the left column only - the right one is the
 * site's standing setup, which a date range has nothing to say about.
 *
 * One request draws the whole screen. Every panel here is a different reading of the same
 * log table over the same range, so splitting them across endpoints would mean parsing
 * that range five times to render one page.
 */
export default {
    name: 'Dashboard',
    components: {
        ActivityChart,
        LogList,
        SecurityAside
    },
    data() {
        return {
            icons,
            loading: true,
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
        fetchDashboard() {
            this.loading = true;

            this.$get('dashboard', {day_range: this.range})
                .then(response => {
                    this.dashboard = response;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /*
         * Refuses the address outright from here on. The row is marked blocked rather than
         * removed: it is still the evidence for why, and taking it away would leave the card
         * looking like the attempts had stopped.
         */
        blockIp(row) {
            this.blocking = row.ip;

            this.$post('ip-rules/add', {type: 'block', ip: row.ip, label: this.$t('Blocked from the dashboard')})
                .then(response => {
                    this.$notify.success(response.message);
                    row.is_blocked = true;
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
    <div class="fls_page">
        <div class="fls_page_inner">
            <div class="fls_page_main">
                <div class="fls_dash_greeting">
                    <div class="fls_dash_greeting_who">
                        <div v-if="appVars.me.avatar" class="fls_dash_avatar">
                            <img :src="appVars.me.avatar" :alt="appVars.me.full_name"/>
                        </div>
                        <div>
                            <h1>{{ greeting }}</h1>
                            <p>{{ $t('Here is who has been signing in, and what is guarding the door.') }}</p>
                        </div>
                    </div>

                    <div class="fls_dash_greeting_actions">
                        <el-button @click="$router.push({name: 'security_scans'})">
                            {{ $t('Scan Files') }}
                        </el-button>
                        <el-button type="primary" @click="$router.push({name: 'settings_general'})">
                            {{ $t('Security Settings') }}
                        </el-button>
                    </div>
                </div>

                <div class="fls_dash_range">
                    <span class="fls_dash_range_label">{{ $t('Showing') }}</span>
                    <el-select v-model="range" @change="fetchDashboard()" size="small" style="width: 150px;">
                        <el-option v-for="item in ranges" :key="item.value" :value="item.value"
                                   :label="item.label"/>
                    </el-select>
                </div>

                <el-skeleton v-if="!dashboard" :animated="true" :rows="12"/>

                <template v-else>
                    <div v-loading="loading" class="fls_stat_tiles">
                        <router-link v-for="stat in dashboard.stats" :key="stat.key"
                                     class="fls_stat_tile" :class="'fls_stat_' + stat.key"
                                     :to="statTarget(stat)">
                            <span class="fls_stat_icon" v-html="icons[stat.key === 'two_fa' ? 'twoFa' : stat.key]"></span>
                            <div>
                                <div class="fls_stat_title">{{ stat.title }}</div>
                                <div class="fls_stat_value">
                                    {{ stat.value }}
                                    <small v-if="stat.meta">{{ stat.meta }}</small>
                                </div>
                            </div>
                        </router-link>
                    </div>

                    <div class="fls_dcard">
                        <div class="fls_dcard_head">
                            <h2>
                                <span v-html="icons.chart"></span>
                                {{ $t('Login Activity') }}
                            </h2>
                            <router-link :to="{name: 'logs'}">{{ $t('View all logs') }}</router-link>
                        </div>
                        <div v-loading="loading" class="fls_dcard_body">
                            <activity-chart :chart="dashboard.chart"/>
                        </div>
                    </div>

                    <div class="fls_dcard_pair">
                        <div class="fls_dcard">
                            <div class="fls_dcard_head">
                                <h2>
                                    <span v-html="icons.threat"></span>
                                    {{ $t('Failed & Blocked') }}
                                </h2>
                                <!-- The logs table filters by one status, and this card is two. -->
                                <router-link :to="{name: 'logs'}">{{ $t('View all') }}</router-link>
                            </div>
                            <div v-loading="loading" class="fls_dcard_body is_flush">
                                <log-list :logs="dashboard.recent.threats"
                                          :empty-text="$t('Nothing has been turned away recently')"/>
                            </div>
                        </div>

                        <div class="fls_dcard">
                            <div class="fls_dcard_head">
                                <h2>
                                    <span v-html="icons.globe"></span>
                                    {{ $t('Most Attempts by IP') }}
                                </h2>
                            </div>
                            <div v-loading="loading" class="fls_dcard_body is_flush">
                                <ul v-if="dashboard.top_ips.length" class="fls_dash_list">
                                    <li v-for="row in dashboard.top_ips" :key="row.ip">
                                        <div class="fls_dash_list_main">
                                            <div class="fls_dash_list_title">
                                                <span>{{ row.ip }}</span>
                                            </div>
                                            <div class="fls_dash_list_meta">
                                                {{ $_n('%s username tried', '%s usernames tried', row.usernames) }}
                                                · {{ row.last_seen }}
                                            </div>
                                        </div>
                                        <div class="fls_dash_list_aside">
                                            <span class="fls_dash_list_count">{{ row.attempts }}</span>
                                            {{ $t('attempts') }}
                                        </div>
                                        <!--
                                            The evidence and the action in the same row: this
                                            card is where you find out an address is worth
                                            blocking, so it is where blocking belongs.
                                        -->
                                        <span v-if="row.is_blocked" class="fls_tag is_blocked">
                                            {{ $t('Blocked') }}
                                        </span>
                                        <el-button v-else size="small" class="fls_dash_list_action"
                                                   :loading="blocking === row.ip" @click="blockIp(row)">
                                            {{ $t('Block') }}
                                        </el-button>
                                    </li>
                                </ul>
                                <div v-else class="fls_dash_empty">
                                    <span v-html="icons.empty"></span>
                                    {{ $t('No failed or blocked attempts in this period') }}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="fls_dcard_pair">
                        <div class="fls_dcard">
                            <div class="fls_dcard_head">
                                <h2>
                                    <span v-html="icons.check"></span>
                                    {{ $t('Recent Sign-ins') }}
                                </h2>
                                <router-link :to="{name: 'logs', query: {status: 'success'}}">
                                    {{ $t('View all') }}
                                </router-link>
                            </div>
                            <div v-loading="loading" class="fls_dcard_body is_flush">
                                <log-list :logs="dashboard.recent.successes"
                                          :empty-text="$t('Nobody has signed in during this period')"/>
                            </div>
                        </div>

                        <div class="fls_dcard">
                            <div class="fls_dcard_head">
                                <h2>
                                    <span v-html="icons.key"></span>
                                    {{ $t('How People Signed In') }}
                                </h2>
                            </div>
                            <div v-loading="loading" class="fls_dcard_body">
                                <div v-if="dashboard.methods.length" class="fls_dash_bars">
                                    <div v-for="method in dashboard.methods" :key="method.key">
                                        <div class="fls_dash_bar_head">
                                            <b>{{ method.label }}</b>
                                            <span>{{ method.count }} · {{ method.percent }}%</span>
                                        </div>
                                        <div class="fls_dash_bar_track">
                                            <div class="fls_dash_bar_fill" :style="{width: method.percent + '%'}"></div>
                                        </div>
                                    </div>
                                </div>
                                <div v-else class="fls_dash_empty">
                                    <span v-html="icons.empty"></span>
                                    {{ $t('No sign-ins to break down yet') }}
                                </div>
                            </div>
                        </div>
                    </div>
                </template>
            </div>

            <security-aside v-if="dashboard" :protection="dashboard.protection"/>
        </div>
    </div>
</template>
