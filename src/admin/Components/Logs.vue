<script type="text/babel">
import icons from './Dashboard/icons';

/**
 * The activity log.
 *
 * Not only logins: the same table records a password reset being asked for, and what an
 * administrator did from the recovery screen. The views bar shows all five and divides
 * after the three that are outcomes of one login attempt.
 *
 * Laid out like FluentCart's Orders screen: a page heading with the actions that apply to
 * the whole screen, then one card holding the views, the search and the table. The status
 * filter is a row of views rather than a segmented control, which is what makes room for
 * search to sit under it instead of squeezing in beside it.
 */
export default {
    name: 'Logs',
    data() {
        return {
            icons,
            logs: [],
            paginate: {
                page: 1,
                per_page: 20,
                total: 0
            },
            search: '',
            /*
             * The dashboard's tiles and "view all" links land here already filtered - a
             * count you clicked should open the rows it counted, not every row there is.
             */
            status: this.hasView(this.$route.query.status) ? this.$route.query.status : 'all',
            /*
             * Which kind of event, within whatever view is open. The list comes back with
             * the rows, so it only ever offers events the log actually holds.
             */
            event: 'all',
            eventOptions: [],
            searchOpen: false,
            loading: false,
            sortBy: 'created_at',
            sortType: 'descending',
            deleting: false,
            // Days an entry is kept for. 0 means the log is never trimmed.
            retention: 0
        }
    },
    computed: {
        /* "All" first, then the views the server declares, in the order it declares them. */
        views() {
            const declared = this.appVars.auth_log_views || [];

            return [{key: 'all', label: this.$t('All'), statuses: ['all']}].concat(
                declared.map((view, index) => ({
                    key: view.key,
                    label: view.label,
                    statuses: view.statuses,
                    /* Whether this view wants the event dropdown. Only site activity does. */
                    events: !!view.events,
                    /*
                     * A rule where the login outcomes stop and the rest begin, so the two
                     * kinds of row read as two kinds rather than as five equal tabs.
                     */
                    divided: index > 0 && declared[index - 1].group !== view.group
                }))
            );
        },
        currentView() {
            return this.views.find(candidate => candidate.key === this.status);
        },
        /* A view can cover more than one status, so the query follows the view, not the key. */
        currentStatuses() {
            return this.currentView ? this.currentView.statuses : ['all'];
        },
        /*
         * Site activity only - it is the one view holding several kinds of event. On the
         * others the view name already says what the rows are, so a dropdown would only
         * repeat it. The server decides; this follows.
         */
        showEventFilter() {
            return !!(this.currentView && this.currentView.events) && this.eventOptions.length > 1;
        },
        /*
         * How long these rows last, said on the page that shows them. Without it, a log
         * that starts a month ago looks like one that lost a month.
         */
        retentionLabel() {
            if (!this.retention) {
                return this.$t('Entries are kept until you delete them.');
            }

            return this.$t('Entries older than %s days are deleted automatically.', this.retention);
        },
        countLabel() {
            const total = this.paginate.total;

            if (!total) {
                return '';
            }

            const from = (this.paginate.page - 1) * this.paginate.per_page + 1;
            const to = Math.min(from + this.logs.length - 1, total);

            return this.$t('%1s-%2s of %3s', from, to, total);
        }
    },
    methods: {
        hasView(key) {
            return !!key && (this.appVars.auth_log_views || []).some(view => view.key === key);
        },
        selectView(key) {
            if (this.status === key) {
                return;
            }

            this.status = key;
            this.paginate.page = 1;
            /*
             * A view carries its own kinds of event, so one picked in the last view would
             * usually match nothing here - and an empty table with the reason hidden in a
             * control you have already forgotten is the worst way to say so.
             */
            this.event = 'all';
            this.fetchLogs();
        },
        selectEvent() {
            this.paginate.page = 1;
            this.fetchLogs();
        },
        changePage(page) {
            this.paginate.page = page;
            this.fetchLogs();
        },
        toggleSearch() {
            this.searchOpen = !this.searchOpen;

            if (this.searchOpen) {
                this.$nextTick(() => this.$refs.searchInput && this.$refs.searchInput.focus());
            }
        },
        /*
         * Recovery rows are written by an administrator's own click, not by a sign-in, so
         * they carry no user agent. Joining two empty halves left a bare "/" in the cell.
         */
        browserLabel(log) {
            return [log.device_os, log.browser].filter(part => !!part).join(' / ');
        },
        /*
         * Closing the search clears it. Leaving a hidden term applied is how a list ends up
         * looking empty for no reason anybody can see.
         */
        cancelSearch() {
            this.searchOpen = false;

            if (this.search) {
                this.search = '';
                this.runSearch();
            }
        },
        runSearch() {
            this.paginate.page = 1;
            this.fetchLogs();
        },
        handleSortChange(sort) {
            if (!sort.prop) {
                return;
            }

            this.sortBy = sort.prop;
            this.sortType = sort.order;
            this.fetchLogs();
        },
        fetchLogs() {
            this.loading = true;

            this.$get('auth-logs', {
                per_page: this.paginate.per_page,
                page: this.paginate.page,
                statuses: this.currentStatuses,
                /* Which view is open, so the server knows whether to look for its events. */
                view: this.status,
                events: [this.event],
                sortBy: this.sortBy,
                search: this.search,
                sortType: (this.sortType === 'descending') ? 'DESC' : 'ASC'
            })
                .then(response => {
                    this.logs = response.logs.data;
                    this.paginate.total = response.logs.total;
                    this.retention = response.retention;
                    this.eventOptions = response.events || [];
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        rowAction(command, row) {
            if (command === 'delete') {
                this.deleteLog(row.id);
                return;
            }

            /*
             * The server holds every rule these lists have - it will refuse to block the
             * address you are reading this from, and refuse an address already covered - so
             * this just reports back what it decided.
             */
            this.$post('ip-rules/add', {type: command, ip: row.ip})
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                });
        },
        deleteLog(id) {
            this.deleting = true;

            this.$post('delete-log/' + id)
                .then(response => {
                    this.$notify.success(response.message);
                    this.fetchLogs();
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.deleting = false;
                });
        },
        deleteAllLogs() {
            this.deleting = true;

            this.$post('truncate-auth-logs')
                .then(response => {
                    this.$notify.success(response.message);
                    this.paginate.page = 1;
                    this.fetchLogs();
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.deleting = false;
                });
        }
    },
    mounted() {
        this.fetchLogs();
    }
}
</script>

<template>
    <div class="fls_list_page">
        <div class="fls_list_inner">
            <div class="fls_page_head">
                <h1 class="fls_page_title">{{ $t('Activity Log') }}</h1>

                <div class="fls_page_actions">
                    <el-popconfirm :width="240" @confirm="deleteAllLogs()"
                                   :title="$t('Delete every log entry? This cannot be undone.')">
                        <template #reference>
                            <el-button :loading="deleting">{{ $t('Delete all logs') }}</el-button>
                        </template>
                    </el-popconfirm>
                </div>
            </div>

            <div class="fls_list_card">
                <div class="fls_list_head">
                    <div class="fls_list_head_top">
                        <ul class="fls_tabs">
                            <li v-for="view in views" :key="view.key"
                                :class="{is_divided: view.divided}">
                                <button type="button" :class="{is_active: status === view.key}"
                                        @click="selectView(view.key)">
                                    {{ view.label }}
                                </button>
                            </li>
                        </ul>

                        <div class="fls_list_head_actions">
                            <el-select v-if="showEventFilter" v-model="event" size="small"
                                       class="fls_event_filter" @change="selectEvent()">
                                <el-option value="all" :label="$t('All events')"/>
                                <el-option v-for="option in eventOptions" :key="option.value"
                                           :value="option.value" :label="option.label"/>
                            </el-select>
                            <button type="button" class="fls_icon_btn" :class="{is_active: searchOpen}"
                                    :title="$t('Search')" :aria-label="$t('Search')" @click="toggleSearch()">
                                <span v-html="icons.search"></span>
                            </button>
                            <button type="button" class="fls_icon_btn" :title="$t('Refresh')"
                                    :aria-label="$t('Refresh')" @click="fetchLogs()">
                                <span v-html="icons.refresh"></span>
                            </button>
                        </div>
                    </div>

                    <div v-if="searchOpen" class="fls_list_search">
                        <div class="fls_list_search_row">
                            <el-input ref="searchInput" v-model="search" clearable
                                      :placeholder="$t('Search')"
                                      @keyup.enter="runSearch()" @clear="runSearch()"/>
                            <a href="#" class="fls_list_search_cancel" @click.prevent="cancelSearch()">
                                {{ $t('Cancel') }}
                            </a>
                        </div>
                        <p class="fls_list_search_hint">
                            {{ $t('Search by username, IP address or how they signed in. Press Enter to search.') }}
                        </p>
                    </div>
                </div>

                <div class="fls_list_body">
                    <el-table class="fls_list_table" v-loading="loading" :data="logs"
                              :default-sort="{prop: sortBy, order: sortType}"
                              @sort-change="handleSortChange" style="width: 100%">
                        <el-table-column type="expand">
                            <template #default="props">
                                <div class="fls_log_detail">
                                    <div>
                                        <h4>{{ $t('Description') }}</h4>
                                        <div class="fls_log_detail_value" v-html="props.row.description"></div>
                                    </div>
                                    <div>
                                        <h4>{{ $t('Browser details') }}</h4>
                                        <div class="fls_log_detail_value">{{ props.row.agent }}</div>
                                    </div>
                                </div>
                            </template>
                        </el-table-column>

                        <el-table-column sortable prop="created_at" :label="$t('Date')" width="190">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <div class="fls_cell_main">{{ scope.row.human_time_diff }}</div>
                                    <div class="fls_cell_sub">{{ scope.row.created_at_human }}</div>
                                </div>
                            </template>
                        </el-table-column>

                        <!--
                            "User" and "Event" rather than "Login Username" and "Method":
                            both have to be true of a blocked login and of a file being
                            quarantined, and only these read correctly for both.
                        -->
                        <el-table-column sortable prop="username" min-width="200"
                                         :label="$t('User')">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <div class="fls_cell_main">{{ scope.row.username }}</div>
                                    <div class="fls_cell_sub">
                                        <!--
                                            Compared as a number. The column arrives from the
                                            database as a string, and "0" is truthy in
                                            JavaScript - so every row written by the system
                                            rather than by a person announced "User #0".
                                        -->
                                        {{ Number(scope.row.user_id) > 0 ? $t('User #%s', scope.row.user_id) : $t('No account') }}
                                    </div>
                                </div>
                            </template>
                        </el-table-column>

                        <el-table-column sortable prop="status" :label="$t('Status')" width="130">
                            <template #default="scope">
                                <span class="fls_tag" :class="'is_' + scope.row.status">
                                    {{ appVars.auth_statuses[scope.row.status] || scope.row.status }}
                                </span>
                            </template>
                        </el-table-column>

                        <el-table-column sortable prop="media" :label="$t('Event')" width="190">
                            <template #default="scope">{{ scope.row.media_label }}</template>
                        </el-table-column>

                        <el-table-column sortable prop="ip" :label="$t('IP Address')" width="160">
                            <template #default="scope">
                                <a class="fls_cell_mono" target="_blank" rel="noopener nofollow"
                                   :href="'https://ipinfo.io/' + scope.row.ip">{{ scope.row.ip }}</a>
                            </template>
                        </el-table-column>

                        <el-table-column sortable prop="browser" :label="$t('Browser')" min-width="170">
                            <template #default="scope">
                                <span v-if="browserLabel(scope.row)">{{ browserLabel(scope.row) }}</span>
                                <span v-else class="fls_cell_muted" :title="$t('Not a sign-in')">&mdash;</span>
                            </template>
                        </el-table-column>

                        <el-table-column align="right" width="90">
                            <template #default="scope">
                                <!--
                                    The address is right there in the row, so the two things
                                    worth doing about it are too - rather than copying it out
                                    and typing it into a settings screen.
                                -->
                                <el-dropdown trigger="click" @command="rowAction($event, scope.row)">
                                    <el-button text :title="$t('Actions')">
                                        <span class="dashicons dashicons-ellipsis"></span>
                                    </el-button>
                                    <template #dropdown>
                                        <el-dropdown-menu>
                                            <el-dropdown-item command="allow" :disabled="!scope.row.ip">
                                                {{ $t('Never lock out %s', scope.row.ip) }}
                                            </el-dropdown-item>
                                            <el-dropdown-item command="block" :disabled="!scope.row.ip">
                                                {{ $t('Block %s', scope.row.ip) }}
                                            </el-dropdown-item>
                                            <el-dropdown-item command="delete" divided>
                                                {{ $t('Delete this entry') }}
                                            </el-dropdown-item>
                                        </el-dropdown-menu>
                                    </template>
                                </el-dropdown>
                            </template>
                        </el-table-column>

                        <template #empty>
                            <div class="fls_empty">
                                <span v-html="icons.empty"></span>
                                {{ search ? $t('Nothing matches that search') : $t('Nothing to show yet. Sign-ins, failed attempts and site changes will appear here as they happen.') }}
                            </div>
                        </template>
                    </el-table>
                </div>

                <!--
                    Rendered whether or not there are rows: an empty log is exactly when
                    somebody wants to know whether it was emptied on a schedule.
                -->
                <div class="fls_list_footer">
                    <div class="fls_list_footer_text">
                        <span v-if="paginate.total" class="fls_list_count">{{ countLabel }}</span>
                        <span class="fls_list_retention">{{ retentionLabel }}</span>
                    </div>
                    <el-pagination v-if="paginate.total"
                                   @current-change="changePage"
                                   :current-page="paginate.page"
                                   :page-size="paginate.per_page"
                                   background layout="prev, pager, next"
                                   :total="paginate.total"/>
                </div>
            </div>
        </div>
    </div>
</template>
