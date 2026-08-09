<script type="text/babel">
import icons from '../Dashboard/icons';
import SettingsHeader from '../Settings/_SettingsHeader.vue';

/**
 * Who has two-factor turned on, and who does not.
 *
 * It is a list of rows you read down, so it is built like the auth log rather than like a
 * settings form: the filters are views along the top of one card, search folds out under
 * them, and the table wears the same skin. Only the page heading comes from the settings
 * shell it is routed inside.
 */
export default {
    name: 'EnrolledUsers',
    components: {
        SettingsHeader
    },
    data() {
        return {
            icons,
            loading: false,
            resetting: 0,
            users: [],
            search: '',
            searchOpen: false,
            filter: 'all',
            summary: {enrolled: 0, eligible: 0},
            /*
             * What the site actually has in force, reported with the rows rather than
             * read from the settings this screen was booted with - people arrive here
             * straight after changing a policy.
             */
            methods: {totp: false, email: false},
            loaded: false,
            pagination: {
                total: 0,
                per_page: 20,
                current_page: 1
            }
        }
    },
    computed: {
        anythingEnabled() {
            return this.methods.totp || this.methods.email;
        },
        /*
         * Counted against the people who could have an app, not against everybody with
         * an account - and left unsaid entirely when no app can be set up, because "0 of
         * 0" is not a fact about anything.
         */
        headerNote() {
            if (!this.methods.totp) {
                return this.methods.email
                    ? this.$t('Emailed codes only. Nobody on this site can set up an authenticator app.')
                    : '';
            }

            return this.$t(
                '%1s of %2s users who can have an authenticator app have set one up',
                this.summary.enrolled,
                this.summary.eligible
            );
        },
        /* Named so the notice can say which one is missing rather than "some of them". */
        missingMethods() {
            const missing = [];

            if (!this.methods.totp) {
                missing.push(this.$t('an authenticator app'));
            }

            if (!this.methods.email) {
                missing.push(this.$t('emailed codes'));
            }

            return missing;
        },
        views() {
            return [
                {key: 'all', label: this.$t('All')},
                {key: 'enrolled', label: this.$t('Enrolled')},
                {key: 'not_enrolled', label: this.$t('Not enrolled')}
            ];
        },
        countLabel() {
            const total = this.pagination.total;

            if (!total) {
                return '';
            }

            const from = (this.pagination.current_page - 1) * this.pagination.per_page + 1;
            const to = Math.min(from + this.users.length - 1, total);

            return this.$t('%1s-%2s of %3s', from, to, total);
        }
    },
    methods: {
        fetchUsers() {
            this.loading = true;

            this.$get('two-fa/users', {
                page: this.pagination.current_page,
                search: this.search,
                filter: this.filter
            })
                .then(response => {
                    this.users = response.users.data;
                    this.summary = response.summary;
                    this.methods = response.methods;
                    this.pagination.total = response.users.total;
                    this.pagination.per_page = response.users.per_page;
                    this.loaded = true;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        changePage(page) {
            this.pagination.current_page = page;
            this.fetchUsers();
        },
        selectView(key) {
            if (this.filter === key) {
                return;
            }

            this.filter = key;
            this.pagination.current_page = 1;
            this.fetchUsers();
        },
        toggleSearch() {
            this.searchOpen = !this.searchOpen;

            if (this.searchOpen) {
                this.$nextTick(() => this.$refs.searchInput && this.$refs.searchInput.focus());
            }
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
            this.pagination.current_page = 1;
            this.fetchUsers();
        },
        /**
         * Turning someone's authenticator app off lowers what guards their account, so
         * it is spelled out rather than confirmed with a bare "are you sure".
         */
        confirmReset(user) {
            this.$confirm(
                this.$t('%s will be signed in by password alone until they set up a new one. Their recovery codes stop working straight away.', user.user_login),
                this.$t('Turn off the authenticator app?'),
                {
                    confirmButtonText: this.$t('Turn it off'),
                    cancelButtonText: this.$t('Cancel'),
                    type: 'warning'
                }
            )
                .then(() => {
                    this.resetUser(user);
                })
                .catch(() => {
                });
        },
        resetUser(user) {
            this.resetting = user.id;

            this.$post('two-fa/users/' + user.id + '/reset')
                .then(response => {
                    this.$notify.success(response.message);
                    this.summary = response.summary;

                    const index = this.users.findIndex(row => row.id === user.id);
                    if (index > -1) {
                        this.users[index] = response.user;
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.resetting = 0;
                });
        },
        roleNames(user) {
            return user.roles.length ? user.roles.join(', ') : '—';
        }
    },
    mounted() {
        this.fetchUsers();
    }
};
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Two-Factor Enrollment')"
                        :description="headerNote"
                        :show-save="false"/>

        <div class="fls_settings_content" v-loading="loading && !loaded">
            <!--
                Nothing to list. The table would be a page of "Not available" down every
                column, which reads as a fault rather than as a setting nobody has turned
                on - so the screen says which it is and where to go.
            -->
            <div v-if="loaded && !anythingEnabled" class="fls_list_card">
                <div class="fls_empty fls_2fa_prompt">
                    <span v-html="icons.twoFa"></span>
                    <h3>{{ $t('No second factor is switched on') }}</h3>
                    <p>
                        {{ $t('Nobody on this site is asked for anything beyond a password. Switch on an authenticator app or emailed codes, and this page will show who has set one up.') }}
                    </p>
                    <router-link :to="{name: 'settings_general', query: {section: 'two_fa'}}">
                        <el-button type="primary" size="small">
                            {{ $t('Set up two-factor authentication') }}
                        </el-button>
                    </router-link>
                </div>
            </div>

            <template v-else>
                <!--
                    One of the two is off. Worth saying on the page that reports on them,
                    because a column of blanks otherwise looks like nobody has bothered
                    rather than like the method was never offered.
                -->
                <el-alert v-if="loaded && missingMethods.length" type="info" :closable="false" show-icon
                          class="fls_row_alert"
                          :title="$t('Not every method is switched on')">
                    {{ $t('This site does not offer %s. Users can only set up what is switched on, so that column stays empty for everyone.', missingMethods.join($t(' or '))) }}
                    <router-link :to="{name: 'settings_general', query: {section: 'two_fa'}}">
                        {{ $t('Review two-factor settings') }}
                    </router-link>
                </el-alert>

            <div class="fls_list_card">
                <div class="fls_list_head">
                    <div class="fls_list_head_top">
                        <ul class="fls_tabs">
                            <li v-for="view in views" :key="view.key">
                                <button type="button" :class="{is_active: filter === view.key}"
                                        @click="selectView(view.key)">
                                    {{ view.label }}
                                </button>
                            </li>
                        </ul>

                        <div class="fls_list_head_actions">
                            <button type="button" class="fls_icon_btn" :class="{is_active: searchOpen}"
                                    :title="$t('Search')" :aria-label="$t('Search')" @click="toggleSearch()">
                                <span v-html="icons.search"></span>
                            </button>
                            <button type="button" class="fls_icon_btn" :title="$t('Refresh')"
                                    :aria-label="$t('Refresh')" @click="fetchUsers()">
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
                            {{ $t('Search by name, username or email address. Press Enter to search.') }}
                        </p>
                    </div>
                </div>

                <div class="fls_list_body">
                    <el-table class="fls_list_table" v-loading="loading" :data="users" style="width: 100%">
                        <el-table-column :label="$t('User')" min-width="200">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <div class="fls_cell_main">{{ scope.row.display_name }}</div>
                                    <div class="fls_cell_sub">
                                        {{ scope.row.user_login }} &middot; {{ scope.row.user_email }}
                                    </div>
                                </div>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Roles')" min-width="150">
                            <template #default="scope">
                                <span class="fls_cell_muted">{{ roleNames(scope.row) }}</span>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Authenticator app')" width="200">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <template v-if="scope.row.totp_enrolled">
                                        <div class="fls_cell_main">
                                            <span class="fls_tag is_success">{{ $t('Active') }}</span>
                                        </div>
                                        <div v-if="scope.row.activated_at" class="fls_cell_sub">
                                            {{ scope.row.activated_at }}
                                        </div>
                                    </template>
                                    <div v-else-if="scope.row.totp_required" class="fls_cell_main">
                                        <span class="fls_tag is_warning">{{ $t('Required, not set up') }}</span>
                                    </div>
                                    <div v-else-if="scope.row.totp_allowed" class="fls_cell_main">
                                        <span class="fls_tag is_neutral">{{ $t('Not set up') }}</span>
                                    </div>
                                    <span v-else class="fls_cell_muted">{{ $t('Not available') }}</span>
                                </div>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Recovery codes')" width="140">
                            <template #default="scope">
                                <span v-if="!scope.row.totp_enrolled" class="fls_cell_muted">—</span>
                                <span v-else :class="{fls_cell_alert: scope.row.recovery_codes < 3}">
                                    {{ scope.row.recovery_codes }} / {{ scope.row.recovery_total }}
                                </span>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Email code')" width="120">
                            <template #default="scope">
                                <span v-if="scope.row.email_2fa" class="fls_tag is_success">{{ $t('On') }}</span>
                                <span v-else class="fls_cell_muted">—</span>
                            </template>
                        </el-table-column>

                        <el-table-column align="right" width="90">
                            <template #default="scope">
                                <!--
                                    The same row menu the logs table carries, rather than a
                                    red button in every row: turning an app off is the lost
                                    phone path, not something to be doing down the list.
                                -->
                                <el-dropdown v-if="scope.row.totp_enrolled && scope.row.can_edit"
                                             trigger="click" @command="confirmReset(scope.row)">
                                    <el-button text :title="$t('Actions')"
                                               :loading="resetting === scope.row.id">
                                        <span class="dashicons dashicons-ellipsis"></span>
                                    </el-button>
                                    <template #dropdown>
                                        <el-dropdown-menu>
                                            <el-dropdown-item command="reset">
                                                {{ $t('Turn off the authenticator app') }}
                                            </el-dropdown-item>
                                        </el-dropdown-menu>
                                    </template>
                                </el-dropdown>
                            </template>
                        </el-table-column>

                        <template #empty>
                            <div class="fls_empty">
                                <span v-html="icons.empty"></span>
                                {{ search ? $t('Nothing matches that search') : $t('No users match this filter') }}
                            </div>
                        </template>
                    </el-table>
                </div>

                <div v-if="pagination.total" class="fls_list_footer">
                    <span class="fls_list_count">{{ countLabel }}</span>
                    <el-pagination @current-change="changePage"
                                   :current-page="pagination.current_page"
                                   :page-size="pagination.per_page"
                                   background layout="prev, pager, next"
                                   :total="pagination.total"/>
                </div>
            </div>
            </template>
        </div>
    </div>
</template>
