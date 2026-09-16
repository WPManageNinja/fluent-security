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
            /*
             * Opens on who actually holds a factor, not on everybody in scope. The reason
             * anyone comes to this screen in a hurry is that one of these people is on the
             * phone locked out, and that is the list they are on; "All" is one click away
             * for the other reading of the page.
             */
            filter: 'enrolled',
            summary: {enrolled: 0, eligible: 0},
            /*
             * What the site actually has in force, reported with the rows rather than
             * read from the settings this screen was booted with - people arrive here
             * straight after changing a policy.
             */
            methods: {totp: false, email: false, passkey: false},
            loaded: false,
            pagination: {
                total: 0,
                per_page: 20,
                current_page: 1
            }
        }
    },
    computed: {
        /*
         * Passkeys count. Left out, this screen greeted a site running passkeys alone with
         * "No second factor is switched on" - an empty state covering a table that had rows
         * to show, because the only two methods it asked about were off.
         */
        anythingEnabled() {
            return this.methods.totp || this.methods.email || this.methods.passkey;
        },
        /* The device factors, named, for the sentence that reports on them. */
        deviceMethods() {
            const methods = [];

            if (this.methods.totp) {
                methods.push(this.$t('an authenticator app'));
            }

            if (this.methods.passkey) {
                methods.push(this.$t('a passkey'));
            }

            return methods;
        },
        /*
         * Counted against the people who could have an app, not against everybody with
         * an account - and left unsaid entirely when no app can be set up, because "0 of
         * 0" is not a fact about anything.
         */
        headerNote() {
            if (!this.deviceMethods.length) {
                return this.methods.email
                    ? this.$t('Emailed codes only. Nobody on this site can set up an authenticator app or a passkey.')
                    : '';
            }

            /*
             * Both halves of the fraction come from the server counting apps and passkeys
             * together, so the sentence has to name both. Written as "an authenticator app"
             * alone, it described a number that was not being measured - a site with
             * passkeys rolled out read "5 of 5 have set one up" over a column of "Not set
             * up", because the five were holding the method the sentence left out.
             */
            return this.$t(
                '%1s of %2s users who can set up %3s have one',
                this.summary.enrolled,
                this.summary.eligible,
                this.deviceMethods.join(this.$t(' or '))
            );
        },
        /* Named so the notice can say which one is missing rather than "some of them". */
        missingMethods() {
            const missing = [];

            if (!this.methods.totp) {
                missing.push(this.$t('an authenticator app'));
            }

            if (!this.methods.passkey) {
                missing.push(this.$t('passkeys'));
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
        /*
         * Named for the view being looked at. "No users match this filter" is true of all
         * three and useful in none: on the Enrolled view the thing worth saying is that
         * nobody has set anything up yet, which is a fact about the site, not about a
         * filter.
         */
        emptyText() {
            if (this.search) {
                return this.$t('Nothing matches that search');
            }

            if (this.filter === 'enrolled') {
                return this.$t('Nobody has set up a second factor yet');
            }

            if (this.filter === 'not_enrolled') {
                return this.$t('Everybody who is offered one has set it up');
            }

            return this.$t('No users match this filter');
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
         * Removing someone's authenticator app lowers what guards their account, so it is
         * spelled out rather than confirmed with a bare "are you sure" - and it opens by
         * saying what the action is *for*. Named "turn off", it read as a policy switch to
         * use when you had changed your mind about authenticator apps; it is the lost
         * device path, and the only reason to press it is that somebody cannot get in.
         */
        confirmReset(user) {
            this.$confirm(
                this.$t('Use this when %s has lost the device it was set up on. They will be signed in by password alone until they set up a new one, and their recovery codes stop working straight away.', user.user_login),
                this.$t('Remove the authenticator app?'),
                {
                    confirmButtonText: this.$t('Remove it'),
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
        },
        /**
         * What this user actually holds, as chips. Both when they hold both: an account
         * with an app and a passkey is a different thing from one with either, and the
         * column that reported only the app called half of them "Not set up".
         */
        factorsOf(user) {
            const factors = [];

            if (user.totp_enrolled) {
                factors.push({key: 'totp', icon: 'authApp', label: this.$t('App')});
            }

            if (user.passkey_count) {
                factors.push({
                    key: 'passkey',
                    icon: 'passkey',
                    label: user.passkey_count > 1
                        ? this.$t('%s passkeys', user.passkey_count)
                        : this.$t('Passkey')
                });
            }

            return factors;
        },
        /**
         * What the row menu offers. Opening the profile is the one that is always there -
         * it is where the whole of this user's second factor lives, including the passkeys
         * this table can show but not remove.
         */
        rowActions(user) {
            const actions = [];

            if (user.profile_url) {
                actions.push({command: 'profile', label: this.$t('Open their 2FA setup')});
            }

            if (user.totp_enrolled && user.can_edit) {
                actions.push({
                    command: 'reset',
                    label: this.$t('Remove their authenticator app'),
                    divided: actions.length > 0
                });
            }

            return actions;
        },
        /*
         * Dispatched on the command. It used to call confirmReset() for whatever came back,
         * which was harmless with one item on the menu and would have been a second item
         * that turned somebody's app off.
         */
        runCommand(command, user) {
            if (command === 'profile') {
                window.location.href = user.profile_url;
                return;
            }

            if (command === 'reset') {
                this.confirmReset(user);
            }
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

                        <el-table-column :label="$t('Roles')" min-width="120">
                            <template #default="scope">
                                <span class="fls_cell_muted">{{ roleNames(scope.row) }}</span>
                            </template>
                        </el-table-column>

                        <!--
                            One column for both device factors rather than one each. They
                            are alternatives to each other and most people hold neither, so
                            two columns spent most of their width saying "Not set up" twice
                            about the same account. Held factors are drawn as chips, so a
                            row with both reads as both at a glance.
                        -->
                        <el-table-column :label="$t('Second factor')" min-width="190">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <template v-if="factorsOf(scope.row).length">
                                        <div class="fls_factors">
                                            <span v-for="factor in factorsOf(scope.row)" :key="factor.key"
                                                  class="fls_factor">
                                                <span v-html="icons[factor.icon]"></span>{{ factor.label }}
                                            </span>
                                        </div>
                                        <div v-if="scope.row.activated_at" class="fls_cell_sub">
                                            {{ scope.row.activated_at }}
                                        </div>
                                    </template>
                                    <div v-else-if="scope.row.totp_required" class="fls_cell_main">
                                        <span class="fls_tag is_warning">{{ $t('Required, not set up') }}</span>
                                    </div>
                                    <div v-else-if="scope.row.totp_allowed || scope.row.passkey_allowed"
                                         class="fls_cell_main">
                                        <span class="fls_tag is_neutral">{{ $t('Not set up') }}</span>
                                    </div>
                                    <span v-else class="fls_cell_muted">{{ $t('Not available') }}</span>
                                </div>
                            </template>
                        </el-table-column>

                        <!--
                            Shown for a passkey holder too. The codes belong to the account
                            rather than to the app, and for somebody whose only device is a
                            passkey they are the way back in - the one row where a dash here
                            was worth reading and the column printed one anyway.
                        -->
                        <el-table-column :label="$t('Recovery codes')" width="130">
                            <template #default="scope">
                                <span v-if="!factorsOf(scope.row).length" class="fls_cell_muted">—</span>
                                <span v-else :class="{fls_cell_alert: scope.row.recovery_codes < 3}">
                                    {{ scope.row.recovery_codes }} / {{ scope.row.recovery_total }}
                                </span>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Email code')" width="110">
                            <template #default="scope">
                                <span v-if="scope.row.email_2fa" class="fls_tag is_success">{{ $t('On') }}</span>
                                <span v-else class="fls_cell_muted">—</span>
                            </template>
                        </el-table-column>

                        <el-table-column align="right" width="90">
                            <template #default="scope">
                                <!--
                                    The same row menu the logs table carries, rather than a
                                    red button in every row: removing an app is the lost
                                    device path, not something to be doing down the list.
                                -->
                                <el-dropdown v-if="rowActions(scope.row).length" trigger="click"
                                             @command="command => runCommand(command, scope.row)">
                                    <el-button text :title="$t('Actions')"
                                               :loading="resetting === scope.row.id">
                                        <span class="dashicons dashicons-ellipsis"></span>
                                    </el-button>
                                    <template #dropdown>
                                        <el-dropdown-menu>
                                            <el-dropdown-item v-for="action in rowActions(scope.row)"
                                                              :key="action.command"
                                                              :command="action.command"
                                                              :divided="action.divided">
                                                {{ action.label }}
                                            </el-dropdown-item>
                                        </el-dropdown-menu>
                                    </template>
                                </el-dropdown>
                            </template>
                        </el-table-column>

                        <template #empty>
                            <div class="fls_empty">
                                <span v-html="icons.empty"></span>
                                {{ emptyText }}
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
