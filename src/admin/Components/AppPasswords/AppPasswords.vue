<script type="text/babel">
import icons from '../Dashboard/icons';
import SettingsHeader from '../Settings/_SettingsHeader.vue';

/**
 * Every application password on the site, across users.
 *
 * Built like the 2FA enrollment list: views along the top of one card, the same table
 * skin. The whole list comes in one request and is filtered here, because a site has a
 * handful of these, not thousands.
 */
export default {
    name: 'AppPasswords',
    components: {
        SettingsHeader
    },
    data() {
        return {
            icons,
            loading: false,
            loaded: false,
            passwords: [],
            unusedDays: 90,
            available: true,
            turnedOffHere: false,
            truncated: false,
            maxUsers: 1000,
            filter: 'all',
            search: '',
            revoking: '',
            revokingUnused: false
        }
    },
    computed: {
        unused() {
            return this.passwords.filter(row => row.unused);
        },
        userCount() {
            return new Set(this.passwords.map(row => row.user_id)).size;
        },
        views() {
            return [
                {key: 'all', label: this.$t('All')},
                // translators: %d is a number of days
                {key: 'unused', label: this.$t('Not used in %d days', this.unusedDays)}
            ];
        },
        rows() {
            const term = this.search.trim().toLowerCase();

            return (this.filter === 'unused' ? this.unused : this.passwords).filter(row => {
                if (!term) {
                    return true;
                }

                return [row.display_name, row.user_login, row.name].some(value => (value || '').toLowerCase().includes(term));
            });
        },
        summary() {
            return [
                // translators: %s is how many application passwords the site has
                this.$_n('%s password', '%s passwords', this.passwords.length),
                // translators: %s is how many users hold an application password
                this.$_n('%s user', '%s users', this.userCount),
                // translators: %s is how many application passwords nobody has used for a long time
                this.$_n('%s unused', '%s unused', this.unused.length)
            ].join(' · ');
        }
    },
    methods: {
        fetch() {
            this.loading = true;

            this.$get('app-passwords')
                .then(response => this.apply(response))
                .catch(errors => this.$handleError(errors))
                .finally(() => {
                    this.loading = false;
                    this.loaded = true;
                });
        },
        apply(response) {
            this.passwords = response.passwords || [];
            this.unusedDays = response.unused_days || 90;
            this.available = !!response.available;
            this.turnedOffHere = !!response.turned_off_here;
            this.truncated = !!response.truncated;
            this.maxUsers = response.max_users || 1000;
        },
        confirmRevoke(row) {
            this.$confirm(
                // translators: %1$s is the application password's name, %2$s is the user's login name
                this.$t('Anything using "%1$s" will stop signing in as %2$s. This cannot be undone, but they can create a new one from their profile.', row.name, row.user_login),
                this.$t('Revoke this application password?'),
                {
                    confirmButtonText: this.$t('Revoke'),
                    cancelButtonText: this.$t('Cancel'),
                    type: 'warning'
                }
            )
                .then(() => this.revoke(row))
                .catch(() => {
                });
        },
        revoke(row) {
            this.revoking = row.uuid;

            this.$post('app-passwords/revoke', {user_id: row.user_id, uuid: row.uuid})
                .then(response => {
                    this.apply(response);
                    this.$notify.success(response.message);
                })
                .catch(errors => this.$handleError(errors))
                .finally(() => {
                    this.revoking = '';
                });
        },
        confirmRevokeUnused() {
            this.$confirm(
                // translators: %d is a number of days
                this.$t('Anything still using one of them will stop signing in. Every password on this list has gone unused for at least %d days.', this.unusedDays),
                // translators: %s is how many application passwords will be revoked
                this.$_n('Revoke %s unused application password?', 'Revoke %s unused application passwords?', this.unused.length),
                {
                    confirmButtonText: this.$t('Revoke'),
                    cancelButtonText: this.$t('Cancel'),
                    type: 'warning'
                }
            )
                .then(() => this.revokeUnused())
                .catch(() => {
                });
        },
        revokeUnused() {
            this.revokingUnused = true;

            this.$post('app-passwords/revoke-unused')
                .then(response => {
                    this.apply(response);
                    this.filter = 'all';
                    this.$notify.success(response.message);
                })
                .catch(errors => this.$handleError(errors))
                .finally(() => {
                    this.revokingUnused = false;
                });
        }
    },
    mounted() {
        this.fetch();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Application Passwords')"
                        :description="$t('Passwords that apps and services use to sign in as one of your users. Revoke any you do not recognise.')"
                        :show-save="false">
            <template #actions>
                <el-button v-if="unused.length" type="primary" :loading="revokingUnused"
                           @click="confirmRevokeUnused()">
                    <!-- translators: %s is how many unused application passwords the button revokes -->
                    {{ $_n('Revoke the %s unused', 'Revoke the %s unused', unused.length) }}
                </el-button>
            </template>
        </SettingsHeader>

        <div class="fls_settings_content" v-loading="loading && !loaded">
            <el-alert v-if="loaded && !available" type="info" :closable="false" show-icon class="fls_row_alert"
                      :title="$t('Application passwords are turned off')">
                {{ $t('None of these can sign in right now. They will work again if application passwords are turned back on.') }}
                <router-link v-if="turnedOffHere" :to="{name: 'settings_general'}">
                    {{ $t('Review the setting') }}
                </router-link>
            </el-alert>

            <div class="fls_list_card">
                <div class="fls_list_head">
                    <div class="fls_list_head_top">
                        <ul class="fls_tabs">
                            <li v-for="view in views" :key="view.key">
                                <button type="button" :class="{is_active: filter === view.key}"
                                        @click="filter = view.key">
                                    {{ view.label }}
                                </button>
                            </li>
                        </ul>

                        <div class="fls_list_head_actions">
                            <el-input v-model="search" clearable size="small" class="fls_app_pw_search"
                                      :placeholder="$t('Search user or password name')"/>
                            <button type="button" class="fls_icon_btn" :title="$t('Refresh')"
                                    :aria-label="$t('Refresh')" @click="fetch()">
                                <span v-html="icons.refresh"></span>
                            </button>
                        </div>
                    </div>
                    <p v-if="passwords.length" class="fls_app_pw_summary">
                        {{ summary }}
                        <!-- translators: %s is the most users this screen reads -->
                        <template v-if="truncated"> · {{ $t('Showing the first %s users who have one', maxUsers) }}</template>
                    </p>
                </div>

                <div class="fls_list_body">
                    <el-table class="fls_list_table" v-loading="loading" :data="rows" style="width: 100%">
                        <el-table-column :label="$t('User')" min-width="200">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <a class="fls_cell_main" :href="scope.row.profile_url">{{ scope.row.display_name }}</a>
                                    <div class="fls_cell_sub">
                                        {{ scope.row.user_login }}<template v-if="scope.row.roles.length"> &middot; {{ scope.row.roles.join(', ') }}</template>
                                    </div>
                                </div>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Password name')" min-width="160">
                            <template #default="scope">
                                <span class="fls_cell_main">{{ scope.row.name }}</span>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Created')" width="140">
                            <template #default="scope">
                                <span class="fls_cell_muted">{{ scope.row.created_on }}</span>
                            </template>
                        </el-table-column>

                        <el-table-column :label="$t('Last used')" min-width="170">
                            <template #default="scope">
                                <div class="fls_cell_stack">
                                    <div class="fls_cell_main">
                                        <span v-if="scope.row.last_used_ago">{{ scope.row.last_used_ago }}</span>
                                        <span v-else class="fls_cell_muted">{{ $t('Never') }}</span>
                                        <span v-if="scope.row.unused" class="fls_tag is_warning fls_app_pw_tag">{{ $t('Unused') }}</span>
                                    </div>
                                    <div v-if="scope.row.last_ip" class="fls_cell_sub">{{ scope.row.last_ip }}</div>
                                </div>
                            </template>
                        </el-table-column>

                        <el-table-column align="right" width="110">
                            <template #default="scope">
                                <el-button size="small" :loading="revoking === scope.row.uuid"
                                           @click="confirmRevoke(scope.row)">
                                    {{ $t('Revoke') }}
                                </el-button>
                            </template>
                        </el-table-column>

                        <template #empty>
                            <div class="fls_empty">
                                <span v-html="icons.empty"></span>
                                <template v-if="!passwords.length">{{ $t('Nobody on this site has an application password.') }}</template>
                                <template v-else>{{ $t('Nothing matches.') }}</template>
                            </div>
                        </template>
                    </el-table>
                </div>
            </div>
        </div>
    </div>
</template>
