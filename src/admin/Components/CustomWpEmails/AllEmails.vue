<script type="text/babel">
import each from 'lodash/each';
import SettingsHeader from '../Settings/_SettingsHeader.vue';
import SettingsCard from '../Settings/_SettingsCard.vue';

export default {
    name: 'CustomizeWPEmails',
    components: {SettingsHeader, SettingsCard},
    data() {
        return {
            emailIndexes: [],
            loading: false
        }
    },
    computed: {
        /**
         * Split by who receives the email. The two groups are worth keeping apart:
         * one is what your users see, the other only ever reaches you.
         */
        groups() {
            let indexes = {
                user_emails: [],
                admin_emails: []
            };

            each(this.emailIndexes, function (index) {
                if (index.recipient == 'user') {
                    indexes.user_emails.push(index);
                } else if (index.recipient == 'site_admin') {
                    indexes.admin_emails.push(index);
                }
            });

            return indexes;
        }
    },
    methods: {
        fetchEmails() {
            this.loading = true;

            this.$get('wp-default-emails')
                .then(response => {
                    this.emailIndexes = response.emailIndexes;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /*
         * The three the server actually stores. It used to be matched against 'custom',
         * which is never written, so every customised email fell through and showed the
         * raw word "active".
         */
        getStatusType(status) {
            if (status == 'active') {
                return 'success';
            }

            if (status == 'disabled') {
                return 'danger';
            }

            return 'info';
        },
        getStatusName(status) {
            if (status == 'active') {
                return this.$t('Customized');
            }

            if (status == 'disabled') {
                return this.$t('Disabled');
            }

            if (status == 'system') {
                return this.$t('WordPress default');
            }

            return status;
        },
        editEmail(row) {
            this.$router.push({name: 'settings_edit_email', params: {email_id: row.name}});
        }
    },
    mounted() {
        this.fetchEmails();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('System Emails')"
                        :description="$t('The emails WordPress itself sends, in your own words and your own design.')"
                        :show-save="false">
            <template #actions>
                <!--
                    Bordered, unlike the secondary actions on the screens that have a Save.
                    A borderless button reads as the lesser of two things; with nothing
                    beside it to be lesser than, it just reads as a caption.
                -->
                <el-button size="large" @click="$router.push({name: 'settings_email_template'})">
                    {{ $t('Template design') }}
                </el-button>
            </template>
        </SettingsHeader>

        <div class="fls_settings_content" v-loading="loading">
            <SettingsCard :title="$t('Sent to your users')"
                          :description="$t('Anything left as the WordPress default keeps sending exactly as it does today.')">
                <el-table :data="groups.user_emails" class="fls_table">
                    <el-table-column min-width="300" prop="name" :label="$t('Email')">
                        <template #default="scope">
                            <div class="fls_email_name">
                                <p class="fls_email_title">{{ scope.row.title }}</p>
                                <p class="fls_email_desc">{{ scope.row.description }}</p>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="status" width="160" :label="$t('Status')">
                        <template #default="scope">
                            <el-tag :type="getStatusType(scope.row.status)" disable-transitions>
                                {{ getStatusName(scope.row.status) }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column width="100" align="right">
                        <template #default="scope">
                            <el-button size="small" @click="editEmail(scope.row)">{{ $t('Edit') }}</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </SettingsCard>

            <SettingsCard :title="$t('Sent to you')"
                          :description="$t('Notices about the site itself, delivered to the administration address.')">
                <el-table :data="groups.admin_emails" class="fls_table">
                    <el-table-column min-width="300" prop="name" :label="$t('Email')">
                        <template #default="scope">
                            <div class="fls_email_name">
                                <p class="fls_email_title">{{ scope.row.title }}</p>
                                <p class="fls_email_desc">{{ scope.row.description }}</p>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="status" width="160" :label="$t('Status')">
                        <template #default="scope">
                            <el-tag :type="getStatusType(scope.row.status)" disable-transitions>
                                {{ getStatusName(scope.row.status) }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column width="100" align="right">
                        <template #default="scope">
                            <el-button size="small" @click="editEmail(scope.row)">{{ $t('Edit') }}</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </SettingsCard>
        </div>
    </div>
</template>
