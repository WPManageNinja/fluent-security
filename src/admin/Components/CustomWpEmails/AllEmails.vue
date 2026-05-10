<template>
    <div class="box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div class="box_header" style="padding: 15px;font-size: 16px;">
                <div style="padding-top: 5px;" class="box_head">
                    {{ $t('Customize Default WordPress System Emails') }}
                    <p style="font-weight: 500; margin: 10px 0 0;">
                        {{$t('Customize your default system emails sent by WordPress. Make it beautiful and use your own content.')}}
                    </p>
                </div>
                <div style="display: flex;" class="box_actions">
                    <el-button @click="$router.push({name: 'template_settings'})" type="primary">
                        {{$t('Template Settings')}}
                    </el-button>
                </div>
            </div>
            <div v-loading="loading" class="box_body_x">
                <h3>{{$t('System Emails send to User')}}</h3>
                <el-table :data="formattedIndexes.user_emails" stripe>
                    <el-table-column min-width="300" prop="name" :label="$t('Description')">
                        <template #default="scope">
                            <div class="fls_email_name">
                                <p class="fls_email_title">
                                    {{ scope.row.title }}
                                </p>
                                <p class="fls_email_desc">{{ scope.row.description }}</p>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="status" width="150" :label="$t('Status')">
                        <template #default="scope">
                            <el-tag :type="getStatusType(scope.row.status)">
                                {{ getStatusName(scope.row.status) }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column width="100" :label="$t('Actions')">
                        <template #default="scope">
                            <el-button size="small" type="primary"
                                       @click="$router.push({ name: 'edit_wp_email', params: { email_id: scope.row.name } })">
                                {{ $t('Edit') }}
                            </el-button>
                        </template>
                    </el-table-column>
                </el-table>

                <h3 style="margin-top: 30px;">{{$t('System Emails send to Site Admin')}}</h3>
                <el-table :data="formattedIndexes.admin_emails" stripe>
                    <el-table-column min-width="300" prop="name" :label="$t('Description')">
                        <template #default="scope">
                            <div class="fls_email_name">
                                <p class="fls_email_title">
                                    {{ scope.row.title }}
                                </p>
                                <p class="fls_email_desc">{{ scope.row.description }}</p>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="status" width="150" :label="$t('Status')">
                        <template #default="scope">
                            <el-tag :type="getStatusType(scope.row.status)">
                                {{ getStatusName(scope.row.status) }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column width="100" :label="$t('Actions')">
                        <template #default="scope">
                            <el-button size="small" type="primary" @click="$router.push({ name: 'edit_wp_email', params: { email_id: scope.row.name } })">
                                {{ $t('Edit') }}
                            </el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
import each from 'lodash/each';

export default {
    name: 'CustomizeWPEmails',
    data() {
        return {
            emailIndexes: [],
            loading: false,
            showTemplateSettings: false
        }
    },
    computed: {
        formattedIndexes() {
            let indexes = {
                user_emails: [],
                admin_emails: []
            };

            each(this.emailIndexes, function (index, email) {
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
        getStatusType(status) {
            if (status == 'system') {
                return 'info';
            } else if (status == 'custom') {
                return 'success';
            } else if (status == 'disabled') {
                return 'danger';
            }
        },
        getStatusName(status) {
            if (status == 'system') {
                return this.$t('System Default');
            } else if (status == 'custom') {
                return this.$t('Enabled');
            } else if (status == 'disabled') {
                return this.$t('Disabled');
            }
            return status;
        }
    },
    mounted() {
        this.fetchEmails();
    }
}
</script>
