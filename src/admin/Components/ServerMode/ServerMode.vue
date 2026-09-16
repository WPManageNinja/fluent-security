<script type="text/babel">
import SettingsHeader from '../Settings/_SettingsHeader.vue';
import SettingsCard from '../Settings/_SettingsCard.vue';
import SettingRow from '../Settings/_SettingRow.vue';

export default {
    name: 'ServerMode',
    components: {SettingsHeader, SettingsCard, SettingRow},
    data() {
        return {
            sites: [],
            loading: false,
            addinNew: false,
            new_site_config: '',
            new_site_token: '',
            saving: false
        }
    },
    methods: {
        fetchSites() {
            this.loading = true;
            this.new_site_token = '';
            this.new_site_config = '';

            this.$get('child-sites')
                .then(response => {
                    this.sites = response.sites;

                    // Nothing connected yet means the only useful thing here is the form.
                    if (!this.sites.length) {
                        this.addinNew = true;
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        addNewSite() {
            this.saving = true;

            this.$post('child-sites', {site_config: this.new_site_config})
                .then(response => {
                    this.new_site_token = response.server_token;
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        copyCode(code) {
            navigator.clipboard.writeText(code)
                .then(() => this.$notify.success(this.$t('Copied to clipboard')))
                .catch(err => this.$notify.error(this.$t('Failed to copy code') + ': ' + err));
        },
        removeSite(url) {
            this.$confirm(this.$t('Are you sure you want to remove this site?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, Remove')
            }).then(() => {
                this.saving = true;

                this.$post('child-sites', {site_url: url, will_remove: 'yes'})
                    .then(response => {
                        this.$notify.success(response.message);
                        this.fetchSites();
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.saving = false;
                    });
            }).catch(() => {
                // Dismissed the confirmation.
            });
        }
    },
    mounted() {
        this.fetchSites();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Remote Auth')"
                        :description="$t('Let other sites sign their users in against this one.')"
                        :show-save="false">
            <template #actions>
                <el-button v-if="!addinNew" size="large" type="primary" @click="addinNew = true">
                    {{ $t('Connect a site') }}
                </el-button>
            </template>
        </SettingsHeader>

        <div class="fls_settings_content">
            <el-skeleton v-if="loading" :animated="true" :rows="5"/>

            <template v-else>
                <SettingsCard v-if="addinNew" :title="$t('Connect a site')"
                              :description="$t('Two steps: paste the child site\'s configuration here, then copy the token you get back into that site.')">
                    <template #actions>
                        <el-button size="small" @click="addinNew = false">{{ $t('Cancel') }}</el-button>
                    </template>

                    <div v-loading="saving">
                        <template v-if="!new_site_token">
                            <SettingRow stacked :label="$t('Child site configuration')"
                                        :description="$t('The JSON shown on the child site\'s own Remote Auth screen.')">
                                <el-input type="textarea" :rows="3" v-model="new_site_config"
                                          :placeholder="$t('Paste the child site config JSON here')"/>
                                <p>
                                    <el-button type="primary" size="small" @click="addNewSite()">
                                        {{ $t('Get the token') }}
                                    </el-button>
                                </p>
                            </SettingRow>
                        </template>

                        <template v-else>
                            <SettingRow stacked :label="$t('Site token')"
                                        :description="$t('Paste this into the child site to finish connecting it. It is shown once.')">
                                <el-input v-model="new_site_token" :readonly="true" type="text">
                                    <template #append>
                                        <el-button @click="copyCode(new_site_token)">{{ $t('Copy') }}</el-button>
                                    </template>
                                </el-input>
                                <p>
                                    <el-button type="primary" size="small" @click="fetchSites()">
                                        {{ $t('Done') }}
                                    </el-button>
                                </p>
                            </SettingRow>
                        </template>
                    </div>
                </SettingsCard>

                <SettingsCard :title="$t('Connected sites')"
                              :description="$t('Each of these can sign its users in using the accounts on this site.')">
                    <el-table :data="sites" class="fls_table"
                              :empty-text="$t('No sites have been connected yet')">
                        <el-table-column prop="site_id" :label="$t('ID')" width="70"/>
                        <el-table-column prop="title" :label="$t('Title')"/>
                        <el-table-column prop="url" :label="$t('Site URL')"/>
                        <el-table-column width="120" align="right">
                            <template #default="scope">
                                <el-button @click="removeSite(scope.row.url)" type="danger" plain size="small">
                                    {{ $t('Remove') }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </SettingsCard>
            </template>
        </div>
    </div>
</template>
