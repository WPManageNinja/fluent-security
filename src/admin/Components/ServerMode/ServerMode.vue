<template>
    <div class="dashboard box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div class="box_header">
                <p style="font-weight: bold; font-size: 120%; margin: 0;">Use this site as AuthServer for your child
                    site</p>
                <p style="font-weight: normal; margin: 0;">You can use this site as the main Register/Login Provider for
                    your Child Sites. Please read <a href="#" target="_blank" rel="noopener">this doc for the full
                        documentation</a>.</p>
            </div>
            <div class="box_body">
                <el-skeleton v-if="loading" :animated="true" :rows="5"/>
                <div v-else>
                    <h3>
                        Connected Sites
                        <el-button @click="addinNew = !addinNew" type="info" size="small">Add New</el-button>
                    </h3>
                    <div class="" v-if="addinNew">
                        <div style="border: 1px solid #e3e8ee;" class="box dashboard_box">
                            <div class="box_header" style="padding: 10px 15px; font-weight: bold; font-size: 16px;">
                                Add new Site
                            </div>
                            <div v-loading="saving" class="box_body" style="padding: 0px 15px 20px;">
                                <template v-if="!new_site_token">
                                    <p style="font-weight: bold;">Please provide the child site's config JSON</p>
                                    <el-input type="textarea" :rows="2" v-model="new_site_config"
                                              placeholder="Paste the child site config JSON here"></el-input>
                                    <el-button @click="addNewSite" type="success" style="margin-top: 20px;">
                                        Add and Get Site Token
                                    </el-button>
                                </template>
                                <template v-else>
                                    <p>Copy this token in your site site to connect.</p>
                                    <el-input v-model="new_site_token" :readonly="true" type="text">
                                        <template #append>
                                            <el-button @click="copyCode(new_site_token)">Copy</el-button>
                                        </template>
                                    </el-input>
                                    <el-button type="success" @click="fetchSites()" style="margin-top: 20px;">Done!
                                    </el-button>
                                </template>
                            </div>
                        </div>
                    </div>
                    <el-table stripe border :data="sites" empty-text="No sites has been connected yet">
                        <el-table-column prop="site_id" label="Site ID" width="80px;"></el-table-column>
                        <el-table-column prop="title" label="Title">
                            <template #default="scope">
                                {{scope.row.title}}
                            </template>
                        </el-table-column>
                        <el-table-column prop="url" label="Site URL"></el-table-column>
                        <el-table-column width="100px;" prop="status" label="Action">
                            <template #default="scope">
                                <el-button @click="removeSite(scope.row.url)" type="danger" plain size="small">
                                    Remove
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </div>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'ServerMode',
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
                    if(!this.sites.length) {
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
            this.$post('child-sites', {
                site_config: this.new_site_config
            })
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
            navigator.clipboard.writeText(code).then(() => {
                this.$notify.success('Code copied to clipboard');
            }).catch(err => {
                this.$notify.error('Failed to copy code: ' + err);
            });
        },
        removeSite(url) {
            this.$confirm('Are you sure you want to remove this site?', {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: 'Cancel',
                confirmButtonText: 'Yes, Remove'
            }).then(() => {
                this.saving = true;
                this.$post('child-sites', {
                    site_url: url,
                    will_remove: 'yes'
                })
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
                // Do nothing
            });
        }
    },
    mounted() {
        this.fetchSites();
    }
}
</script>
