<template>
    <div class="fls_scanner-widgets">
        <div class="fls-scanner-widgets">
            <div class="box dashboard_box">
                <div class="box_header" style="padding: 10px 15px; font-weight: bold; font-size: 16px;">
                    {{ $t('Scheduled Scanning') }}
                </div>
                <div class="box_body" style="padding: 0px 15px 20px;">
                    <template v-if="settings.status == 'active'">
                        <div v-if="settings.auto_scan != 'yes'">
                            <p style="font-weight: bold;">
                                {{ $t('Scheduled scanning is currently disabled') }}
                            </p>
                            <p>
                                {{
                                    $t('Enable auto-scanning of your Core WordPress files and get emails if there has any un-authorized file changes.')
                                }}
                            </p>
                            <template v-if="settings.status == 'active'">
                                <el-button v-loading="saving" :disabled="saving" v-if="scheduling.auto_scan != 'yes'"
                                           type="primary"
                                           @click="scheduling.auto_scan = 'yes'">{
                                    {{ $t('Enable Auto Scanning') }}
                                </el-button>
                                <div v-else>
                                    <el-form label-position="top" v-model="scheduling">
                                        <el-form-item :label="$t('Scanning Interval')">
                                            <el-select v-model="scheduling.scan_interval" :placeholder="$t('Select Interval')">
                                                <el-option :label="$t('Every Hour')" value="hourly"></el-option>
                                                <el-option :label="$t('Daily')" value="daily"></el-option>
                                            </el-select>
                                        </el-form-item>
                                        <el-form-item>
                                            <el-button type="success" @click="saveSchedulingSettings">
                                                {{ $t('Save') }}
                                            </el-button>
                                        </el-form-item>
                                    </el-form>
                                </div>
                            </template>
                        </div>
                        <div v-else>
                            <p style="font-weight: bold;">{{ $t('Scheduled scanning is currently enabled') }}</p>
                            <p>
                                {{ $t('You will get email alerts if there has any un-authorized file changes.') }}
                            </p>
                            <p>
                                <b>{{ $t('Scanning Interval') }}:</b> {{ scheduling.scan_interval }} <br/>
                                <b>{{ $t('Notification Email') }}:</b> {{ settings.account_email_id }}
                            </p>
                            <el-button v-loading="saving" :disabled="saving" style="margin-bottom: 15px;"
                                       @click="disableSchedule">
                                {{ $t('Disable/Change Auto Scanning') }}
                            </el-button>
                        </div>
                    </template>
                    <template v-else-if="settings.status == 'self'">
                        <p style="font-weight: bold;">{{ $t('Scheduled scanning is currently disabled') }}</p>
                        <p>
                            {{ $t('Please get a free API key to enable Scheduled Scanning and get notified when FluentAuth detects file changes.') }}</p>
                        <el-button type="primary" @click="$router.push({name: 'security_scan_register'})">
                            {{ $t('Setup Auto Scanning') }}
                        </el-button>
                    </template>
                </div>
            </div>

            <div v-if="settings.status == 'active'" class="box dashboard_box">
                <div class="box_header" style="padding: 10px 15px; font-weight: bold; font-size: 16px;">
                    {{ $t('Scanner Status') }}
                </div>
                <div class="box_body" style="padding: 20px 15px 20px;">
                    <p style="font-weight: bold;">{{ $t('Scanner Status') }}: {{ settings.status }}</p>
                    <template v-if="settings.last_checked_human">
                        <p style="font-weight: bold;">{{ $t('Last Scanned %s ago', settings.last_checked_human) }}</p>
                        <p style="font-weight: bold;">{{ $t('Last Scanned Status') }}:
                            {{ settings.is_ok == 'yes' ? 'OK' : $t('Found changes') }}</p>
                    </template>
                    <p v-if="settings.status == 'active'">
                        {{ $t('If you want to change the notification email address or disable scanning service,') }} <a
                        v-loading="saving" @click.prevent="resetApi()" href="#">{{ $t('please click here') }}</a>.</p>
                </div>
            </div>

            <div v-if="hasIgnores" class="box dashboard_box">
                <div class="box_header"
                     style="padding: 10px 15px; font-weight: bold; font-size: 16px;display: flex;align-items: center;justify-content: space-between;">
                    <span>{{ $t('Ignored Files & Folders') }}</span>
                    <el-button @click="resetIgnores()" text type="info">
                        {{ $t('Reset') }}
                    </el-button>
                </div>
                <div class="box_body" style="padding: 20px 15px 20px;">
                    <div class="fls_file_lists">
                        <div class="fls_file_item" v-for="folder in ignores.folders" :key="folder">
                            <div class="fls_file_title">
                                <el-icon>
                                    <FolderOpened/>
                                </el-icon>
                                <span>{{ folder }}</span>
                            </div>
                        </div>
                        <div class="fls_file_item" v-for="file in ignores.files" :key="file">
                            <div class="fls_file_title">
                                <el-icon>
                                    <Document/>
                                </el-icon>
                                <span>{{ file }}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
import isEmpty from 'lodash/isEmpty';

export default {
    name: 'ScannerWidgets',
    props: ['settings', 'ignores'],
    data() {
        return {
            scheduling: {
                auto_scan: this.settings.auto_scan,
                scan_interval: this.settings.scan_interval,
            },
            saving: false
        }
    },
    computed: {
        hasIgnores() {
            return !isEmpty(this.ignores.folders) || !isEmpty(this.ignores.files);
        },
    },
    methods: {
        saveSchedulingSettings() {
            this.saving = true;
            this.$post('security-scan-settings/scan/update-schedule-scan', this.scheduling)
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings.auto_scan = response.settings.auto_scan;
                    this.settings.scan_interval = response.settings.scan_interval;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        disableSchedule() {
            this.saving = true;
            this.$post('security-scan-settings/scan/update-schedule-scan', {
                auto_scan: 'no',
                scan_interval: this.scheduling.scan_interval
            })
                .then(response => {
                    this.$notify.success(response.message);
                    this.scheduling.auto_scan = 'no';
                    this.settings.auto_scan = response.settings.auto_scan;
                    this.settings.scan_interval = response.settings.scan_interval;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        resetApi() {
            this.saving = true;
            this.$post('security-scan-settings/scan/reset-api')
                .then(response => {
                    this.$notify.success(response.message);
                    // reload the page
                    window.location.reload();
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        resetIgnores() {

            this.$confirm(this.$t('Are you sure you want to reset the ignored files and folders?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, Reset'),
            }).then(() => {
                this.saving = true;
                this.$post('security-scan-settings/scan/reset-ignores')
                    .then(response => {
                        this.$notify.success(response.message);
                        // reload the page
                        window.location.reload();
                    })
                    .catch((errors) => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.saving = false;
                    });
            })
                .catch(() => {
                    // do nothing
                });
        }
    }
}
</script>
