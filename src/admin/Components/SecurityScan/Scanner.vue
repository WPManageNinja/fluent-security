<template>
    <el-row style="margin-top: 20px;" :gutter="30">
        <el-col :md="16" :sm="24" :xs="24">
            <div v-if="!scanStatus || scanStatus == 'scanning'" class="box dashboard_box">
                <div class="box_header" style="padding: 10px 15px; font-weight: bold; font-size: 16px;">
                    {{ $t('Site Scan') }}
                </div>
                <div class="box_body" style="padding: 10px 30px 30px;">
                    <p>{{$t('__scanner_desc__')}}</p>
                    <el-button v-if="!scanStatus" :disabled="scanStatus == 'scanning'" :loading="scanStatus == 'scanning'" @click="startScanning" size="large" type="primary">
                        {{ $t('Start Scan for WP Core Files') }}
                    </el-button>
                    <div v-else>
                        <h3 style="margin: 0 0 10px;">{{$t('Scanning in progress. Please wait....')}}</h3>
                        <el-skeleton :animated="true" :rows="5"/>
                    </div>

                    <p v-if="error_message" style="color: red;">{{error_message}}</p>

                    <p style="color: red;" v-else-if="settings.is_ok == 'no' && !scanStatus">
                        <span v-html="$t('__last_scan_warning__', settings.last_checked_human)"></span>
                    </p>
                </div>
            </div>

            <div v-else-if="!hasIssues" class="box dashboard_box">
                <div class="box_header" style="padding: 10px 15px; font-weight: bold; font-size: 16px;">
                    {{ $t('Scan Result') }}
                </div>
                <div class="box_body" style="padding: 10px 30px 30px;">
                    <el-alert :title="$t('Awesome! Everything looks good!')" type="success" :closable="false" show-icon/>
                    <p>{{$t('FluentAuth has scanned your site and found no unauthorized changes in WordPress core files.')}}</p>
                    <el-button @click="startScanning" size="large" type="primary">
                        {{ $t('Scan Again') }}
                    </el-button>
                </div>
            </div>

            <div v-else-if="hasIssues" class="box dashboard_box">
                <template v-if="willAlert">
                    <el-alert :title="$t('Alert: Please review the file changes!')" type="error" :closable="false" show-icon/>
                    <p style="font-size: 16px;">
                        {{$t('__file_change_detected__')}}
                    </p>
                </template>
                <template v-else>
                    <el-alert :title="$t('FluentAuth found some file changes, but you previously marked them as ignored.')"
                              type="warning" :closable="false" show-icon/>
                    <p>
                        {{$t('__scanner_result_dec_normal__')}}
                    </p>
                </template>

                <div v-if="scan_results.folders && scan_results.folders.length">
                    <folder-lists :ignored-files="ignores.folders" root-path="/" :files="scan_results.folders"/>
                </div>

                <div v-if="scan_results.files.root">
                    <file-lists folderType="" :ignored-files="ignores.files" :files="scan_results.files.root" root-path="/"/>
                </div>

                <div v-if="scan_results.files['wp-admin']">
                    <file-lists folderType="wp-admin" :ignored-files="ignores.files" :files="scan_results.files['wp-admin']" root-path="/wp-admin/"/>
                </div>

                <div v-if="scan_results.files['wp-includes']">
                    <file-lists folderType="wp-includes" :ignored-files="ignores.files" :files="scan_results.files['wp-includes']"
                                root-path="/wp-includes/"/>
                </div>

                <el-button :disabled="scanStatus == 'scanning'" :loading="scanStatus == 'scanning'" @click="startScanning" size="large" type="primary">
                    {{ $t('Scan Again') }}
                </el-button>
            </div>

        </el-col>
        <el-col :md="8" :sm="24" :xs="24">
            <scanner-widgets :settings="settings" :ignores="ignores"/>
        </el-col>
    </el-row>
</template>

<script type="text/babel">
import FileLists from "./_FileLists.vue";
import FolderLists from "./_FolderLists.vue";
import each from "lodash/each";
import ScannerWidgets from "./_ScannerWidgets.vue";

export default {
    name: 'Scanner',
    props: ['settings', 'ignores'],
    components: {
        ScannerWidgets,
        FileLists,
        FolderLists
    },
    data() {
        return {
            scanStatus: '',
            scan_results: [],
            error_message: '',
            hasIssues: true,
            willAlert: false
        }
    },
    methods: {
        startScanning() {
            this.scan_results = null;
            this.scanStatus = 'scanning';
            this.error_message = '';

            this.$get('security-scan-settings/scan')
                .then(response => {
                    this.willAlert = response.willAlert,
                    this.hasIssues = response.hasIssues;
                    this.scan_results = response.scan_results;
                    this.scanStatus = 'scanned';
                })
                .catch((errors) => {
                    console.log(errors);
                    this.$handleError(errors.message);
                    this.error_message = errors?.message;
                    this.scanStatus = '';
                });
        }
    },
    mounted() {
        if(this.settings.status == 'active' && this.$route.query.auto_scan == 'yes') {
            this.startScanning();
        }
    }
}
</script>
