<template>
    <div class="box dashboard_box">
        <div class="box_header" style="padding: 10px 15px; font-weight: bold; font-size: 16px;">
            <el-icon>
                <FolderOpened/>
            </el-icon>
            {{ rootPath }}
        </div>
        <div class="box_body">
            <div class="fls_file_lists">
                <div class="fls_file_item" v-for="file in formattedFiles"
                     :class="[
                         'fls_file_list_status_' + file.status,
                          (file.isIgnored) ? 'fls_file_ignored' : ''
                     ]"
                     :key="file.file"
                >
                    <div class="fls_file_title">
                        <el-tag size="small" type="info" :class="'fls_file_icon_type_' + file.status"
                                class="fls_file_icon">
                            <el-icon>
                                <DocumentAdd v-if="file.status == 'new'"/>
                                <Warning v-else-if="file.status == 'modified'"/>
                                <DocumentDelete v-else-if="file.status == 'deleted'"/>
                            </el-icon>
                            <span>{{ $t(file.status) }}</span>
                        </el-tag>
                        <el-tag v-if="file.isIgnored" size="small" type="info" class="fls_file_icon">
                            <MuteNotification/>
                            <span>{{ $t('Ignored') }}</span>
                        </el-tag>
                        <span>{{ file.relativeName }}</span>
                        <el-button v-if="file.status != 'deleted'" @click="viewFile(file)" text size="small">
                            <el-icon>
                                <View/>
                            </el-icon>
                        </el-button>
                    </div>
                    <div v-loading="workingFile == file.file" class="fls_file_status">
                        <span :title="$t('Modified at (UTC)')" style="font-size: 70%; opacity: 0.5;">{{file.modifiedAt}}</span>
                        <el-dropdown @command="handleCommand" trigger="click">
                            <el-button text class="el-dropdown-link">
                                <el-icon>
                                    <MoreFilled/>
                                </el-icon>
                            </el-button>
                            <template #dropdown>
                                <el-dropdown-menu>
                                    <el-dropdown-item :command="file">
                                        <span v-if="file.isIgnored">
                                            {{ $t('Remove from Ignore List') }}
                                        </span>
                                        <span v-else>
                                             {{ $t('Add to Ignore List') }}
                                        </span>
                                    </el-dropdown-item>
                                </el-dropdown-menu>
                            </template>
                        </el-dropdown>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <el-dialog
        :title="$t('View File')"
        v-model="viewing"
        width="60%"
        :append-to-body="true"
        :before-close="(done) => { viewing = false; viewingFile = null; done(); }"
        :close-on-click-modal="false">
        <view-file v-if="viewingFile" :viewing_file="viewingFile" />
    </el-dialog>

</template>

<script type="text/babel">
import each from 'lodash/each';
import ViewFile from './_ViewFile.vue';

export default {
    name: 'FileLists',
    components: {
        ViewFile
    },
    props: {
        files: {
            type: Object,
            default: () => ({})
        },
        ignoredFiles: {
            type: Array,
            default: () => []
        },
        rootPath: {
            type: String,
            default: ''
        },
        folderType: {
            type: String,
            default: ''
        },
        relativeBasePath: {
            type: String,
            default: ''
        }
    },
    data() {
        return {
            workingFile: '',
            viewing: false,
            viewingFile: null
        }
    },
    computed: {
        stats() {
            let statuses = {};
            each(this.files, (fileStatus, file) => {
                file = this.rootPath ? this.rootPath + file : file;
                if (this.ignoredFiles.includes(file)) {
                    fileStatus = 'ignored';
                }
                if (!statuses[fileStatus]) {
                    statuses[fileStatus] = 0;
                }
                statuses[fileStatus] += 1;
            });

            return statuses;
        },
        formattedFiles() {
            let formatted = [];

            let ignoredFiles = this.ignoredFiles;

            if (!ignoredFiles || !ignoredFiles.length) {
                ignoredFiles = [];
            }

            each(this.files, (fileData, file) => {
                let fullName = this.rootPath ? this.rootPath + file : file;
                formatted.push({
                    file: fullName,
                    relativeName: file,
                    status: fileData.status,
                    modifiedAt: fileData.modified_at,
                    isIgnored: ignoredFiles.includes(fullName)
                });
            });

            return formatted;
        }
    },
    methods: {
        handleCommand(file) {
            this.workingFile = file.file;
            let willRemove = file.isIgnored;
            this.$post('security-scan-settings/scan/toggle-ignore', {
                will_remove: willRemove ? 'yes' : 'no',
                file: file.file
            })
                .then((response) => {
                    this.$notify.success(response.message);
                    if (willRemove) {
                        this.ignoredFiles.splice(this.ignoredFiles.indexOf(file.file), 1);
                    } else {
                        this.ignoredFiles.push(this.workingFile);
                    }
                })
                .catch((errors) => {
                    this.$handleError(errors)
                })
                .finally(() => {
                    this.workingFile = '';
                });
        },
        viewFile(file) {
            let filePath = file.relativeName;
            if (this.relativeBasePath) {
                filePath = this.relativeBasePath.replace(/^\/+|\/+$/g, '') + '/' + filePath;
            }

            this.viewing = true;
            this.viewingFile = {
                file: filePath,
                folder: this.folderType,
                status: file.status,
            };
        }
    }
}
</script>
