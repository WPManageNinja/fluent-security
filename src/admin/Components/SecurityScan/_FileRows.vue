<script type="text/babel">
import each from 'lodash/each';
import icons from './icons';
import ViewFile from './_ViewFile.vue';

/*
 * The changed files themselves, as rows.
 *
 * Just the rows - no card, no heading. Every place findings appear is now inside something
 * that has been expanded (a core folder, a plugin, a theme), so the surrounding panel is the
 * caller's business and this only knows how to list files and act on them.
 */
export default {
    name: 'FileRows',
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
        /* Prefixed to each file to make the path the ignore list stores. */
        rootPath: {
            type: String,
            default: ''
        },
        /* Core findings are located by their folder... */
        folderType: {
            type: String,
            default: ''
        },
        /* ...and an extension's by which extension they belong to. See _ScanResults.vue. */
        scope: {
            type: Object,
            default: null
        },
        truncated: {
            type: Number,
            default: 0
        }
    },
    data() {
        return {
            icons,
            workingFile: '',
            viewing: false,
            viewingFile: null,
            /* Files put back during this visit, so the rows can say so before the next scan. */
            restoredFiles: []
        }
    },
    computed: {
        formattedFiles() {
            const formatted = [];
            const ignoredFiles = this.ignoredFiles || [];

            each(this.files, (fileData, file) => {
                const fullName = this.rootPath ? this.rootPath + file : file;

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
        statusLabel(status) {
            const labels = {
                new: this.$t('New'),
                modified: this.$t('Modified'),
                deleted: this.$t('Deleted')
            };

            return labels[status] || status;
        },
        /*
         * A file that should not be there at all is the alarming case, so it is the red one;
         * a file that has been edited or removed is amber. Both are worth reading.
         */
        statusTag(status) {
            return status === 'new' ? 'is_blocked' : 'is_warning';
        },
        toggleIgnore(file) {
            this.workingFile = file.file;

            const willRemove = file.isIgnored;

            this.$post('security-scan-settings/scan/toggle-ignore', {
                will_remove: willRemove ? 'yes' : 'no',
                file: file.file
            })
                .then(response => {
                    this.$notify.success(response.message);

                    if (willRemove) {
                        this.ignoredFiles.splice(this.ignoredFiles.indexOf(file.file), 1);
                    } else {
                        this.ignoredFiles.push(file.file);
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.workingFile = '';
                });
        },
        viewFile(file) {
            this.viewing = true;

            this.viewingFile = this.scope
                ? {
                    scope: 'extension',
                    type: this.scope.type,
                    key: this.scope.key,
                    file: file.relativeName,
                    status: file.status
                }
                : {
                    file: file.relativeName,
                    folder: this.folderType,
                    status: file.status
                };
        },
        closeViewer() {
            this.viewing = false;
            this.viewingFile = null;
        },
        /*
         * Marked here rather than removed from the list. The row is a finding from the last
         * scan, and the last scan did find it - what has changed is what the file is now, and
         * saying so is honest in a way that quietly dropping the row would not be. The next
         * scan is what makes the list itself right again.
         */
        onRestored(viewingFile) {
            /*
             * Keyed on the name the viewer was opened with, which is the row's relativeName in
             * both the core and the extension case - not its full path, which is what the row
             * itself is keyed on.
             */
            if (!this.restoredFiles.includes(viewingFile.file)) {
                this.restoredFiles.push(viewingFile.file);
            }
        }
    }
}
</script>

<template>
    <ul class="fls_scan_files">
        <li v-for="file in formattedFiles" :key="file.file"
            v-loading="workingFile === file.file"
            :class="{is_ignored: file.isIgnored}">
            <div class="fls_scan_file_main">
                <span class="fls_tag" :class="statusTag(file.status)">
                    {{ statusLabel(file.status) }}
                </span>
                <span v-if="file.isIgnored" class="fls_tag is_neutral">{{ $t('Ignored') }}</span>
                <span v-if="restoredFiles.includes(file.relativeName)" class="fls_tag is_success">
                    {{ $t('Restored') }}
                </span>
                <span class="fls_scan_file_name" :title="file.file">{{ file.relativeName }}</span>
            </div>

            <div class="fls_scan_file_aside">
                <span v-if="file.modifiedAt" class="fls_scan_file_meta"
                      :title="$t('Modified at (UTC)')">
                    {{ file.modifiedAt }}
                </span>

                <div class="fls_scan_file_actions">
                    <button v-if="file.status !== 'deleted'" type="button" class="fls_icon_btn"
                            :title="$t('View File')" @click="viewFile(file)"
                            v-html="icons.eye"></button>

                    <el-dropdown trigger="click" @command="toggleIgnore">
                        <button type="button" class="fls_icon_btn" :title="$t('More')"
                                v-html="icons.more"></button>
                        <template #dropdown>
                            <el-dropdown-menu>
                                <el-dropdown-item :command="file">
                                    {{ file.isIgnored ? $t('Remove from Ignore List') : $t('Add to Ignore List') }}
                                </el-dropdown-item>
                            </el-dropdown-menu>
                        </template>
                    </el-dropdown>
                </div>
            </div>
        </li>

        <li v-if="truncated" class="fls_scan_files_more">
            {{ $_n('and %s more file', 'and %s more files', truncated) }}
        </li>
    </ul>

    <el-dialog :title="$t('View File')" v-model="viewing" width="70%" :append-to-body="true"
               :before-close="(done) => { closeViewer(); done(); }" :close-on-click-modal="false">
        <view-file v-if="viewingFile" :viewing_file="viewingFile" @restored="onRestored"/>
    </el-dialog>
</template>
