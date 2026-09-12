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
            restoredFiles: [],
            /* And the ones deleted from the server, for the same reason. */
            deletedFiles: []
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
        /*
         * The menu has more than one item now, so what it sends is the action as well as the
         * file. Element Plus passes whatever `command` holds straight through.
         */
        onCommand({action, file}) {
            if (action === 'delete') {
                this.deleteFile(file);
                return;
            }

            this.toggleIgnore(file);
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
        /*
         * Only ever offered for a file that is not part of the official release. A modified
         * file has an original to be put back to, which is what the viewer's restore does;
         * deleting one would take a working part of WordPress off the server.
         */
        canDelete(file) {
            return file.status === 'new' && !this.deletedFiles.includes(file.relativeName);
        },
        /*
         * Confirmed, and the confirmation says plainly that this cannot be undone - because it
         * cannot. The file is deleted rather than kept anywhere, so the only copy left is
         * whatever the site's backups hold, and somebody about to press this should be reading
         * that rather than finding it out afterwards. The path is named in the question so the
         * file being deleted is the file on screen.
         */
        deleteFile(file) {
            this.$confirm(this.$t('__delete_file_confirm__', file.file), this.$t('Delete this file permanently?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, delete it')
            }).then(() => {
                this.workingFile = file.file;

                this.$post('security-scan-settings/scan/delete-file', {
                    viewing_file: this.fileConfig(file)
                })
                    .then(response => {
                        this.$notify.success(response.message);
                        this.onDeleted(file.relativeName);
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.workingFile = '';
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        /*
         * What the server needs to find one file, in the shape the viewer and the restore
         * already use. Built here rather than in each caller so the three of them cannot come
         * to disagree about how a file is named.
         */
        fileConfig(file) {
            return this.scope
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
        viewFile(file) {
            this.viewing = true;
            this.viewingFile = this.fileConfig(file);
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
        },
        /* The same, for a file that has just been deleted from the server. */
        onDeleted(name) {
            if (!this.deletedFiles.includes(name)) {
                this.deletedFiles.push(name);
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
                <span v-if="deletedFiles.includes(file.relativeName)" class="fls_tag is_success">
                    {{ $t('Deleted') }}
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

                    <el-dropdown trigger="click" @command="onCommand">
                        <button type="button" class="fls_icon_btn" :title="$t('More')"
                                v-html="icons.more"></button>
                        <template #dropdown>
                            <el-dropdown-menu>
                                <el-dropdown-item :command="{action: 'ignore', file}">
                                    {{ file.isIgnored ? $t('Remove from Ignore List') : $t('Add to Ignore List') }}
                                </el-dropdown-item>
                                <!--
                                    Divided off and marked, because it is the only item here
                                    that cannot be undone - and it sits next to one that reads
                                    very like it and undoes nothing.
                                -->
                                <el-dropdown-item v-if="canDelete(file)" divided class="fls_menu_danger"
                                                  :command="{action: 'delete', file}">
                                    {{ $t('Delete this file…') }}
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
        <view-file v-if="viewingFile" :viewing_file="viewingFile"
                   @restored="onRestored" @deleted="onDeleted($event.file)"/>
    </el-dialog>
</template>
