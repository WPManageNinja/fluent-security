<script type="text/babel">
import each from 'lodash/each';
import icons from './icons';

/*
 * Directories in the site root that WordPress did not put there. Not a finding on its own -
 * plenty of installs have one - which is why the ignore list exists.
 *
 * Rows only, like _FileRows: these appear inside the expanded core panel, so the panel around
 * them belongs to the caller.
 */
export default {
    name: 'FolderLists',
    props: {
        files: {
            type: Array,
            default: () => []
        },
        ignoredFiles: {
            type: Array,
            default: () => []
        },
        rootPath: {
            type: String,
            default: ''
        }
    },
    data() {
        return {
            icons,
            workingFile: ''
        }
    },
    computed: {
        formattedFiles() {
            const formatted = [];
            const ignoredFiles = this.ignoredFiles || [];

            each(this.files, folder => {
                formatted.push({
                    file: folder,
                    isIgnored: ignoredFiles.includes(folder)
                });
            });

            return formatted;
        },
    },
    methods: {
        toggleIgnore(folder) {
            this.workingFile = folder.file;

            const willRemove = folder.isIgnored;

            this.$post('security-scan-settings/scan/toggle-ignore', {
                will_remove: willRemove ? 'yes' : 'no',
                file: folder.file,
                is_folder: 'yes'
            })
                .then(response => {
                    this.$notify.success(response.message);

                    if (willRemove) {
                        this.ignoredFiles.splice(this.ignoredFiles.indexOf(folder.file), 1);
                    } else {
                        this.ignoredFiles.push(folder.file);
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.workingFile = '';
                });
        }
    }
}
</script>

<template>
    <ul class="fls_scan_files">
        <li v-for="folder in formattedFiles" :key="folder.file"
            v-loading="workingFile === folder.file"
            :class="{is_ignored: folder.isIgnored}">
            <div class="fls_scan_file_main">
                <span class="fls_tag is_neutral">{{ $t('Folder') }}</span>
                <span v-if="folder.isIgnored" class="fls_tag is_neutral">{{ $t('Ignored') }}</span>
                <span class="fls_scan_file_name">{{ folder.file }}</span>
            </div>

            <div class="fls_scan_file_aside">
                <div class="fls_scan_file_actions">
                    <el-dropdown trigger="click" @command="toggleIgnore">
                        <button type="button" class="fls_icon_btn" :title="$t('More')"
                                :aria-label="$t('More actions for this folder')" aria-haspopup="menu"
                                v-html="icons.more"></button>
                        <template #dropdown>
                            <el-dropdown-menu>
                                <el-dropdown-item :command="folder">
                                    {{ folder.isIgnored ? $t('Remove from Ignore List') : $t('Add to Ignore List') }}
                                </el-dropdown-item>
                            </el-dropdown-menu>
                        </template>
                    </el-dropdown>
                </div>
            </div>
        </li>
    </ul>
</template>
