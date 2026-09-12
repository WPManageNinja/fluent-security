<script type="text/babel">
/*
 * What actually changed in one file.
 *
 * A new file has nothing to compare against, so it is shown as it stands; a modified one is
 * shown against the official release. The diff is built into elements with classes rather
 * than into spans with inline colours: coloured text alone is unreadable on a dark
 * background, and a tinted line with a gutter mark says the same thing in both themes.
 */
export default {
    name: 'ViewFile',
    props: ['viewing_file'],
    emits: ['restored', 'deleted'],
    data() {
        return {
            filePath: '',
            fileContent: '',
            originalFileContent: '',
            hasDiff: false,
            loading: true,
            restoring: false,
            restored: false,
            deleting: false,
            deleted: false,
            error: ''
        }
    },
    computed: {
        /*
         * Only ever offered next to the changes it would undo. A file the scan calls "new" has
         * no original to go back to; what it needs is to be deleted, which is a different
         * decision with a different consequence and has a button of its own beside this one.
         */
        canRestore() {
            return this.hasDiff && !this.restored && this.viewing_file.status === 'modified';
        },
        /*
         * The other half of that decision, and the reason this panel is worth opening on a new
         * file at all: having read what is in it, the thing you want next is for it not to be
         * there. Offered here as well as on the row because this is where somebody finds out
         * whether it belongs - and the contents on screen are the last chance to keep a copy of
         * a file that is about to stop existing.
         */
        canDelete() {
            return !this.deleted && this.viewing_file.status === 'new';
        }
    },
    methods: {
        getFileContent() {
            this.error = '';
            this.loading = true;

            this.$get('security-scan-settings/scan/view-file', {viewing_file: this.viewing_file})
                .then(response => {
                    this.filePath = response.filePath;
                    this.hasDiff = response.hasDiff;
                    this.fileContent = response.fileContent;
                    this.originalFileContent = response.originalFileContent;

                    if (response.hasDiff) {
                        this.$nextTick(() => {
                            this.renderDiff();
                        });
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                    this.error = errors && errors.message ? errors.message : '';
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        restore() {
            this.$confirm(this.$t('__restore_file_confirm__'), this.$t('Put this file back?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, restore it')
            }).then(() => {
                this.restoring = true;

                this.$post('security-scan-settings/scan/restore-file', {viewing_file: this.viewing_file})
                    .then(response => {
                        this.$notify.success(response.message);
                        this.restored = true;
                        /*
                         * Re-read rather than assumed. The file on disk is the only thing that
                         * settles whether this worked, and the panel should now be showing it.
                         */
                        this.getFileContent();
                        this.$emit('restored', this.viewing_file);
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.restoring = false;
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        /*
         * Says plainly that it cannot be undone, because it cannot: the file is deleted rather
         * than kept anywhere, and the site's backups are the only copy afterwards.
         */
        del() {
            this.$confirm(this.$t('__delete_file_confirm__', this.filePath), this.$t('Delete this file permanently?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, delete it')
            }).then(() => {
                this.deleting = true;

                this.$post('security-scan-settings/scan/delete-file', {viewing_file: this.viewing_file})
                    .then(response => {
                        this.$notify.success(response.message);
                        this.deleted = true;
                        /*
                         * The panel is showing a file that is no longer there, so it says so
                         * rather than leaving the contents up as though nothing had happened.
                         */
                        this.fileContent = '';
                        this.$emit('deleted', this.viewing_file);
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.deleting = false;
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        renderDiff() {
            const target = this.$refs.fls_diff_viewer;

            if (!target || typeof Diff === 'undefined') {
                return;
            }

            const parts = Diff.diffLines(this.originalFileContent, this.fileContent);
            const fragment = document.createDocumentFragment();

            parts.forEach(part => {
                const line = document.createElement('span');

                line.className = 'fls_diff_part';

                if (part.added) {
                    line.classList.add('is_added');
                } else if (part.removed) {
                    line.classList.add('is_removed');
                }

                line.appendChild(document.createTextNode(part.value));
                fragment.appendChild(line);
            });

            target.innerHTML = '';
            target.appendChild(fragment);
        }
    },
    mounted() {
        this.getFileContent();
    }
}
</script>

<template>
    <div v-loading="loading" :element-loading-text="$t('Loading file…')">
        <div class="fls_file_view_head">
            <p class="fls_file_view_path">{{ filePath }}</p>

            <el-button v-if="canRestore" type="primary" size="small"
                       :loading="restoring" @click="restore">
                {{ $t('Restore this file') }}
            </el-button>
            <el-button v-else-if="canDelete" type="danger" size="small"
                       :loading="deleting" @click="del">
                {{ $t('Delete this file') }}
            </el-button>
            <span v-else-if="restored" class="fls_tag is_success">{{ $t('Restored') }}</span>
            <span v-else-if="deleted" class="fls_tag is_success">{{ $t('Deleted') }}</span>
        </div>

        <pre v-if="error" class="fls_code">{{ error }}</pre>

        <p v-else-if="deleted" class="fls_file_view_gone">
            {{ $t('__file_deleted_note__') }}
        </p>

        <el-input v-else-if="!hasDiff" type="textarea" :rows="24" v-model="fileContent"
                  :readonly="true"/>

        <pre v-else ref="fls_diff_viewer" class="fls_diff"></pre>
    </div>
</template>
