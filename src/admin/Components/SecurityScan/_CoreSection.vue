<script type="text/babel">
import icons from './icons';
import FileRows from './_FileRows.vue';
import FolderLists from './_FolderLists.vue';

/*
 * WordPress core, as one line you can open.
 *
 * Core is a single subject with a single verdict, so it gets a single row: changed, or not.
 * The detail underneath is still grouped by the three places the scanner looks, because a
 * path is much easier to place when it sits under the heading it belongs to.
 */
export default {
    name: 'CoreSection',
    components: {
        FileRows,
        FolderLists
    },
    props: {
        /* The core scan payload, or null if core has not been checked in this session. */
        results: {
            type: Object,
            default: null
        },
        ignores: {
            type: Object,
            required: true
        },
        /* True while core is the phase being worked on. */
        checking: {
            type: Boolean,
            default: false
        },
        /*
         * Whether any scan has ever run. Only reached when a scan has run but its findings
         * could not be read back - the stored results having been cleared, say. That is
         * different from never having been checked and should not be worded as though it
         * were, so the row asks for a re-scan rather than claiming nothing has happened.
         */
        everScanned: {
            type: Boolean,
            default: false
        }
    },
    data() {
        return {
            icons,
            open: false
        }
    },
    computed: {
        fileGroups() {
            if (!this.results || !this.results.files) {
                return [];
            }

            const groups = [
                {key: 'root', folderType: '', rootPath: '/', label: '/'},
                {key: 'wp-admin', folderType: 'wp-admin', rootPath: '/wp-admin/', label: '/wp-admin/'},
                {key: 'wp-includes', folderType: 'wp-includes', rootPath: '/wp-includes/', label: '/wp-includes/'}
            ];

            return groups.filter(group => {
                const files = this.results.files[group.key];

                return files && Object.keys(files).length > 0;
            }).map(group => ({...group, files: this.results.files[group.key]}));
        },
        extraFolders() {
            return this.results && this.results.folders ? this.results.folders : [];
        },
        /*
         * Findings split by whether the site has already accepted them.
         *
         * A change on the ignore list is a decision somebody made, not an outstanding problem, so
         * it must not colour the verdict: a site whose only findings are accepted ones is clean,
         * and saying otherwise trains people to ignore an amber row that never goes away. The
         * count is still reported, because "clean" with nothing further said would hide the fact
         * that the ignore list is doing the work.
         */
        counts() {
            const ignoredFiles = this.ignores.files || [];
            const ignoredFolders = this.ignores.folders || [];

            let active = 0;
            let accepted = 0;

            this.fileGroups.forEach(group => {
                Object.keys(group.files).forEach(file => {
                    ignoredFiles.includes(group.rootPath + file) ? accepted++ : active++;
                });
            });

            let activeFolders = 0;
            let acceptedFolders = 0;

            this.extraFolders.forEach(folder => {
                ignoredFolders.includes(folder) ? acceptedFolders++ : activeFolders++;
            });

            return {
                activeFiles: active,
                activeFolders: activeFolders,
                accepted: accepted + acceptedFolders,
                total: active + accepted + activeFolders + acceptedFolders
            };
        },
        activeCount() {
            return this.counts.activeFiles + this.counts.activeFolders;
        },
        /* pending -> checking -> clean | changed. Drives the tag and whether it opens. */
        state() {
            if (this.checking) {
                return 'checking';
            }

            if (!this.results) {
                return 'pending';
            }

            return this.activeCount ? 'changed' : 'clean';
        },
        statusLabel() {
            const labels = {
                checking: this.$t('Checking…'),
                pending: this.everScanned ? this.$t('Re-scan to see details') : this.$t('Not checked yet'),
                clean: this.$t('No changes')
            };

            if (labels[this.state]) {
                return labels[this.state];
            }

            const parts = [];

            if (this.counts.activeFiles) {
                parts.push(this.$_n('%s file', '%s files', this.counts.activeFiles));
            }

            if (this.counts.activeFolders) {
                parts.push(this.$_n('%s folder', '%s folders', this.counts.activeFolders));
            }

            return parts.join(' · ');
        },
        statusTag() {
            if (this.state === 'clean') {
                return 'is_success';
            }

            return this.state === 'changed' ? 'is_warning' : 'is_neutral';
        },
        /* Openable whenever there is anything listed, accepted findings included. */
        canOpen() {
            return this.counts.total > 0;
        }
    }
}
</script>

<template>
    <div class="fls_dcard">
        <!--
            The whole head is the control when there is something to open, and a plain heading
            when there is not - a row that offers to expand into nothing is a small lie.
        -->
        <component :is="canOpen ? 'button' : 'div'"
                   :type="canOpen ? 'button' : null"
                   class="fls_scan_summary"
                   :class="{is_open: open, is_static: !canOpen}"
                   @click="canOpen && (open = !open)">
            <span class="fls_scan_summary_icon" v-html="icons.wordpress"></span>

            <span class="fls_scan_summary_name">{{ $t('WordPress Core') }}</span>

            <span class="fls_scan_summary_tags">
                <span class="fls_tag" :class="statusTag">{{ statusLabel }}</span>

                <!--
                    Said even when the verdict is clean: it is the reason the verdict is clean,
                    and without it the ignore list quietly does its work unmentioned.
                -->
                <span v-if="counts.accepted" class="fls_tag is_neutral">
                    {{ $_n('%s ignored', '%s ignored', counts.accepted) }}
                </span>
            </span>

            <span v-if="canOpen" class="fls_scan_chevron" v-html="icons.chevron"></span>
        </component>

        <div v-if="open" class="fls_scan_detail">
            <template v-if="extraFolders.length">
                <!-- A description, not a path, so not set in the monospace the paths use. -->
                <p class="fls_scan_detail_head is_prose">{{ $t('Extra Folders in Root') }}</p>
                <folder-lists :ignored-files="ignores.folders" root-path="/" :files="extraFolders"/>
            </template>

            <template v-for="group in fileGroups" :key="group.key">
                <p class="fls_scan_detail_head">{{ group.label }}</p>
                <file-rows :files="group.files"
                           :folder-type="group.folderType"
                           :root-path="group.rootPath"
                           :ignored-files="ignores.files"/>
            </template>
        </div>
    </div>
</template>
