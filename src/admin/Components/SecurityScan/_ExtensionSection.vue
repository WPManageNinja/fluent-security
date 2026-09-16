<script type="text/babel">
import ExtensionRow from './_ExtensionRow.vue';

/*
 * All the plugins, or all the themes, with their verdicts.
 *
 * The heading carries the arithmetic - how many were checked, how many came back changed - so
 * the state of the whole set is readable without going down the list. The list itself is
 * ordered by what needs attention rather than alphabetically throughout: anything with changes
 * first, then anything still waiting, then the ones that passed, each group alphabetical.
 * Sorted purely by name, a single changed plugin could sit fortieth.
 */
export default {
    name: 'ExtensionSection',
    components: {
        ExtensionRow
    },
    emits: ['recheck'],
    props: {
        title: {
            type: String,
            required: true
        },
        items: {
            type: Array,
            default: () => []
        },
        ignoredFiles: {
            type: Array,
            default: () => []
        },
        /* Extensions accepted whole - see _ExtensionRow. */
        ignoredFolders: {
            type: Array,
            default: () => []
        },
        /* The extensions in flight right now, as "type:key". More than one, because the walk
         * runs a few at a time - a row should say it is being checked when it actually is. */
        checkingKeys: {
            type: Array,
            default: () => []
        },
        emptyText: {
            type: String,
            default: ''
        }
    },
    data() {
        return {
            /* Collapsed once past this many rows - see visibleItems. */
            showAll: false,
            collapseAfter: 8
        }
    },
    methods: {
        /*
         * Findings the site has not already accepted. Rows decide their own colour the same way
         * (see _ExtensionRow.counts); this is here so the heading and the ordering agree with
         * them rather than counting findings the admin has already signed off.
         */
        activeCount(item) {
            if (!item.result || !item.result.verifiable) {
                return 0;
            }

            const root = '/' + String(item.rel_path || '').replace(/^\/+|\/+$/g, '') + '/';

            return Object.keys(item.result.files || {}).filter(
                file => !this.ignoredFiles.includes(root + file)
            ).length + (item.result.truncated || 0);
        },
        isSuspicious(item) {
            if (!item.result || item.result.verifiable || item.result.severity !== 'suspicious') {
                return false;
            }

            return !this.ignoredFolders.includes('/' + String(item.rel_path || '').replace(/^\/+|\/+$/g, ''));
        }
    },
    computed: {
        sorted() {
            /*
             * Most alarming first. An unpublished version outranks changed files: the files
             * could be a legitimate patch, whereas a version the directory has never released
             * means nothing about the extension could be verified at all.
             */
            const rank = item => {
                if (!item.result) {
                    return 2; // not checked yet
                }

                if (!item.result.verifiable) {
                    if ((item.result.severity || 'unknown') === 'suspicious') {
                        return this.isSuspicious(item) ? 0 : 4;
                    }

                    return 3;
                }

                return this.activeCount(item) ? 1 : 5;
            };

            return [...this.items].sort((a, b) => {
                const byRank = rank(a) - rank(b);

                return byRank !== 0 ? byRank : a.name.localeCompare(b.name);
            });
        },
        /*
         * Long lists are folded after the first few. Everything that needs attention sorts to
         * the top, so what is hidden is the part that passed - but it is still one click away,
         * because "is my plugin in there and did it pass" is the question this list exists for.
         */
        visibleItems() {
            if (this.showAll || this.sorted.length <= this.collapseAfter) {
                return this.sorted;
            }

            return this.sorted.slice(0, this.collapseAfter);
        },
        hiddenCount() {
            return this.sorted.length - this.visibleItems.length;
        },
        checkedCount() {
            return this.items.filter(item => item.result && item.result.verifiable).length;
        },
        changedCount() {
            return this.items.filter(item => this.activeCount(item) > 0).length;
        },
        /* Called out in the heading on its own, because it is not the same kind of problem. */
        suspiciousCount() {
            return this.items.filter(item => this.isSuspicious(item)).length;
        },
        metaLabel() {
            if (!this.items.length) {
                return '';
            }

            if (!this.checkedCount) {
                return this.$_n('%s to check', '%s to check', this.items.length);
            }

            const parts = [this.$t('%s of %s checked', this.checkedCount, this.items.length)];

            if (this.changedCount) {
                parts.push(this.$_n('%s with changes', '%s with changes', this.changedCount));
            }

            if (this.suspiciousCount) {
                parts.push(this.$_n('%s version not on WordPress.org', '%s versions not on WordPress.org', this.suspiciousCount));
            }

            return parts.join(' · ');
        }
    }
}
</script>

<template>
    <div class="fls_dcard">
        <div class="fls_dcard_head">
            <h2>{{ title }}</h2>
            <span v-if="metaLabel" class="fls_dcard_meta">{{ metaLabel }}</span>
        </div>

        <div v-if="!items.length" class="fls_dcard_body">
            <p class="fls_note">{{ emptyText }}</p>
        </div>

        <div v-else class="fls_dcard_body is_flush">
            <ul class="fls_scan_exts">
                <extension-row v-for="item in visibleItems"
                               :key="item.type + ':' + item.key"
                               :item="item"
                               :ignored-files="ignoredFiles"
                               :ignored-folders="ignoredFolders"
                               :checking="checkingKeys.includes(item.type + ':' + item.key)"
                               @recheck="$emit('recheck', $event)"/>
            </ul>

            <div v-if="hiddenCount || showAll" class="fls_scan_exts_more">
                <el-button text size="small" @click="showAll = !showAll">
                    {{ showAll ? $t('Show fewer') : $_n('Show %s more', 'Show %s more', hiddenCount) }}
                </el-button>
            </div>
        </div>
    </div>
</template>
