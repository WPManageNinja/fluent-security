<script type="text/babel">
import icons from './icons';

/*
 * The scan's blind spot, and the only thing there is to fill it with.
 *
 * Only plugins and themes from the wordpress.org directory have an official copy to compare
 * against. Anything bought from a vendor, written for this site, or installed from a zip has no
 * published checksums, and no amount of scanning will produce any.
 *
 * Kept apart from the plugins and themes lists rather than mixed in with a grey tag, because
 * these are a different kind of answer: not "we looked and it was fine" but "we could not
 * look". Folding them in with the checked ones would let a reader skim the list and come away
 * believing the whole site had been verified.
 *
 * The snapshot lives here for the same reason. It used to be offered only from the aside,
 * which meant the sentence explaining the gap and the one thing that closes it were in
 * different columns - so a reader met the problem and had to go looking for the answer. The
 * offer now sits directly under the explanation, and each row says whether it is covered,
 * which turns "14 items could not be checked" into fourteen separate answers.
 */
export default {
    name: 'UnverifiedList',
    props: {
        items: {
            type: Array,
            default: () => []
        },
        /* What the snapshot covers overall - see BaselineScanner::summary(). */
        baseline: {
            type: Object,
            default: () => ({exists: false, units: 0, files: 0, changed: 0, coverable: 0})
        },
        /* Per-unit snapshot state, keyed by "type:key" - the same identity a row has. */
        baselineByScope: {
            type: Object,
            default: () => ({})
        },
        busy: {
            type: Boolean,
            default: false
        },
        /* Whether the last scan came back clean, so the right moment can be named when it is. */
        isClean: {
            type: Boolean,
            default: false
        }
    },
    emits: ['snapshot'],
    data() {
        return {
            icons,
            open: false,
            /* Which rows are opened, by scope. More than one, because comparing them is the point. */
            openRows: []
        }
    },
    computed: {
        /*
         * Findings first, then the rows that are only partly watched, then plugins and themes
         * alphabetically.
         *
         * The alphabetical run is what makes this a list to look yourself up in, and it stays -
         * but only below the two things somebody needs to be shown rather than go and find.
         * Five rows are visible until the list is opened, so anything left in alphabetical
         * order can sit behind "Show 7 more" - which for a changed file, or for a plugin this
         * is quietly watching half of, is the one thing this section must never do.
         */
        sorted() {
            const rank = item => {
                const unit = this.unitOf(item);

                if (unit.changed) {
                    return 0;
                }

                return unit.skipped ? 1 : 2;
            };

            return [...this.items].sort((a, b) => {
                const byRank = rank(a) - rank(b);

                if (byRank) {
                    return byRank;
                }

                if (a.type !== b.type) {
                    return a.type === 'plugin' ? -1 : 1;
                }

                return a.name.localeCompare(b.name);
            });
        },
        visible() {
            return this.open ? this.sorted : this.sorted.slice(0, 5);
        },
        changedFiles() {
            return Object.keys(this.baselineByScope).reduce(
                (total, scope) => total + (this.baselineByScope[scope].changed || 0), 0
            );
        },
        recordedCount() {
            return Object.keys(this.baselineByScope)
                .filter(scope => this.baselineByScope[scope].in_snapshot).length;
        },
        /* Installed since the snapshot, so covered by nothing at all. The gap worth naming. */
        missingCount() {
            return this.items.filter(item => !this.unitOf(item).in_snapshot).length;
        },
        /*
         * What the bar above the list says. Three states, and they are genuinely different
         * claims - nothing recorded, recorded and quiet, recorded and something moved - so
         * none of them is phrased as a softer version of another.
         */
        skippedFiles() {
            return Object.keys(this.baselineByScope).reduce(
                (total, scope) => total + (this.baselineByScope[scope].skipped || 0), 0
            );
        },
        barState() {
            if (!this.baseline.exists) {
                return 'none';
            }

            return this.changedFiles ? 'changed' : 'watching';
        },
        barTitle() {
            if (this.barState === 'none') {
                return this.$t('Nothing is watching these files yet');
            }

            if (this.barState === 'changed') {
                return this.$_n(
                    '%s file has changed since your snapshot',
                    '%s files have changed since your snapshot',
                    this.changedFiles
                );
            }

            /*
             * Handed the formatted number, not the raw one. $_n strips the separators back out
             * before deciding plural, so "29,726 files" is both correctly grouped and correctly
             * pluralised - and a five-figure count is exactly where an ungrouped number stops
             * being readable at a glance.
             */
            return this.$_n(
                'Watching %s file against your snapshot',
                'Watching %s files against your snapshot',
                this.readableCount(this.baseline.files)
            );
        }
    },
    methods: {
        readableCount(value) {
            return Number(value || 0).toLocaleString();
        },
        scopeOf(item) {
            return item.type + ':' + item.key;
        },
        unitOf(item) {
            return this.baselineByScope[this.scopeOf(item)]
                || {in_snapshot: false, changed: 0, file_count: 0, skipped: 0, changes: []};
        },
        isOpen(item) {
            return this.openRows.includes(this.scopeOf(item));
        },
        toggle(item) {
            const scope = this.scopeOf(item);

            this.openRows = this.isOpen(item)
                ? this.openRows.filter(open => open !== scope)
                : [...this.openRows, scope];
        },
        rowTag(item) {
            const unit = this.unitOf(item);

            if (unit.changed) {
                return {klass: 'is_blocked', label: this.$_n('%s changed', '%s changed', unit.changed)};
            }

            /*
             * Said before "in your snapshot", because it is the correction to it. A unit over
             * the ceiling is partly watched, and a green tag claiming otherwise is the one
             * thing on this screen that would be actively misleading rather than merely absent.
             */
            if (unit.skipped) {
                return {
                    klass: 'is_warning',
                    label: this.$t(
                        'Watching %s of %s',
                        this.readableCount(unit.file_count),
                        this.readableCount(unit.file_count + unit.skipped)
                    )
                };
            }

            if (unit.in_snapshot) {
                return {klass: 'is_success', label: this.$t('Recorded')};
            }

            return {klass: 'is_neutral', label: this.$t('Not recorded')};
        },
        changeLabel(change) {
            const labels = {
                added: this.$t('new file'),
                modified: this.$t('changed'),
                removed: this.$t('deleted')
            };

            return labels[change.status] || change.status;
        },
        /* The paths past the stored cap are gone; the count they stood for is not. */
        truncatedOf(item) {
            const marker = (this.unitOf(item).changes || []).find(change => change.status === 'truncated');

            return marker ? marker.count : 0;
        },
        listedChanges(item) {
            return (this.unitOf(item).changes || []).filter(change => change.status !== 'truncated');
        },
        readableDate(stamp) {
            if (!stamp) {
                return '';
            }

            return new Date(stamp.replace(' ', 'T')).toLocaleDateString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric'
            });
        },
        snapshotAll() {
            this.$emit('snapshot', []);
        },
        snapshotOne(item) {
            this.$emit('snapshot', [this.scopeOf(item)]);
        }
    }
}
</script>

<template>
    <div class="fls_dcard" v-loading="busy">
        <div class="fls_dcard_head">
            <h2>{{ $t('Premium & Custom Extensions') }}</h2>
            <span class="fls_dcard_meta">{{ $_n('%s with no official copy', '%s with no official copy', items.length) }}</span>
        </div>

        <!-- The note belongs to the list, so it sits in the same block rather than its own. -->
        <div class="fls_dcard_body is_flush">
            <p class="fls_scan_section_note">{{ $t('__unverifiable_extensions_desc__') }}</p>

            <!--
                Directly under the sentence it answers. The wording is about when to take one
                rather than what it does: a snapshot of a site that has already been broken
                into records the break-in as normal, and that is the single way this feature
                fails its owner.
            -->
            <div class="fls_scan_snapshot" :class="'is_' + barState">
                <span class="fls_scan_snapshot_icon"
                      v-html="barState === 'changed' ? icons.alert : icons.radar"></span>

                <div class="fls_scan_snapshot_text">
                    <strong>{{ barTitle }}</strong>

                    <template v-if="barState === 'none'">
                        <span>{{ $t('__baseline_promo__') }}</span>
                        <!--
                            Named as the right moment rather than as a warning, because it is
                            advice about when, not a hazard.
                        -->
                        <em>{{ isClean ? $t('__baseline_when_clean__') : $t('__baseline_when_unclean__') }}</em>
                    </template>

                    <span v-else-if="barState === 'changed'">{{ $t('__baseline_changed_note__') }}</span>

                    <span v-else>
                        {{ $_n('%s plugin or theme recorded', '%s plugins and themes recorded', recordedCount) }}<template
                            v-if="missingCount"> · {{ $_n('%s not yet recorded', '%s not yet recorded', missingCount) }}</template>
                    </span>

                    <!--
                        Its own line, under whichever sentence the bar is making. It qualifies
                        both of them - a clean result and a list of changes are each only as
                        complete as the walk that produced them.
                    -->
                    <em v-if="skippedFiles" class="is_warning">
                        {{ $_n('%s file is not being watched because one plugin or theme is too large to record in full.', '%s files are not being watched because some plugins or themes are too large to record in full.', readableCount(skippedFiles)) }}
                    </em>
                </div>

                <div class="fls_scan_snapshot_actions">
                    <el-button v-if="barState === 'none'" type="primary" size="small"
                               :disabled="busy" @click="snapshotAll">
                        {{ $t('Take a snapshot') }}
                    </el-button>

                    <el-button v-else size="small" :disabled="busy" @click="snapshotAll">
                        {{ changedFiles ? $t('Accept all as they are now') : $t('Update snapshot') }}
                    </el-button>
                </div>
            </div>

            <ul class="fls_scan_exts">
                <li v-for="item in visible" :key="item.type + ':' + item.key"
                    class="fls_scan_ext" :class="{is_alarming: unitOf(item).changed}">
                    <button type="button" class="fls_scan_summary is_row"
                            :class="{is_open: isOpen(item)}" @click="toggle(item)">
                        <span class="fls_scan_summary_icon"
                              v-html="item.type === 'theme' ? icons.theme : icons.plugin"></span>
                        <span class="fls_scan_summary_name" :title="item.name">{{ item.name }}</span>
                        <span v-if="item.version" class="fls_scan_group_version">{{ item.version }}</span>

                        <span class="fls_scan_summary_tags">
                            <span class="fls_tag" :class="rowTag(item).klass">{{ rowTag(item).label }}</span>
                        </span>

                        <span class="fls_scan_chevron" v-html="icons.chevron"></span>
                    </button>

                    <div v-if="isOpen(item)" class="fls_scan_detail">
                        <p class="fls_scan_detail_head is_prose">{{ item.reason_label }}</p>

                        <!--
                            The blind spot, said wherever the unit is described - above the
                            changed files as well as above the quiet ones, because a partial
                            list of changes is exactly the case where it matters most.
                        -->
                        <p v-if="unitOf(item).skipped" class="fls_scan_snapshot_fact is_warning">
                            {{ $t('__baseline_unit_partial__', readableCount(unitOf(item).file_count + unitOf(item).skipped), readableCount(unitOf(item).file_count)) }}
                        </p>

                        <!-- Recorded and something moved: the files, named. -->
                        <template v-if="unitOf(item).changed">
                            <ul class="fls_scan_files">
                                <li v-for="change in listedChanges(item)" :key="change.path">
                                    <span class="fls_scan_file_name">{{ change.path }}</span>
                                    <span class="fls_scan_file_meta">{{ changeLabel(change) }}</span>
                                </li>
                            </ul>

                            <span v-if="truncatedOf(item)" class="fls_scan_files_more">
                                {{ $_n('and %s more file', 'and %s more files', truncatedOf(item)) }}
                            </span>

                            <div class="fls_scan_explain_actions is_padded">
                                <el-button size="small" :disabled="busy" @click="snapshotOne(item)">
                                    {{ $t('Accept these changes') }}
                                </el-button>
                            </div>
                        </template>

                        <!-- Recorded and quiet: what is being watched, and since when. -->
                        <template v-else-if="unitOf(item).in_snapshot">
                            <p class="fls_scan_snapshot_fact">
                                {{ $_n('%s file recorded', '%s files recorded', readableCount(unitOf(item).file_count)) }}<template
                                    v-if="unitOf(item).checked_at"> · {{ $t('last checked') }}
                                {{ readableDate(unitOf(item).checked_at) }}</template>
                            </p>
                        </template>

                        <!-- Not recorded: the gap, and the one button that closes it. -->
                        <template v-else>
                            <p class="fls_scan_snapshot_fact">{{ $t('__baseline_unit_missing__') }}</p>

                            <div class="fls_scan_explain_actions is_padded">
                                <el-button size="small" :disabled="busy" @click="snapshotOne(item)">
                                    {{ $t('Record this one') }}
                                </el-button>
                            </div>
                        </template>
                    </div>
                </li>
            </ul>

            <div v-if="sorted.length > 5" class="fls_scan_exts_more">
                <el-button text size="small" @click="open = !open">
                    {{ open ? $t('Show fewer') : $_n('Show %s more', 'Show %s more', sorted.length - 5) }}
                </el-button>
            </div>
        </div>
    </div>
</template>
