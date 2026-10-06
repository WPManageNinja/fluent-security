<script type="text/babel">
import icons from './icons';
import FileRows from './_FileRows.vue';

/*
 * One plugin or theme, as a line you can open.
 *
 * Every installed extension gets a row whether or not anything was found in it. That is the
 * point of the list: "no changes" against a name you recognise is the reassurance, and a list
 * that only showed problems could never give it - you would have no way to tell a plugin that
 * passed from one that was never looked at.
 *
 * Five things a row can say, and they are not degrees of the same thing:
 *
 *   No changes    every file matches what WordPress.org published.
 *   N changes     files differ; open it to see which.
 *   Version not on WordPress.org
 *                 the directory publishes this extension but has never published this version.
 *                 The red one. Nothing was compared, because there was nothing to compare
 *                 against - which is itself the finding, and the shape a tampered copy takes
 *                 when whoever replaced the files also edited the version header.
 *   Expected      the above, acknowledged - a pre-release build looks identical.
 *   Could not be checked
 *                 the attempt failed on the network or the filesystem. Says nothing about the
 *                 extension and is worth retrying.
 */
export default {
    name: 'ExtensionRow',
    components: {
        FileRows
    },
    props: {
        /* An inventory target with its scan result attached, if it has one yet. */
        item: {
            type: Object,
            required: true
        },
        ignoredFiles: {
            type: Array,
            default: () => []
        },
        /* Extensions accepted whole. Mutated in place, the way the file lists do it. */
        ignoredFolders: {
            type: Array,
            default: () => []
        },
        /* True while this is the extension being checked. */
        checking: {
            type: Boolean,
            default: false
        }
    },
    emits: ['recheck'],
    data() {
        return {
            icons,
            open: false,
            saving: false,
            reinstalling: false
        }
    },
    computed: {
        result() {
            return this.item.result || null;
        },
        findings() {
            return this.result && this.result.files ? this.result.files : {};
        },
        truncated() {
            return this.result && this.result.truncated ? this.result.truncated : 0;
        },
        count() {
            return Object.keys(this.findings).length + this.truncated;
        },
        /*
         * Findings split by whether the site has already accepted them - same reasoning as
         * _CoreSection: an accepted change is a decision, not an outstanding problem, so it
         * should not keep the row amber for ever. Findings past the stored cap count as active,
         * since there is no path to have put on the ignore list.
         */
        counts() {
            const ignored = this.ignoredFiles || [];
            let active = this.truncated;
            let accepted = 0;

            Object.keys(this.findings).forEach(file => {
                ignored.includes(this.rootPath + file) ? accepted++ : active++;
            });

            return {active, accepted};
        },
        /*
         * Files here that are not in the release at all - the ones a reinstall moves aside
         * rather than overwrites, and so the ones worth naming before it runs.
         */
        newFileCount() {
            return Object.keys(this.findings)
                .filter(file => this.findings[file].status === 'new')
                .length;
        },
        /* Where the files sit, which is also how the ignore list names them. */
        rootPath() {
            return '/' + String(this.item.rel_path || '').replace(/^\/+|\/+$/g, '') + '/';
        },
        ignorePath() {
            return '/' + String(this.item.rel_path || '').replace(/^\/+|\/+$/g, '');
        },
        isIgnored() {
            return this.ignoredFolders.includes(this.ignorePath);
        },
        severity() {
            return (this.result && this.result.severity) || this.item.severity || 'unknown';
        },
        state() {
            if (this.checking) {
                return 'checking';
            }

            if (!this.result) {
                return 'pending';
            }

            if (!this.result.verifiable) {
                if (this.severity === 'suspicious') {
                    return this.isIgnored ? 'expected' : 'suspicious';
                }

                return 'unchecked';
            }

            return this.counts.active ? 'changed' : 'clean';
        },
        statusLabel() {
            const labels = {
                checking: this.$t('Checking…'),
                pending: this.$t('Not checked yet'),
                expected: this.$t('Expected'),
                clean: this.$t('No changes')
            };

            if (labels[this.state]) {
                return labels[this.state];
            }

            if (this.state === 'suspicious' || this.state === 'unchecked') {
                return (this.result && this.result.reason_label) || this.$t('Could not be checked');
            }

            return this.$_n('%s change', '%s changes', this.counts.active);
        },
        statusTag() {
            const tags = {
                suspicious: 'is_blocked',
                changed: 'is_warning',
                clean: 'is_success'
            };

            return tags[this.state] || 'is_neutral';
        },
        icon() {
            return this.item.type === 'theme' ? icons.theme : icons.plugin;
        },
        scope() {
            return {type: this.item.type, key: this.item.key};
        },
        /*
         * An unpublished version has no file list, but it does have something to explain. A clean
         * row still opens when its findings were all accepted, so they can be reviewed.
         */
        canOpen() {
            if (['suspicious', 'expected'].includes(this.state)) {
                return true;
            }

            return this.count > 0;
        },
        /*
         * Whether this row may offer to put the official copy back.
         *
         * The server decides whether it is possible at all - a premium plugin has no official
         * copy, a single-file plugin has no folder to replace, a folder renamed away from its
         * slug would end up installed twice. What is decided here is whether it is worth
         * offering: a row with nothing wrong has nothing to put back.
         */
        canReinstall() {
            return !!this.item.reinstallable && ['changed', 'suspicious'].includes(this.state);
        },
        /*
         * Said in the row rather than left to the confirm, because it is the answer to "why is
         * there no button here" - which is a question somebody asks while looking at the row.
         */
        blockedReason() {
            if (this.item.reinstallable || !['changed', 'suspicious'].includes(this.state)) {
                return '';
            }

            return this.item.blocked || '';
        }
    },
    watch: {
        /*
         * A row that has just been put right has nothing left to show, so it stops being open
         * rather than standing there with an empty list under it. Watched rather than closed by
         * the reinstall, because a recheck can empty a row for other reasons too.
         */
        canOpen(canOpen) {
            if (!canOpen) {
                this.open = false;
            }
        }
    },
    methods: {
        /*
         * Download the official copy from WordPress.org and replace this folder with it.
         *
         * The same action the recovery screen runs, against the same endpoint, offered here
         * because this is where somebody finds out they need it - they have just opened a
         * plugin and seen a list of files that do not match the release.
         *
         * Confirmed with what it will actually do, in the recovery screen's words. The one
         * thing worth reading twice is the quarantine: a reinstall replaces the folder, so
         * anything in it that the official copy does not contain is moved aside first, and
         * that includes a file somebody put there deliberately.
         */
        reinstall() {
            const lines = [];

            if (this.state === 'suspicious') {
                lines.push(this.$t(
                    '%1s is on version %2s, which WordPress.org never published, so it will be replaced with the current release instead.',
                    this.item.name,
                    this.item.version
                ));
            } else {
                lines.push(this.$t(
                    'This downloads %1s %2s from WordPress.org and replaces its folder.',
                    this.item.name,
                    this.item.version
                ));
            }

            if (this.newFileCount) {
                lines.push(this.$_n(
                    '%s file that is not part of it will be moved to quarantine first.',
                    '%s files that are not part of it will be moved to quarantine first.',
                    this.newFileCount
                ));
            }

            lines.push(this.$t('Its settings are kept.'));

            this.$confirm(lines.join(' '), this.$t('Reinstall %s?', this.item.name), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, reinstall it')
            }).then(() => {
                this.reinstalling = true;

                this.$post('recovery/reinstall-extension', {type: this.item.type, key: this.item.key})
                    .then(response => {
                        this.$notify.success(response.message);
                        /*
                         * Checked again rather than assumed clean. The reinstall reports what it
                         * did; whether this plugin now matches the release is a question only
                         * another comparison answers, and the row should be showing that answer.
                         */
                        this.$emit('recheck', this.item);
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.reinstalling = false;
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        /*
         * Accept, or stop accepting, this extension as a whole.
         *
         * Stored as a folder in the shared ignore list, so it is undone by the same "Reset" the
         * aside already offers for everything else that has been accepted.
         */
        toggleExpected() {
            this.saving = true;

            const willRemove = this.isIgnored;

            this.$post('security-scan-settings/scan/toggle-ignore', {
                will_remove: willRemove ? 'yes' : 'no',
                file: this.ignorePath,
                is_folder: 'yes'
            })
                .then(response => {
                    this.$notify.success(response.message);

                    if (willRemove) {
                        this.ignoredFolders.splice(this.ignoredFolders.indexOf(this.ignorePath), 1);
                    } else {
                        this.ignoredFolders.push(this.ignorePath);
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    }
}
</script>

<template>
    <li class="fls_scan_ext" :class="{is_open: open, is_alarming: state === 'suspicious'}"
        v-loading="saving || reinstalling"
        :element-loading-text="reinstalling ? $t('Reinstalling from WordPress.org…') : ''">
        <component :is="canOpen ? 'button' : 'div'"
                   :type="canOpen ? 'button' : null"
                   class="fls_scan_summary is_row"
                   :class="{is_open: open, is_static: !canOpen}"
                   @click="canOpen && (open = !open)">
            <span class="fls_scan_summary_icon" v-html="icon"></span>

            <span class="fls_scan_summary_name" :title="item.name">{{ item.name }}</span>

            <span v-if="item.version" class="fls_scan_group_version">{{ item.version }}</span>

            <span class="fls_scan_summary_tags">
                <span class="fls_tag" :class="statusTag">{{ statusLabel }}</span>

                <span v-if="counts.accepted" class="fls_tag is_neutral">
                    {{ $_n('%s ignored', '%s ignored', counts.accepted) }}
                </span>
            </span>

            <span v-if="canOpen" class="fls_scan_chevron" v-html="icons.chevron"></span>
        </component>

        <div v-if="open" class="fls_scan_detail">
            <!-- Nothing was compared, so what there is to show is what that means. -->
            <template v-if="state === 'suspicious' || state === 'expected'">
                <div class="fls_scan_explain">
                    <p>
                        {{ $t('__unpublished_version_desc__', item.version) }}
                    </p>
                    <p class="fls_scan_explain_path">{{ rootPath }}</p>

                    <div class="fls_scan_explain_actions">
                        <el-button v-if="canReinstall" type="primary" size="small"
                                   :disabled="reinstalling" @click="reinstall">
                            {{ $t('Replace with the WordPress.org version') }}
                        </el-button>

                        <el-button size="small" :disabled="saving" @click="toggleExpected">
                            {{ isIgnored ? $t('Stop treating as expected') : $t('Mark as expected') }}
                        </el-button>
                    </div>

                    <p v-if="blockedReason" class="fls_scan_blocked">{{ blockedReason }}</p>
                </div>
            </template>

            <template v-else>
                <!--
                    Above the list rather than below it: this replaces every file named under
                    it at once, so it reads as what to do about the whole list rather than as
                    one more row's worth of action.
                -->
                <div v-if="canReinstall || blockedReason" class="fls_scan_ext_action">
                    <div>
                        <p class="fls_scan_ext_action_title">{{ $t('Put the official copy back') }}</p>
                        <p class="fls_scan_ext_action_body">{{ $t('__reinstall_extension_desc__') }}</p>
                    </div>

                    <el-button v-if="canReinstall" type="primary" size="small"
                               :disabled="reinstalling" @click="reinstall">
                        {{ $t('Reinstall from WordPress.org') }}
                    </el-button>
                </div>

                <p v-if="blockedReason" class="fls_scan_blocked">{{ blockedReason }}</p>

                <p class="fls_scan_detail_head">{{ rootPath }}</p>
                <file-rows :files="findings"
                           :scope="scope"
                           :root-path="rootPath"
                           :truncated="truncated"
                           :ignored-files="ignoredFiles"/>
            </template>
        </div>
    </li>
</template>
