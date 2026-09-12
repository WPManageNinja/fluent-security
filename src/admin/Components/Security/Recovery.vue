<script type="text/babel">
import icons from '../SecurityScan/icons';
import {counts as subNavCounts} from '@/Bits/subNav';

/*
 * What to do once you think somebody has been in.
 *
 * Deliberately a sequence rather than a set of controls. Every action here evicts somebody,
 * replaces files or writes to people's inboxes, and the person reading it has just had a
 * fright - a grid of red buttons invites one of them to be pressed at random. Numbered,
 * because the order genuinely changes the outcome: a reset link mailed while a session is
 * still open achieves nothing, and a session revoked while a backdoor is still on disk is
 * re-opened in seconds. So the files come first.
 *
 * The one button above the sequence does the part that can be undone by the people affected
 * simply signing in again. That is the whole reason it can be one button: nothing it does is
 * irreversible, so it is safe to offer to somebody who has not read the rest of the page.
 * Everything below it is a judgement call and stays a separate, described step.
 */
export default {
    name: 'SecurityRecovery',
    data() {
        return {
            icons,
            loading: true,
            securing: false,
            resetting: '',
            /* The row being reinstalled: 'core', or 'type:key' for a plugin or theme. */
            reinstalling: '',
            /* Set while "Reinstall all" walks the list, so no row can be pressed twice. */
            reinstallingAll: false,
            administrators: [],
            progress: {running: false},
            history: [],
            outstanding: {to_fix: 0, open: 0},
            files: null,
            showAdmins: false
        }
    },
    computed: {
        lastUsed() {
            return this.history.length ? this.history[0] : null;
        },
        newAdmins() {
            return this.administrators.filter(admin => admin.is_new);
        },
        core() {
            return this.files ? this.files.core : null;
        },
        extensionRows() {
            return this.files ? this.files.extensions : [];
        },
        reinstallableRows() {
            return this.extensionRows.filter(row => row.reinstallable);
        },
        /* Whether the last scan left anything to put back at all. */
        hasFileFindings() {
            return !!(this.core && this.core.files) || this.extensionRows.length > 0;
        },
        /*
         * One line under the file step's title, and it changes with what is known: nothing
         * has been compared yet, everything matched, or here is what did not.
         */
        filesStepBody() {
            if (!this.files || !this.files.scanned) {
                return this.$t('Nothing has been compared against WordPress.org yet. Run a scan first, so this step knows what to put back.');
            }

            if (!this.hasFileFindings) {
                return this.$t('Checked %s ago: every core file, plugin and theme from the directory matched WordPress.org.', this.files.checked_human);
            }

            return this.$t('Checked %s ago. Each reinstall fetches the official copy from WordPress.org and replaces the whole thing, so a file you cannot see is put back along with the ones you can.', this.files.checked_human);
        },
        /* "3 files changed · 1 not in the release · 2 missing", or nothing. */
        coreStatusLine() {
            if (!this.core || !this.core.files) {
                return '';
            }

            return this.countParts({
                modified: this.core.modified,
                new: this.core.new,
                deleted: this.core.deleted,
                truncated: this.core.truncated
            }).join(' · ');
        },
        busy() {
            return !!this.reinstalling || this.reinstallingAll;
        },
        /* Where the moved files went, and that they are harmless there. */
        quarantineNote() {
            const count = this.files && this.files.quarantine ? this.files.quarantine.files : 0;

            if (!count) {
                return '';
            }

            return this.$t(
                count === 1
                    ? '%1s file is in quarantine at %2s. It cannot run from there. Delete the folder once you are sure you do not need it.'
                    : '%1s files are in quarantine at %2s. They cannot run from there. Delete the folder once you are sure you do not need them.',
                count,
                this.files.quarantine.path
            );
        },
        steps() {
            return [
                {
                    key: 'files',
                    title: this.$t('Put changed files back'),
                    body: this.filesStepBody,
                    warning: this.hasFileFindings
                },
                {
                    key: 'admins',
                    title: this.$t('Check who can change your site'),
                    body: this.newAdmins.length
                        ? this.$_n(
                            'One administrator account was created in the last week.',
                            '%s administrator accounts were created in the last week.',
                            this.newAdmins.length
                        )
                        : this.$_n(
                            'There is %s administrator on this site.',
                            'There are %s administrators on this site.',
                            this.administrators.length
                        ),
                    warning: this.newAdmins.length > 0
                },
                {
                    key: 'passwords',
                    title: this.$t('Ask people to choose a new password'),
                    body: this.$t('This emails a link. It does not stop the old password working until somebody uses it, so sign everyone out first.'),
                    warning: false
                }
            ];
        }
    },
    methods: {
        countParts(counts) {
            const parts = [];

            if (counts.modified) {
                parts.push(this.$_n('%s file changed', '%s files changed', counts.modified));
            }

            if (counts.new) {
                parts.push(this.$_n('%s file not in the release', '%s files not in the release', counts.new));
            }

            if (counts.deleted) {
                parts.push(this.$_n('%s file missing', '%s files missing', counts.deleted));
            }

            if (counts.truncated) {
                parts.push(this.$t('and %s more', counts.truncated));
            }

            return parts;
        },
        rowStatusLine(row) {
            if (row.suspicious) {
                return row.reason_label;
            }

            return this.countParts(row).join(' · ');
        },
        rowActionLabel(row) {
            return row.suspicious ? this.$t('Replace with the WordPress.org release') : this.$t('Reinstall');
        },
        load() {
            this.$get('recovery')
                .then(response => {
                    this.administrators = response.administrators || [];
                    this.progress = response.progress || {running: false};
                    this.history = response.history || [];
                    this.outstanding = response.outstanding || this.outstanding;
                    /* The number on the Findings tab of the bar above, drawn by the shell. */
                    subNavCounts.findings = this.outstanding.open;
                    this.files = response.files || null;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /*
         * Confirmed even though nothing here is destructive, because everybody on the site is
         * about to be signed out of whatever they were doing, and that is worth one deliberate
         * press rather than an accidental one.
         */
        secureNow() {
            this.$confirm(this.$t('__recovery_secure_confirm__'), this.$t('Secure this site now?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, do it')
            }).then(() => {
                this.securing = true;

                this.$post('recovery/secure-now')
                    .then(response => {
                        this.$notify.success(response.message);
                        this.load();
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.securing = false;
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        /*
         * Every reinstall says what it will download, what it will replace, and what it will
         * move aside, before it does any of it. The question is the whole description; a
         * confirm that says "Are you sure?" is a button pressed twice.
         */
        reinstallCore() {
            const core = this.core;
            const lines = [
                this.$t('This downloads WordPress %s from WordPress.org and replaces every file in wp-admin and wp-includes. Your content, plugins, themes and wp-config.php are not touched.', core.version)
            ];

            if (core.removable) {
                lines.push(this.$_n(
                    '%s file that is not part of WordPress will be moved to quarantine first.',
                    '%s files that are not part of WordPress will be moved to quarantine first.',
                    core.removable
                ));
            }

            lines.push(this.$t('The site will be in maintenance mode for a few seconds.'));

            this.confirmReinstall(lines.join(' '), this.$t('Reinstall WordPress %s?', core.version), () => {
                this.reinstalling = 'core';

                return this.$post('recovery/reinstall-core');
            });
        },
        reinstallExtension(row) {
            const lines = [];

            if (row.suspicious) {
                lines.push(this.$t('%1s is on version %2s, which WordPress.org never published, so it will be replaced with the current release instead.', row.name, row.version));
            } else {
                lines.push(this.$t('This downloads %1s %2s from WordPress.org and replaces its folder.', row.name, row.version));
            }

            if (row.new) {
                lines.push(this.$_n(
                    '%s file that is not part of it will be moved to quarantine first.',
                    '%s files that are not part of it will be moved to quarantine first.',
                    row.new
                ));
            }

            lines.push(this.$t('Its settings are kept, because they live in the database.'));

            this.confirmReinstall(lines.join(' '), this.$t('Reinstall %s?', row.name), () => {
                this.reinstalling = row.type + ':' + row.key;

                return this.$post('recovery/reinstall-extension', {type: row.type, key: row.key});
            });
        },
        /*
         * One at a time, deliberately. Each reinstall replaces a folder the site may be
         * executing, and two of those at once on the same server is how a request finds a
         * plugin half-copied.
         */
        reinstallAll() {
            const rows = this.reinstallableRows.slice();
            const lines = [
                this.$_n(
                    'This reinstalls %s plugin or theme from WordPress.org, one after another, moving any file that is not part of the official copy to quarantine first.',
                    'This reinstalls %s plugins and themes from WordPress.org, one after another, moving any file that is not part of the official copy to quarantine first.',
                    rows.length
                )
            ];

            /* Said once here, because the per-row confirm that would have said it is skipped. */
            if (rows.some(row => row.suspicious)) {
                lines.push(this.$t('Anything on a version WordPress.org never published is replaced with the current release instead.'));
            }

            this.$confirm(
                lines.join(' '),
                this.$t('Reinstall all of them?'),
                {
                    type: 'warning',
                    showCancelButton: true,
                    cancelButtonText: this.$t('Cancel'),
                    confirmButtonText: this.$t('Yes, reinstall them')
                }
            ).then(async () => {
                this.reinstallingAll = true;
                let done = 0;

                for (const row of rows) {
                    this.reinstalling = row.type + ':' + row.key;

                    try {
                        const response = await this.$post('recovery/reinstall-extension', {type: row.type, key: row.key});
                        this.applyReinstall(response);
                        done++;
                    } catch (errors) {
                        this.$handleError(errors);
                    }
                }

                this.reinstalling = '';
                this.reinstallingAll = false;
                this.$notify.success(this.$_n('%s reinstalled.', '%s reinstalled.', done));
                this.load();
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        confirmReinstall(question, title, action) {
            this.$confirm(question, title, {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, reinstall it')
            }).then(() => {
                action()
                    .then(response => {
                        this.applyReinstall(response);
                        this.$notify.success(response.message);
                        this.load();
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.reinstalling = '';
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        },
        /* The server re-scans what it reinstalled and sends the whole file picture back. */
        applyReinstall(response) {
            if (response.files) {
                this.files = response.files;
            }

            if (response.failed && response.failed.length) {
                this.$notify.warning(this.$t('%s could not be moved to quarantine and may still be on the server.', response.failed.join(', ')));
            }
        },
        sendResets(scope) {
            const count = scope === 'administrators' ? this.administrators.length : null;

            const question = scope === 'administrators'
                ? this.$_n(
                    'This emails a password reset link to %s administrator. Send it?',
                    'This emails a password reset link to %s administrators. Send it?',
                    count
                )
                : this.$t('This emails a password reset link to every user on this site. Send it?');

            this.$confirm(question, this.$t('Send reset links?'), {
                type: 'warning',
                showCancelButton: true,
                cancelButtonText: this.$t('Cancel'),
                confirmButtonText: this.$t('Yes, send them')
            }).then(() => {
                this.resetting = scope;

                this.$post('recovery/password-resets', {scope: scope})
                    .then(response => {
                        this.$notify.success(response.message);
                        this.progress = response.progress || this.progress;
                        this.load();
                    })
                    .catch(errors => {
                        this.$handleError(errors);
                    })
                    .finally(() => {
                        this.resetting = '';
                    });
            }).catch(() => {
                // Dismissed - nothing to do.
            });
        }
    },
    mounted() {
        this.load();
    }
}
</script>

<template>
    <div class="fls_page">
        <div class="fls_page_inner">
            <div class="fls_page_main">
                <div class="fls_page_head">
                    <div>
                        <h1 class="fls_page_title">{{ $t('Been Hacked?') }}</h1>
                        <p class="fls_page_desc">
                            {{ $t('What to do if you think somebody has been into your site.') }}
                        </p>
                    </div>
                </div>

                <el-skeleton v-if="loading" :animated="true" :rows="6"/>

                <template v-else>
                    <!--
                        The one button, above the sequence. Everything it does can be undone by
                        the people affected signing in again, which is what makes it safe to
                        offer to somebody who has not read the rest of the page.
                    -->
                    <div class="fls_recover_hero">
                        <div class="fls_recover_hero_body">
                            <h2>{{ $t('Think somebody has been in?') }}</h2>
                            <p>{{ $t('__recovery_secure_desc__') }}</p>
                        </div>
                        <el-button type="danger" :loading="securing" @click="secureNow">
                            {{ $t('Secure my site now') }}
                        </el-button>
                    </div>

                    <p v-if="lastUsed" class="fls_recover_last">
                        {{ $t('Last used %1s by %2s', lastUsed.at, lastUsed.by) }} — {{ lastUsed.description }}
                    </p>

                    <ol class="fls_recover_steps">
                        <li v-for="(step, index) in steps" :key="step.key"
                            :class="{is_warning: step.warning}">
                            <span class="fls_recover_num">{{ index + 1 }}</span>

                            <div class="fls_recover_body">
                                <h3>{{ step.title }}</h3>
                                <p>{{ step.body }}</p>

                                <!--
                                    Step one opens in place, with a row per thing that can be
                                    put back. The buttons live on the rows rather than in the
                                    step's action column because each one names what it does.
                                -->
                                <template v-if="step.key === 'files' && files">
                                    <div v-if="hasFileFindings" class="fls_recover_files">
                                        <div v-if="core && core.files" class="fls_recover_file" :class="{is_busy: reinstalling === 'core'}">
                                            <div class="fls_recover_file_main">
                                                <strong>{{ $t('WordPress %s', core.version) }}</strong>
                                                <span class="fls_recover_file_status">{{ coreStatusLine }}</span>
                                                <span v-if="core.blocked && core.fixable" class="fls_recover_file_blocked">
                                                    {{ core.blocked }}
                                                    <a :href="core.update_url" target="_blank" rel="noopener">{{ $t('Open Updates') }}</a>
                                                </span>
                                                <!-- Only root extras: nothing a reinstall would touch, so no button and a reason. -->
                                                <span v-else-if="!core.fixable" class="fls_recover_file_blocked">
                                                    {{ $t('These sit outside wp-admin and wp-includes, so reinstalling WordPress would not touch them. Look at each one under Monitoring and decide whether it belongs.') }}
                                                </span>
                                            </div>
                                            <el-button v-if="core.reinstallable && core.fixable" size="small" type="primary"
                                                       :loading="reinstalling === 'core'" :disabled="busy"
                                                       @click="reinstallCore">
                                                {{ $t('Reinstall WordPress') }}
                                            </el-button>
                                        </div>

                                        <div v-for="row in extensionRows" :key="row.type + ':' + row.key"
                                             class="fls_recover_file" :class="{is_busy: reinstalling === row.type + ':' + row.key}">
                                            <div class="fls_recover_file_main">
                                                <strong>
                                                    {{ row.name }} <span class="fls_recover_file_version">{{ row.version }}</span>
                                                    <span class="fls_tag is_neutral">{{ row.type === 'theme' ? $t('Theme') : $t('Plugin') }}</span>
                                                    <span v-if="row.active" class="fls_tag is_neutral">{{ $t('Active') }}</span>
                                                </strong>
                                                <span class="fls_recover_file_status" :class="{is_suspicious: row.suspicious}">{{ rowStatusLine(row) }}</span>
                                                <span v-if="row.blocked" class="fls_recover_file_blocked">{{ row.blocked }}</span>
                                            </div>
                                            <el-button v-if="row.reinstallable" size="small"
                                                       :loading="reinstalling === row.type + ':' + row.key" :disabled="busy"
                                                       @click="reinstallExtension(row)">
                                                {{ rowActionLabel(row) }}
                                            </el-button>
                                        </div>

                                        <div v-if="reinstallableRows.length > 1" class="fls_recover_files_all">
                                            <el-button size="small" :loading="reinstallingAll" :disabled="busy" @click="reinstallAll">
                                                {{ $t('Reinstall all %s', reinstallableRows.length) }}
                                            </el-button>
                                        </div>
                                    </div>

                                    <!--
                                        What no checksum covers. Listed under the row of things
                                        that can be put back, so "everything matches" is never
                                        read as "everything was checked".
                                    -->
                                    <div v-if="files.unverifiable.length" class="fls_recover_unverifiable">
                                        <p>{{ $t('Nobody can put these back for you. Open each one and read it for anything you did not put there.') }}</p>
                                        <ul>
                                            <li v-for="item in files.unverifiable" :key="item.key">
                                                <strong>{{ item.label }}</strong>
                                                <span v-if="item.modified">{{ $t('changed %s', item.modified) }}</span>
                                                <span>{{ item.detail }}</span>
                                            </li>
                                        </ul>
                                    </div>

                                    <p v-if="files.quarantine.files" class="fls_recover_quarantine">{{ quarantineNote }}</p>
                                </template>

                                <!-- Step two opens in place: the dates are the whole point of it. -->
                                <div v-if="step.key === 'admins' && showAdmins" class="fls_recover_admins">
                                    <div v-for="admin in administrators" :key="admin.id"
                                         class="fls_recover_admin" :class="{is_new: admin.is_new}">
                                        <div>
                                            <strong>{{ admin.login }}</strong>
                                            <span v-if="admin.is_you" class="fls_tag is_neutral">{{ $t('You') }}</span>
                                            <span v-if="admin.is_new" class="fls_tag is_warning">{{ $t('New') }}</span>
                                            <span class="fls_recover_admin_email">{{ admin.email }}</span>
                                        </div>
                                        <div class="fls_recover_admin_dates">
                                            <span>{{ $t('Added %s', admin.registered_human) }}</span>
                                            <!-- The phrase comes whole from the server: the two answers are different claims. -->
                                            <span>{{ admin.last_login }}</span>
                                            <a :href="admin.edit_url" target="_blank" rel="noopener">
                                                {{ $t('Open') }}
                                            </a>
                                        </div>
                                    </div>
                                </div>

                                <div v-if="step.key === 'passwords' && progress.total" class="fls_recover_progress">
                                    {{ $t('%1s of %2s sent', progress.sent, progress.total) }}
                                    <span v-if="progress.failed">
                                        · {{ $_n('%s could not be sent', '%s could not be sent', progress.failed) }}
                                    </span>
                                    <span v-if="progress.running">· {{ $t('still sending') }}</span>
                                </div>
                            </div>

                            <div class="fls_recover_actions">
                                <template v-if="step.key === 'files'">
                                    <el-button v-if="!files || !files.scanned" size="small" type="primary"
                                               @click="$router.push({name: 'security_scans', query: {auto_scan: 'yes'}})">
                                        {{ $t('Run a scan') }}
                                    </el-button>
                                    <el-button v-else size="small" @click="$router.push({name: 'security_scans'})">
                                        {{ hasFileFindings ? $t('Review each file') : $t('Scan again') }}
                                    </el-button>
                                </template>

                                <template v-else-if="step.key === 'admins'">
                                    <el-button size="small" @click="showAdmins = !showAdmins">
                                        {{ showAdmins ? $t('Hide') : $t('Review') }}
                                    </el-button>
                                </template>

                                <template v-else>
                                    <el-button size="small" :loading="resetting === 'administrators'"
                                               :disabled="progress.running"
                                               @click="sendResets('administrators')">
                                        {{ $t('Administrators') }}
                                    </el-button>
                                    <el-button size="small" :loading="resetting === 'all'"
                                               :disabled="progress.running"
                                               @click="sendResets('all')">
                                        {{ $t('Everyone') }}
                                    </el-button>
                                </template>
                            </div>
                        </li>
                    </ol>

                    <p class="fls_recover_note">{{ $t('__recovery_logged__') }}</p>
                </template>
            </div>
        </div>
    </div>
</template>
