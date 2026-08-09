<script type="text/babel">
import icons from '../SecurityScan/icons';
import SecurityTabs from './_SecurityTabs.vue';

/*
 * What to do once you think somebody has been in.
 *
 * Deliberately a sequence rather than a set of controls. Every action here evicts somebody or
 * writes to people's inboxes, and the person reading it has just had a fright - a grid of red
 * buttons invites one of them to be pressed at random. Numbered, because the order genuinely
 * changes the outcome: there is no point mailing everyone a reset link while a session you
 * have not revoked is still open.
 *
 * The one button above the sequence does the part that can be undone by the people affected
 * simply signing in again. That is the whole reason it can be one button: nothing it does is
 * irreversible, so it is safe to offer to somebody who has not read the rest of the page.
 * Everything below it is a judgement call and stays a separate, described step.
 */
export default {
    name: 'SecurityRecovery',
    components: {
        SecurityTabs
    },
    data() {
        return {
            icons,
            loading: true,
            securing: false,
            resetting: '',
            administrators: [],
            progress: {running: false},
            history: [],
            outstanding: {to_fix: 0, open: 0},
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
        /*
         * The snapshot step is not built yet, and a disabled row for something that does not
         * exist is worse than no row - so the sequence simply ends where the plugin does.
         */
        steps() {
            return [
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
                },
                {
                    key: 'files',
                    title: this.$t('Put changed files back'),
                    body: this.$t('Anything that no longer matches what WordPress.org published is listed under Monitoring, with the changes shown, so you can put back only what you meant to.'),
                    warning: false
                }
            ];
        }
    },
    methods: {
        load() {
            this.$get('recovery')
                .then(response => {
                    this.administrators = response.administrators || [];
                    this.progress = response.progress || {running: false};
                    this.history = response.history || [];
                    this.outstanding = response.outstanding || this.outstanding;
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
                        <h1 class="fls_page_title">{{ $t('Security') }}</h1>
                        <p class="fls_page_desc">
                            {{ $t('What to do if you think somebody has been into your site.') }}
                        </p>
                    </div>
                </div>

                <security-tabs :open-count="outstanding.open"/>

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

                                <!-- Step one opens in place: the dates are the whole point of it. -->
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
                                <template v-if="step.key === 'admins'">
                                    <el-button size="small" @click="showAdmins = !showAdmins">
                                        {{ showAdmins ? $t('Hide') : $t('Review') }}
                                    </el-button>
                                </template>

                                <template v-else-if="step.key === 'passwords'">
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

                                <template v-else>
                                    <el-button size="small" @click="$router.push({name: 'security_scans'})">
                                        {{ $t('Open Monitoring') }}
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
