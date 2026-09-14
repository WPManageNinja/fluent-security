<script type="text/babel">
/**
 * Encryption of the stored authenticator secrets.
 *
 * The one setting on this screen that cannot be saved with the others, because the key it
 * needs lives in wp-config.php and the server cannot see a line added to that file during
 * the same request. So the switch does not flip optimistically: it moves when the server
 * has read the key back on a later request and said so. Anything else would show "on" over
 * a site that had just written ciphertext it cannot read.
 *
 * Four failing states rather than one, and each gets its own words - two of them are
 * recoverable by pasting the old value back, and lumping them together as "decryption
 * failed" would leave those two looking as final as the one that is not.
 */
export default {
    name: 'SecretEncryption',
    data() {
        return {
            loading: false,
            saving: false,
            loaded: false,
            showInstructions: false,
            rekeying: false,
            writing: false,
            /* Why the write was refused, shown above the line to paste instead. */
            writeFailure: '',
            oldKey: '',
            copied: false,
            status: {
                supported: false,
                state: 'off',
                enabled: false,
                healthy: true,
                has_key: false,
                constant_name: '',
                enrolled: 0,
                counts: {plaintext: 0, unreadable: 0},
                config: {found: false, writable: false, blocked: false, linked: false, path: ''},
                proposed_line: ''
            }
        }
    },
    computed: {
        /*
         * Both ways the key can go wrong are recoverable, as long as the old value still
         * exists somewhere - a password manager, a wp-config.php backup, the deploy that
         * overwrote it. So the box is offered whenever the secrets cannot be read.
         */
        canRekey() {
            return !!this.problem;
        },
        problem() {
            if (this.status.state === 'constant_missing') {
                return {
                    title: this.$t('The encryption key is missing'),
                    body: this.$t('The %s line is no longer in your wp-config.php. If a deployment overwrote the file, putting the same line back makes every authenticator app work again.', this.status.constant_name)
                };
            }

            if (this.status.state === 'key_changed') {
                return {
                    title: this.$t('The encryption key has changed'),
                    body: this.$t('The %s value in your wp-config.php is not the one these secrets were encrypted with. If you still have the previous value, paste it below and everything will be re-encrypted under the new one.', this.status.constant_name)
                };
            }

            return null;
        },
        sourceNote() {
            return this.$t('Keyed to the %s value in your wp-config.php.', this.status.constant_name);
        }
    },
    methods: {
        fetchStatus() {
            this.loading = true;

            return this.$get('two-fa/encryption')
                .then(response => {
                    this.status = Object.assign({}, this.status, response.encryption);
                    this.loaded = true;

                    /*
                     * The key has appeared since the panel was opened, so the instructions
                     * have served their purpose and the next step is the switch.
                     */
                    if (this.status.has_key) {
                        this.showInstructions = false;
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /**
         * The switch is not bound to the status, so nothing moves until the server agrees.
         */
        onToggle(next) {
            if (!next) {
                this.confirmDisable();

                return;
            }

            if (this.status.has_key) {
                this.enable();

                return;
            }

            /*
             * No key yet. Where the site lets us, the line is added for them; where it does
             * not - managed hosting, a read-only deploy, a site that has said plugins may
             * not edit its files - the panel opens with the line to paste. Both are ordinary
             * outcomes, so neither is reported as an error.
             */
            if (this.status.config.writable) {
                this.writeConfig();

                return;
            }

            this.showInstructions = true;
        },
        /**
         * Asks the server to add the line, then switches on in a *separate* request.
         *
         * The second call is not tidiness. wp-config.php was loaded before the write
         * happened, so the process that wrote the line cannot see it; only a new request
         * can. Enabling from the write's own response would mean encrypting under a key
         * that has never once been read back from the file - and a deploy that reverts
         * wp-config.php ten minutes later would leave nothing able to read those rows.
         */
        writeConfig() {
            this.writing = true;
            this.writeFailure = '';

            this.$post('two-fa/encryption/write-config')
                .then(response => {
                    this.status = Object.assign({}, this.status, response.encryption);

                    if (!response.written) {
                        // It could not be done for a reason worth repeating next to the line.
                        this.writeFailure = response.message;
                        this.showInstructions = true;

                        return;
                    }

                    return this.enable();
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.writing = false;
                });
        },
        enable() {
            this.saving = true;

            return this.$post('two-fa/encryption/enable')
                .then(response => {
                    this.status = Object.assign({}, this.status, response.encryption);
                    this.showInstructions = false;
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        /**
         * Spelled out rather than confirmed with a bare "are you sure". Turning this off
         * writes every secret back in the clear, which is a change to what is in the
         * database rather than to a preference.
         */
        confirmDisable() {
            this.$confirm(
                this.$t('Every stored authenticator secret will be written back to the database unencrypted. Nobody has to set anything up again.'),
                this.$t('Turn off encryption?'),
                {
                    confirmButtonText: this.$t('Turn it off'),
                    cancelButtonText: this.$t('Cancel'),
                    type: 'warning'
                }
            )
                .then(() => {
                    this.disable();
                })
                .catch(() => {
                });
        },
        disable() {
            this.saving = true;

            this.$post('two-fa/encryption/disable')
                .then(response => {
                    this.status = Object.assign({}, this.status, response.encryption);
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        rekey() {
            this.rekeying = true;

            this.$post('two-fa/encryption/rekey', {old_key: this.oldKey})
                .then(response => {
                    this.status = Object.assign({}, this.status, response.encryption);
                    this.oldKey = '';
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.rekeying = false;
                });
        },
        closeInstructions() {
            this.showInstructions = false;
            this.writeFailure = '';
        },
        copyLine() {
            const line = this.status.proposed_line;

            if (!line || !navigator.clipboard) {
                return;
            }

            navigator.clipboard.writeText(line).then(() => {
                this.copied = true;
                setTimeout(() => {
                    this.copied = false;
                }, 2000);
            });
        }
    },
    mounted() {
        this.fetchStatus();
    }
};
</script>

<template>
    <div class="fls_secret_encryption" v-loading="loading && !loaded">
        <div class="fls_secret_encryption_head">
            <div>
                <strong>{{ $t('Encrypt stored secrets') }}</strong>
                <p>
                    {{ $t('An authenticator secret has to be readable to check a code, so it cannot be hashed like a password. Encrypting it means a stolen copy of your database is not enough to generate codes.') }}
                </p>
            </div>
            <el-switch v-if="status.supported"
                       :model-value="status.enabled"
                       :loading="saving || writing"
                       :disabled="saving || writing"
                       @change="onToggle"/>
        </div>

        <!--
            Said before anything is offered. A server without the OpenSSL functions cannot
            do this at all, and the switch would only ever fail.
        -->
        <el-alert v-if="loaded && !status.supported" type="info" :closable="false" show-icon
                  :title="$t('This server cannot encrypt')">
            {{ $t('The OpenSSL functions this needs are not available here. Your host can say whether that can change.') }}
        </el-alert>

        <template v-else-if="loaded">
            <!-- The key is gone or has changed, and some enrollments cannot be read. -->
            <el-alert v-if="problem" type="error" :closable="false" show-icon :title="problem.title">
                <p>{{ problem.body }}</p>
                <p v-if="status.counts.unreadable">
                    {{
                        $_n(
                            '%d authenticator app cannot be read. Nobody is locked out - that account is treated as not having one, so they will be asked to set it up again.',
                            '%d authenticator apps cannot be read. Nobody is locked out - those accounts are treated as not having one, so they will be asked to set it up again.',
                            status.counts.unreadable
                        )
                    }}
                </p>

                <div v-if="canRekey" class="fls_rekey">
                    <el-input v-model="oldKey" type="password" show-password
                              :placeholder="$t('Paste the previous key')"/>
                    <el-button type="primary" size="small" :loading="rekeying"
                               :disabled="!oldKey.trim()" @click="rekey()">
                        {{ $t('Re-encrypt') }}
                    </el-button>
                </div>
            </el-alert>

            <!-- On and healthy. The one thing worth saying is what it is keyed to. -->
            <p v-else-if="status.enabled" class="fls_secret_encryption_on">
                <span class="fls_tag is_success">{{ $t('Encrypted') }}</span>
                {{ sourceNote }}
            </p>

            <!--
                Off, with a key already in place - so the switch is all that is left to do
                and there is nothing to explain.
            -->
            <p v-else-if="status.has_key" class="fls_secret_encryption_ready">
                {{ $t('A key is in place. Switch this on to encrypt the stored secrets.') }}
            </p>

            <!-- Off, with no key. The line to paste, and how to come back. -->
            <div v-else-if="showInstructions" class="fls_secret_encryption_setup">
                <!--
                    Only when we tried and could not. Said before the instructions rather
                    than after, because it is the reason they are being asked to do this by
                    hand at all.
                -->
                <el-alert v-if="writeFailure" type="info" :closable="false" show-icon
                          :title="$t('This has to be added by hand')">
                    {{ writeFailure }}
                </el-alert>

                <p>
                    {{ $t('Add this line to your wp-config.php, above the line that says "That\'s all, stop editing", then come back and switch this on.') }}
                </p>

                <div class="fls_config_line">
                    <code>{{ status.proposed_line }}</code>
                    <el-button size="small" text @click="copyLine()">
                        {{ copied ? $t('Copied') : $t('Copy') }}
                    </el-button>
                </div>

                <!--
                    The single most important sentence on this panel. The recovery path for
                    a wp-config.php that gets overwritten exists only if somebody kept a
                    copy of this value.
                -->
                <el-alert type="warning" :closable="false" show-icon
                          :title="$t('Keep a copy of this value')">
                    {{ $t('Store it in your password manager. If wp-config.php is ever overwritten - a deployment will do it - this value is the only way to get the stored secrets back.') }}
                </el-alert>

                <p v-if="status.config.blocked" class="fls_secret_encryption_note">
                    {{ $t('This site is set up so that plugins cannot edit its files, so the line has to be added by hand.') }}
                </p>
                <p v-else-if="status.config.found && !status.config.writable" class="fls_secret_encryption_note">
                    {{ $t('Your wp-config.php is not writable by WordPress, which is usual on managed hosting - the line has to be added by hand.') }}
                </p>

                <div class="fls_secret_encryption_actions">
                    <el-button type="primary" size="small" :loading="loading" @click="fetchStatus()">
                        {{ $t('I have added it - check again') }}
                    </el-button>
                    <el-button size="small" text @click="closeInstructions()">
                        {{ $t('Cancel') }}
                    </el-button>
                </div>

                <!--
                    Said rather than left to be discovered. Without the line the secrets are
                    stored as this plugin always stored them, which is a working site - so
                    walking away from this panel is a choice, not a half-finished setup.
                -->
                <p class="fls_secret_encryption_note">
                    {{ $t('Without this line the secrets are stored unencrypted, exactly as before. Nothing else changes.') }}
                </p>
            </div>

            <p v-else class="fls_secret_encryption_note">
                {{
                    status.config.writable
                        ? $t('Switching this on adds a key to your wp-config.php and encrypts the stored secrets.')
                        : $t('Switching this on will give you a line to add to your wp-config.php.')
                }}
            </p>
        </template>
    </div>
</template>
