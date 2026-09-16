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
         * Offered only where it can actually do something.
         *
         * Re-encrypting derives the new key from the constant, so with no constant in
         * wp-config.php there is nothing to move the data *to* - SecretMigration::rekey()
         * refuses with `no_new_key` before it reads a single row. The box used to be
         * drawn in that state anyway, so the one screen telling somebody their key is
         * missing also offered them a field that could only ever answer "add the key to
         * your wp-config.php first".
         */
        canRekey() {
            return !!this.problem && this.status.state !== 'constant_missing';
        },
        problem() {
            if (this.status.state === 'constant_missing') {
                return {
                    title: this.$t('The encryption key is missing'),
                    body: this.$t('The %s line is no longer in your wp-config.php. Put the same line back, with the same value, and every authenticator app will work again. If you have the old value but not the line, add any new key line first, then come back to move the data across.', this.status.constant_name)
                };
            }

            if (this.status.state === 'key_changed') {
                return {
                    title: this.$t('The encryption key has changed'),
                    body: this.$t('The %s value in your wp-config.php is not the one the app data was encrypted with. If you still have the old value, paste it below and everything will be moved to the new one.', this.status.constant_name)
                };
            }

            return null;
        },
        sourceNote() {
            return this.$t('Uses the %s value in your wp-config.php. Keep a copy of that value somewhere safe.', this.status.constant_name);
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
                this.$t('The app data goes back to being stored unencrypted. Nobody has to set anything up again.'),
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
                <strong>{{ $t('Encrypt authenticator app data') }}</strong>
                <p>
                    {{ $t('The details that pair each authenticator app with this site are stored in your database. Encrypt them, and a stolen copy of the database cannot be used to make login codes.') }}
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
            {{ $t('Your server is missing OpenSSL, which this needs. Ask your host whether it can be added.') }}
        </el-alert>

        <template v-else-if="loaded">
            <!-- The key is gone or has changed, and some enrollments cannot be read. -->
            <el-alert v-if="problem" type="error" :closable="false" show-icon :title="problem.title">
                <p>{{ problem.body }}</p>
                <p v-if="status.counts.unreadable">
                    {{
                        $_n(
                            '%d authenticator app cannot be read. That user is not locked out, but they will need to set the app up again.',
                            '%d authenticator apps cannot be read. Those users are not locked out, but they will need to set the app up again.',
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
                {{ $t('A key is already in your wp-config.php. Switch this on to encrypt the app data.') }}
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
                    {{ $t('Copy this line into your wp-config.php, above the line that says "That\'s all, stop editing". Save the file, then come back here and switch this on.') }}
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
                    {{ $t('Save it in your password manager before you go on. If this value is ever lost, every authenticator app on the site stops working and each user has to set theirs up again.') }}
                </el-alert>

                <p v-if="status.config.blocked" class="fls_secret_encryption_note">
                    {{ $t('This site does not let plugins edit its files, so the line has to be added by hand.') }}
                </p>
                <p v-else-if="status.config.found && !status.config.writable" class="fls_secret_encryption_note">
                    {{ $t('WordPress cannot write to your wp-config.php, which is normal on managed hosting. The line has to be added by hand.') }}
                </p>

                <div class="fls_secret_encryption_actions">
                    <el-button type="primary" size="small" :loading="loading" @click="fetchStatus()">
                        {{ $t('I have added it, check again') }}
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
                    {{ $t('If you skip this, the app data stays unencrypted, as it is now. Everything keeps working.') }}
                </p>
            </div>

            <p v-else class="fls_secret_encryption_note">
                {{
                    status.config.writable
                        ? $t('Switching this on adds a key to your wp-config.php and encrypts the app data.')
                        : $t('Switching this on gives you a line to add to your wp-config.php yourself.')
                }}
            </p>
        </template>
    </div>
</template>
