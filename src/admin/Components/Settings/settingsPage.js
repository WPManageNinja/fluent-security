/*
 * Shared behaviour for every page in the settings sidebar.
 *
 * All of these pages edit slices of one option, and saving replaces that option
 * wholesale, so each page loads the entire settings object and sends the entire thing
 * back. Editing only a slice and posting only that slice would erase everything the
 * page did not happen to mention - the same trap the "apply recommended settings"
 * button used to fall into.
 */
import {selfWillOweFactor} from '@/Bits/selfLockout';
import {enrollmentSetupUrl} from '@/Bits/enrollmentGate';

export default {
    data() {
        return {
            settings: false,
            user_roles: [],
            low_level_roles: {},
            proxy_config_locked: false,
            proxy_detection: {status: 'none', headers: []},
            /* Null on almost every site - see TwoFaConflictCheck::notice(). */
            two_fa_conflict: null,
            loading: false,
            saving: false,
            errors: false
        }
    },
    methods: {
        fetchSettings() {
            this.loading = true;

            return this.$get('settings')
                .then(response => {
                    this.settings = response.settings;
                    this.user_roles = response.user_roles;
                    this.low_level_roles = response.low_level_roles;
                    this.proxy_config_locked = response.proxy_config_locked;
                    this.proxy_detection = response.proxy_detection || this.proxy_detection;
                    this.two_fa_conflict = response.two_fa_conflict || null;
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        saveSettings() {
            // Nothing loaded means nothing to save - posting now would overwrite with blanks.
            if (!this.settings) {
                return;
            }

            /*
             * One setting on this page can lock the reader out of the site they are
             * reading it on, and only that one is worth a dialog - see Bits/selfLockout.js.
             */
            if (!selfWillOweFactor(this.settings, this.appVars)) {
                return this.postSettings();
            }

            return this.$confirm(
                this.$t('Your own role is on the required list, and this account does not have a passkey or an authenticator app yet. As soon as you save, this screen stops working until you set one up - we will take you straight there.'),
                this.$t('Set up your own second factor next'),
                {
                    confirmButtonText: this.$t('Save and set it up'),
                    cancelButtonText: this.$t('Go back'),
                    type: 'warning'
                }
            )
                .then(() => this.postSettings())
                /* Cancelled. Nothing is saved and nothing needs saying. */
                .catch(() => {
                });
        },
        postSettings() {
            this.errors = false;
            this.saving = true;

            return this.$post('settings', {settings: this.settings})
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings = response.settings;
                    this.appVars.auth_settings = response.settings;

                    /*
                     * Asked again against what the server actually stored rather than
                     * against what was posted, because the two can differ - and then gone
                     * to, because the alternative is leaving the reader on a screen whose
                     * next request will be refused. The enrollment gate would catch that
                     * and say so, but being sent where you were told you would be sent
                     * beats being stopped and offered a link.
                     */
                    if (selfWillOweFactor(response.settings, this.appVars)) {
                        const url = enrollmentSetupUrl();

                        if (url) {
                            window.location.href = url;
                        }
                    }
                })
                .catch(errors => {
                    this.$handleError(errors);
                    this.errors = errors ? errors.data : false;
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    },
    mounted() {
        this.fetchSettings();
    }
};
