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

export default {
    data() {
        return {
            settings: false,
            user_roles: [],
            low_level_roles: {},
            proxy_config_locked: false,
            proxy_detection: {status: 'none', headers: []},
            /* Null on almost every site - see RivalTwoFa::notice(). */
            two_fa_conflict: null,
            recovery_help_preview: null,
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
                    this.recovery_help_preview = response.recovery_help_preview || null;
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
             * The one setting on this page that changes how the reader themselves signs
             * in, so it says so before it happens - see Bits/selfLockout.js. Nothing
             * breaks either way: saving it leaves this screen working normally and the
             * requirement is met at the next sign-in.
             */
            if (!selfWillOweFactor(this.settings, this.appVars)) {
                return this.postSettings();
            }

            return this.$confirm(
                this.$t('Your own role is on the required list, and this account does not have a passkey or an authenticator app yet. You can carry on using the site, but you will be asked to set one up the next time you sign in.'),
                this.$t('You will need one yourself'),
                {
                    confirmButtonText: this.$t('Save and set it up now'),
                    cancelButtonText: this.$t('Go back'),
                    type: 'warning'
                }
            )
                .then(() => this.postSettings(true))
                /* Cancelled. Nothing is saved and nothing needs saying. */
                .catch(() => {
                });
        },
        postSettings(thenEnroll = false) {
            this.errors = false;
            this.saving = true;

            return this.$post('settings', {settings: this.settings})
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings = response.settings;
                    this.appVars.auth_settings = response.settings;

                    /*
                     * Only where they asked for it by pressing that button, and asked
                     * again against what the server actually stored rather than against
                     * what was posted, because the two can differ. The profile screen
                     * rather than the standalone setup page: it is the fuller of the two
                     * and it is where the admin notice sends everybody else.
                     */
                    if (thenEnroll && selfWillOweFactor(response.settings, this.appVars)) {
                        window.location.href = this.appVars.profile_2fa_url;
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
