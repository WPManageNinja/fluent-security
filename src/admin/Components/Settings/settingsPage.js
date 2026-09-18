/*
 * Shared behaviour for every page in the settings sidebar.
 *
 * All of these pages edit slices of one option, and saving replaces that option
 * wholesale, so each page loads the entire settings object and sends the entire thing
 * back. Editing only a slice and posting only that slice would erase everything the
 * page did not happen to mention - the same trap the "apply recommended settings"
 * button used to fall into.
 */
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

            this.errors = false;
            this.saving = true;

            return this.$post('settings', {settings: this.settings})
                .then(response => {
                    this.$notify.success(response.message);
                    this.settings = response.settings;
                    this.appVars.auth_settings = response.settings;
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
