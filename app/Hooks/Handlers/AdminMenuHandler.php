<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Onboarding;
use FluentAuth\App\Services\Optin;
use FluentAuth\App\Services\TransStrings;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\TwoFaBypass;
use FluentAuth\App\Services\TwoFa\WebAuthn\RelyingParty;

class AdminMenuHandler
{
    /**
     * The class that puts the admin app into its dark theme.
     *
     * FluentCart's, deliberately - see printThemeClass().
     */
    const DARK_CLASS = 'fluent_theme_dark';

    public function register()
    {
        add_action('admin_menu', array($this, 'addMenu'));
        add_action('admin_head', array($this, 'printThemeClass'));
    }

    /**
     * Applies the chosen theme to <html> before the page paints.
     *
     * The app itself could do this once Vue has booted, but by then the screen has already
     * been drawn light and the switch reads as a flash. This runs synchronously in <head>,
     * so the first frame is the right one.
     *
     * The storage key, the class name and the `system:<resolved>` form of the stored value
     * are all FluentCart's rather than this plugin's. Both plugins sit in the same admin
     * menu, and a person who has chosen dark in one has chosen it for both - sharing the
     * key is what makes that true without either plugin knowing about the other.
     */
    public function printThemeClass()
    {
        if (!isset($_GET['page']) || $_GET['page'] !== 'fluent-auth') {
            return;
        }

        ?>
        <script>
            (function () {
                var key = 'fluent_theme_mode',
                    stored = localStorage.getItem(key) || localStorage.getItem('fcart_admin_theme'),
                    mode = stored === 'dark' ? 'dark' : (stored === 'light' ? 'light' : 'system'),
                    dark = stored === 'dark' || stored === 'system:dark' ||
                        ((!stored || stored === 'system') && window.matchMedia &&
                            window.matchMedia('(prefers-color-scheme: dark)').matches);

                document.documentElement.setAttribute('data-fct-theme', mode);

                if (dark) {
                    document.documentElement.classList.add('<?php echo esc_js(self::DARK_CLASS); ?>');
                }
            })();
        </script>
        <?php
    }

    public function addMenu()
    {
        $permission = Helper::getAppPermission();
        if (!$permission) {
            return;
        }

        add_menu_page(
            __('FluentAuth Settings', 'fluent-security'),
            __('FluentAuth', 'fluent-security'),
            $permission,
            'fluent-auth',
            array($this, 'render'),
            $this->getMenuIcon(),
            120
        );

        /*
         * The same four destinations the app bar carries, in the same order and under the
         * same names - see the menuItems list in App.vue. WordPress's menu and the app's
         * own bar are two views of one navigation, and a person who learns either one has
         * learned the other.
         *
         * They used to disagree: this listed Login/Signup Forms, Login Redirects and
         * Customize WP Emails as siblings of Settings, at paths (#/auth-shortcodes,
         * #/login-redirects, #/custom-wp-emails) that stopped existing when those screens
         * moved under /settings. Each one opened the app to a blank pane. The screens are
         * still there, in the Settings sidebar, which is the one place a setting is looked
         * for; routes.js keeps the old paths alive as redirects for anything bookmarked.
         */
        add_submenu_page(
            'fluent-auth',
            __('Dashboard', 'fluent-security'),
            __('Dashboard', 'fluent-security'),
            $permission,
            'fluent-auth',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Logs', 'fluent-security'),
            __('Logs', 'fluent-security'),
            $permission,
            'fluent-auth#/logs',
            array($this, 'render')
        );

        /*
         * Lands on Findings rather than on the file scan. The two are tabs of one screen now,
         * and Findings is the one that answers "is anything wrong" without being asked to run.
         */
        add_submenu_page(
            'fluent-auth',
            __('Security', 'fluent-security'),
            __('Security', 'fluent-security'),
            $permission,
            'fluent-auth#/security',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Settings', 'fluent-security'),
            __('Settings', 'fluent-security'),
            $permission,
            'fluent-auth#/settings',
            array($this, 'render')
        );
    }

    public function render()
    {
        if (!wp_next_scheduled('fluent_auth_daily_tasks')) {
            wp_schedule_event(time(), 'daily', 'fluent_auth_daily_tasks');
        }

        if (!wp_next_scheduled('fluent_auth_hourly_tasks')) {
            wp_schedule_event(time(), 'hourly', 'fluent_auth_hourly_tasks');
        }

        add_filter('admin_footer_text', function ($content) {
            return 'Thank you for using <a rel="noopener"  target="_blank" href="https://fluentauth.com">FluentAuth</a> | Write a <a target="_blank" rel="noopener" href="https://wordpress.org/support/plugin/fluent-security/reviews/">review for FluentAuth</a>';
        });

        $currentUser = wp_get_current_user();

        if (function_exists('wp_enqueue_media')) {
            // Editor default styles.
            add_filter('user_can_richedit', '__return_true');
            wp_tinymce_inline_scripts();
            wp_enqueue_editor();
            wp_enqueue_media();
        }

        wp_enqueue_script('diff', FLUENT_AUTH_PLUGIN_URL . 'dist/libs/diff.js', [], '7.0.0', true);

        wp_enqueue_script('fluent_auth_app', FLUENT_AUTH_PLUGIN_URL . 'dist/admin/app.js', ['jquery'], FLUENT_AUTH_VERSION, true);

        $fullName = trim($currentUser->first_name . ' ' . $currentUser->last_name);

        if (!$fullName) {
            $fullName = $currentUser->display_name;
        }

        wp_localize_script('fluent_auth_app', 'fluentAuthAdmin', apply_filters('fluent_security/app_vars', [
            'slug'            => 'fluent-security',
            'nonce'           => wp_create_nonce('fluent-security'),
            'rest'            => [
                'base_url'  => esc_url_raw(rest_url()),
                'url'       => rest_url('fluent-auth'),
                'nonce'     => wp_create_nonce('wp_rest'),
                'namespace' => 'fluent-auth',
                'version'   => '1'
            ],
            /*
             * What word to print for a row's status. Every status the log is written
             * with is in here - two of them were not, which left those rows with a raw
             * slug where the status word should be.
             */
            'auth_statuses'   => Helper::getLogStatuses(),
            // The views bar: what each one is called, what it queries, and where the rule goes.
            'auth_log_views'  => self::getLogViews(),
            'auth_settings'   => Helper::getAuthSettings(),
            // What "apply recommended" writes, and what the dashboard checklist scores against.
            'recommended_settings' => Helper::getRecommendedSettings(),
            'asset_url'       => FLUENT_AUTH_PLUGIN_URL . 'dist/',
            /*
             * Where a member sets up an authenticator app without going into wp-admin.
             * Printed rather than described, because the whole point of it is being an
             * address you can put in a welcome email or a member menu.
             */
            'totp_setup_url'  => TotpSetupPageHandler::getUrl(),
            /*
             * Where an administrator sets up their own second factor. The profile screen
             * rather than the address above, because it is the fuller of the two - passkey,
             * authenticator app and recovery codes on one card - and anyone reading the
             * admin app can reach it. Same place TwoFaReminderHandler's notice points.
             */
            'profile_2fa_url' => admin_url('profile.php#fls-two-factor'),
            /*
             * Browsers refuse WebAuthn outside a secure context, so on a plain http site
             * the switch would turn on a feature that cannot work. The screen says so
             * rather than letting an administrator discover it from a user's report.
             */
            'passkey_supported' => RelyingParty::isSupported(),
            // Used as the example in the redirect URL fields, so the example is real.
            'site_url'        => site_url('/'),
            /*
             * Whether this administrator may see the enrollment list at all.
             *
             * The app's own permission is filterable (fluent_auth/app_permission), so the
             * capability that opens these screens is not necessarily one that carries any
             * right over other people's accounts. Every other screen here is about the
             * site; that one is a list of users, their email addresses and what guards
             * their accounts, so it asks for the capability WordPress uses for exactly
             * that question rather than riding on the app's.
             */
            'can_list_users'  => current_user_can('list_users'),
            'me'              => [
                'id'        => $currentUser->ID,
                'full_name' => $fullName,
                'email'     => $currentUser->user_email,
                // The dashboard greets whoever is reading it, so it needs their face.
                'avatar'    => get_avatar_url($currentUser->ID, ['size' => 96]),
                /*
                 * These two are what let the settings screen notice that a requirement
                 * about to be saved covers the person saving it. Without them, the one
                 * setting on the page that can lock the reader out of their own site was
                 * saved as quietly as the log retention period - and the first they heard
                 * of it was the next request being refused.
                 *
                 * Roles rather than a precomputed "will this lock me out", because the
                 * answer depends on values the reader has not saved yet.
                 */
                'roles'      => array_values($currentUser->roles),
                /*
                 * Whether they already hold a passkey or an authenticator app, so someone
                 * who is protected is not warned about a requirement they already meet.
                 * hasDeviceFactor() rather than isSatisfiedBy(), which reads the saved
                 * level - the level being edited is one of the things in question.
                 */
                'has_device_factor' => DeviceRequirement::hasDeviceFactor($currentUser),
                /*
                 * FLUENT_AUTH_DISABLE_TWO_FA lifts the requirement for this account, so
                 * saving one does not lock them out and warning them that it will would be
                 * a dialog on every unrelated save - the settings screens share one Save.
                 * Read here rather than inferred from has_device_factor, because they are
                 * different facts: one is a credential, the other is a line in
                 * wp-config.php.
                 */
                'two_fa_bypassed'   => TwoFaBypass::isActiveFor($currentUser)
            ],
            /*
             * Whether this site still has a first run waiting for it. The app redirects
             * into the wizard on this, so the question is asked in one place and answered
             * in one place - a site that has finished setup, deliberately left it, or was
             * configured long before the wizard existed never sees it.
             */
            'is_onboarding'   => Onboarding::isRequired(),
            /*
             * Whether the mailing list signup still needs asking. One flag for both places
             * that ask - the wizard's last screen and the dashboard aside - so answering it
             * on either closes it on the other without a reload. See Optin::isRequired().
             */
            'optin_required'  => Optin::isRequired(),
            'i18n'            => TransStrings::getStrings(),
            'suggestedColors' => ['#000000', '#abb8c3', '#ffffff', '#f78da7', '#ff6900', '#fcb900', '#7bdcb5', '#00d084', '#8ed1fc', '#0693e3', '#9b51e0'],
            'has_fluent_smtp' => defined('FLUENTMAIL_PLUGIN_FILE'),
            'fluent_smtp_url' => defined('FLUENTMAIL_PLUGIN_FILE') ? admin_url('options-general.php?page=fluent-mail#/') : '',
        ]));

        echo '<div id="fluent_auth_app"><h3 style="text-align: center; margin-top: 100px;">Loading Settings..</h3></div>';
    }

    /**
     * The views bar as the screen wants it: a list in order, each carrying its own key.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function getLogViews()
    {
        $views = [];

        foreach (Helper::getLogViews() as $key => $view) {
            $views[] = array_merge(['key' => $key], $view);
        }

        return $views;
    }

    private function getMenuIcon()
    {
        return 'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 182.8 203.1"><defs><style>.cls-1{fill:#fff;}</style></defs><g id="Layer_2" data-name="Layer 2"><g id="Layer_1-2" data-name="Layer 1"><path class="cls-1" d="M182.75,23.08S171.7,19.83,140.16,11.7C106.78,3.1,91.4,0,91.4,0S76,3.1,42.64,11.7C11.11,19.83.06,23.08.06,23.08s-1.63,32.5,12.68,91.34c11.54,47.5,54.61,73.79,78.66,88.68,24.06-14.89,67.12-41.18,78.67-88.68C184.37,55.58,182.75,23.08,182.75,23.08ZM90.89,125.68,39.63,139.41V128a17,17,0,0,1,12.58-16.39l62.3-16.71A31.9,31.9,0,0,1,90.89,125.68Zm46.66-50.45L39.63,101.46V90a17,17,0,0,1,12.58-16.4l109-29.2A31.94,31.94,0,0,1,137.55,75.23Z"/></g></g></svg>');
    }
}
