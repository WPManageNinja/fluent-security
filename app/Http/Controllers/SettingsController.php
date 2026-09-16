<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\FactorStore;
use FluentAuth\App\Hooks\Handlers\ServerModeHandler;
use FluentAuth\App\Services\ProxyDetection;

class SettingsController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        return [
            'settings'            => Helper::getAuthSettings(),
            'user_roles'          => Helper::getUserRoles(),
            'low_level_roles'     => Helper::getLowLevelRoles(),
            // wp-config.php wins over the saved settings, so say so in the UI.
            'proxy_config_locked' => defined('FLUENT_AUTH_TRUSTED_PROXIES') && FLUENT_AUTH_TRUSTED_PROXIES,
            /*
             * Read from the administrator's own request, so the screen can stay out of
             * the way on the sites that will never need it and speak up on the ones
             * where it is already going wrong.
             */
            'proxy_detection'     => ProxyDetection::detect()
        ];
    }

    public static function updateSettings(\WP_REST_Request $request)
    {
        $settings = self::validateSettings($request->get_param('settings'));
        if (is_wp_error($settings)) {
            return $settings;
        }

        /*
         * The digest window is measured from the last send. Left alone, switching from
         * daily to a weekday could swallow the first weekly digest because a daily one
         * went out a few days ago. A new frequency starts from now.
         */
        $previous = Helper::getSetting('digest_summary');
        if (Arr::get($settings, 'digest_summary') !== $previous) {
            delete_option('_fls_last_digest_sent');
        }

        update_option('__fls_auth_settings', $settings, false);

        /*
         * Both device factors ship switched off, so on most sites the table they share
         * is one nobody will ever have a row in. It is created here, the first time
         * somebody says they want one of them, rather than at activation - where it
         * would be made on every install that will never use it, and, because
         * activation does not run when a plugin updates, still be missing on the sites
         * that would.
         *
         * Asked on the saved state rather than on a change to it. The two differ only
         * when the table has gone missing under a site that already had the setting on,
         * and in that case re-saving the screen repairing it is better than re-saving
         * the screen doing nothing. ensureTable() is a single option read once the
         * table exists, so there is nothing to save by being cleverer.
         */
        if (Arr::get($settings, 'totp_2fa') === 'yes'
            || Arr::get($settings, 'passkey_2fa') === 'yes'
            // Offering passkeys on the login form needs the same table the method does.
            || Arr::get($settings, 'passkey_primary_login') === 'yes'
            // Requiring a factor grants the methods, so it needs the table as much as
            // switching one on does - and can now be set without switching either on.
            || Arr::get($settings, 'totp_required_roles')) {
            FactorStore::ensureTable();
        }

        return [
            'settings' => $settings,
            'message'  => __('Settings have been updated', 'fluent-security')
        ];
    }

    private static function validateSettings($settings)
    {
        $oldSettings = Helper::getAuthSettings();

        $settings = Arr::only($settings, array_keys($oldSettings));

        $numericTypes = [
            'auto_delete_logs_day',
            'login_try_limit',
            'login_try_timing'
        ];

        foreach ($settings as $settingKey => $setting) {
            if (in_array($settingKey, $numericTypes)) {
                $settings[$settingKey] = (int)$setting;
            } else {
                if (is_array($setting)) {
                    $settings[$settingKey] = map_deep($setting, 'sanitize_text_field');
                } else {
                    $settings[$settingKey] = sanitize_text_field($setting);
                }
            }
        }

        /*
         * Every one of these is a list of roles, and an emptied multi-select posts an
         * empty string rather than an empty array. Nothing breaks on it today only
         * because each reader happens to test the value for truth before using it - and
         * `array_intersect('', ...)` is a TypeError waiting for the first one that does
         * not. Stored as the arrays they are declared to be.
         */
        $roleLists = [
            'notification_user_roles',
            'magic_restricted_roles',
            'email2fa_roles',
            'totp_2fa_roles',
            'totp_required_roles',
            'passkey_2fa_roles',
            'disable_bar_roles'
        ];

        foreach ($roleLists as $listKey) {
            if (array_key_exists($listKey, $settings)) {
                $settings[$listKey] = array_values(array_filter((array)$settings[$listKey]));
            }
        }

        /*
         * A switch and a role list saying the same thing, where one combination - on,
         * with nobody chosen - already did nothing, because both handlers return early
         * on an empty list. The screen now offers only the list, so the switch is
         * derived from it and the two can no longer disagree. It is still stored,
         * because the handlers and anything filtering them read it by name.
         */
        $settings['disable_admin_bar'] = empty($settings['disable_bar_roles']) ? 'no' : 'yes';

        $errors = [];

        // Always required now: the attempt limit is no longer something that can be
        // switched off from the settings screen.
        if (empty($settings['login_try_limit'])) {
            $errors['login_try_limit'] = [
                'required' => 'Login try limit is required'
            ];
        }

        if (empty($settings['login_try_timing'])) {
            $errors['login_try_timing'] = [
                'required' => 'Login Timing is required'
            ];
        }

        if ($settings['email2fa'] == 'yes' && empty($settings['email2fa_roles'])) {
            $errors['email2fa_roles'] = [
                'required' => 'Please choose at least one role that needs an emailed code'
            ];
        }

        /*
         * The two rules that used to live here - required roles must also appear in the
         * allow list, and authenticator apps must be switched on first - are gone, and
         * their absence is the point. They existed because requiring a factor did not
         * grant the means to get one, so the lists could disagree and the disagreement
         * was a locked out user. Requiring now grants; the lists cannot disagree; there
         * is nothing left to validate. See DeviceRequirement::isRequiredForUser().
         */
        if (!in_array(Arr::get($settings, 'two_fa_required_level'), ['device', 'any'], true)) {
            $settings['two_fa_required_level'] = 'device';
        }

        /*
         * The login form can only offer what the site has switched on, so the flag is
         * tied to the method rather than allowed to outlive it. Without this, turning
         * passkeys off and on again would bring back a login button the owner had no
         * chance to reconsider - and while it was off the stored 'yes' would have been
         * quietly opening registration to every role through isAllowedForUser().
         */
        if (Arr::get($settings, 'passkey_2fa') !== 'yes'
            || Arr::get($settings, 'passkey_primary_login') !== 'yes') {
            $settings['passkey_primary_login'] = 'no';
        }

        if ($errors) {
            return new \WP_Error('validation_error', 'Form Validation failed', $errors);
        }

        return $settings;

    }


    public static function getAuthFormSettings(\WP_REST_Request $request)
    {

        $settings = Helper::getAuthFormsSettings();

        return [
            'settings'          => $settings,
            'roles'             => Helper::getUserRoles(true),
            'user_capabilities' => Helper::getWpPermissions(true),
            'destinations'      => self::getRedirectDestinations()
        ];
    }

    /**
     * The handful of places a redirect is actually pointed at.
     *
     * Offered as a list rather than left to a blank URL box: three of these four addresses
     * are ones an administrator would otherwise have to remember and type exactly right,
     * and getting one wrong is only discovered by signing out. Anything else is still typed
     * in by hand.
     *
     * @return array
     */
    private static function getRedirectDestinations()
    {
        return [
            'login'  => [
                [
                    'label' => __('Admin dashboard', 'fluent-security'),
                    'url'   => admin_url()
                ],
                [
                    'label' => __('Site home page', 'fluent-security'),
                    'url'   => home_url('/')
                ],
                [
                    'label' => __('Their profile page', 'fluent-security'),
                    'url'   => admin_url('profile.php')
                ]
            ],
            'logout' => [
                [
                    'label' => __('Site home page', 'fluent-security'),
                    'url'   => home_url('/')
                ],
                [
                    'label' => __('The login page', 'fluent-security'),
                    'url'   => wp_login_url()
                ]
            ]
        ];
    }

    /**
     * A redirect target, or an empty string for "leave it to whatever applies next".
     *
     * Relative paths survive this on purpose - `/members/` is a perfectly good answer and
     * one that keeps working when the site moves domain.
     *
     * @param mixed $url
     * @return string
     */
    private static function sanitizeRedirectUrl($url)
    {
        $url = trim((string)$url);

        return $url ? sanitize_url($url) : '';
    }

    public static function saveAuthFormSettings(\WP_REST_Request $request)
    {
        $oldSettings = Helper::getAuthFormsSettings();
        $settings = (array)$request->get_param('settings');

        if (!$settings) {
            $settings = (array)$request->get_param('redirect_settings');

            $oldSettings['login_redirects'] = sanitize_text_field(Arr::get($settings, 'login_redirects', 'no'));

            /*
             * Written every time, empty or not. These used to be skipped when blank, which
             * meant an address could be set but never cleared: choosing "let WordPress
             * decide" saved silently and came back with the old address still in it.
             */
            $oldSettings['default_login_redirect'] = self::sanitizeRedirectUrl(Arr::get($settings, 'default_login_redirect'));
            $oldSettings['default_logout_redirect'] = self::sanitizeRedirectUrl(Arr::get($settings, 'default_logout_redirect'));

            $redirectRules = Arr::get($settings, 'redirect_rules', []);

            $sanitizedRules = [];

            if ($redirectRules) {
                foreach ($redirectRules as $redirect) {
                    $item = [
                        'login'  => self::sanitizeRedirectUrl(Arr::get($redirect, 'login')),
                        'logout' => self::sanitizeRedirectUrl(Arr::get($redirect, 'logout'))
                    ];

                    $conditions = (array)Arr::get($redirect, 'conditions', []);
                    foreach ($conditions as $index => $condition) {
                        $conditions[$index] = map_deep($condition, 'sanitize_text_field');
                    }

                    $item['conditions'] = array_values($conditions);

                    $sanitizedRules[] = $item;
                }
            }

            $oldSettings['redirect_rules'] = $sanitizedRules;

        } else {
            $oldSettings['enabled'] = sanitize_text_field($settings['enabled']);
        }

        update_option('__fls_auth_forms_settings', $oldSettings, false);

        return [
            'message'  => __('Settings have been updated', 'fluent-security'),
            'settings' => $oldSettings
        ];
    }

    public static function getAuthCustomizerSetting(\WP_REST_Request $request)
    {
        return [
            'settings'        => Helper::getAuthCustomizerSettings(),
            'login_form_html' => ''
        ];
    }

    public static function saveAuthCustomizerSetting(\WP_REST_Request $request)
    {
        $settings = (array)$request->get_param('settings');
        $settings = Helper::formatAuthCustomizerSettings($settings);
        update_option('__fls_auth_customizer_settings', $settings, false);

        return [
            'message'  => __('Settings have been updated', 'fluent-security'),
            'settings' => $settings
        ];
    }

    public static function uploadImage(\WP_REST_Request $request)
    {
        $file = isset($_FILES['file']) ? $_FILES['file'] : null;

        if (empty($file) || !is_array($file) || empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            return new \WP_Error('invalid_file', __('Invalid file', 'fluent-security'));
        }

        // wp_check_filetype_and_ext() will look at both the file extension and the file's actual contents.
        $checked = wp_check_filetype_and_ext(
            $file['tmp_name'],
            $file['name'],
            null // we’ll supply our own list of allowed types below
        );
        $type = $checked['type'];


        $allowed_mimes = [
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png'          => 'image/png',
            'gif'          => 'image/gif',
            'webp'         => 'image/webp',
            'bmp'          => 'image/bmp',
        ];

        if (!in_array($type, $allowed_mimes, true)) {
            return new \WP_Error(
                'invalid_file_type',
                __('Sorry, you can only upload JPG, PNG, GIF, WebP or BMP files.', 'fluent-security')
            );
        }

        if (!function_exists('wp_handle_upload')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $upload_overrides = [
            'test_form' => false,
            // Pass the allowed list here so WP also enforces it
            'mimes'     => $allowed_mimes,
        ];
        $movefile = wp_handle_upload($file, $upload_overrides);

        if (isset($movefile['error'])) {
            return new \WP_Error('upload_error', $movefile['error']);
        }

        return [
            'media' => $movefile,
        ];
    }


    public static function saveChildSite(\WP_REST_Request $request)
    {
        if (!(new ServerModeHandler())->isEnabled()) {
            return new \WP_Error('invalid_request', __('This feature is only available in the server mode.', 'fluent-security'));
        }
        $willRemove = $request->get_param('will_remove');
        if ($willRemove == 'yes') {
            $url = $request->get_param('site_url');

            $prevSettings = get_option('__fls_child_sites', []);

            $prevSettings = array_filter($prevSettings, function ($site) use ($url) {
                return $site['site_url'] !== $url;
            });

            update_option('__fls_child_sites', $prevSettings, false);

            return [
                'message' => __('Site has been removed successfully', 'fluent-security')
            ];
        }

        $siteConfig = trim($request->get_param('site_config'));

        if (empty($siteConfig)) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'));
        }

        $siteConfig = json_decode($siteConfig, true);

        if (empty($siteConfig['site_url']) || empty($siteConfig['callback_url'])) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'));
        }

        // validate the urls
        if (!filter_var($siteConfig['site_url'], FILTER_VALIDATE_URL)) {
            return new \WP_Error('invalid_request', __('Invalid site URL', 'fluent-security'));
        }
        if (!filter_var($siteConfig['callback_url'], FILTER_VALIDATE_URL)) {
            return new \WP_Error('invalid_request', __('Invalid callback URL', 'fluent-security'));
        }

        $fomattedData = [
            'site_url'     => sanitize_url($siteConfig['site_url']),
            'callback_url' => sanitize_url($siteConfig['callback_url']),
            'title'        => sanitize_text_field($siteConfig['site_title']),
            'status'       => 'yes'
        ];

        if (empty($fomattedData['title'])) {
            $fomattedData['title'] = parse_url($fomattedData['site_url'], PHP_URL_HOST);
        }

        $previousSites = get_option('__fls_child_sites', []);

        $siteId = strtolower(wp_generate_password(4, false));

        while (isset($previousSites[$siteId])) {
            $siteId = strtolower(wp_generate_password(4, false));
        }

        $fomattedData['site_id'] = $siteId;

        // check if the site already exists
        $existingSite = array_filter($previousSites, function ($site) use ($fomattedData) {
            return $site['site_url'] === $fomattedData['site_url'];
        });

        if (!empty($existingSite)) {
            return new \WP_Error('invalid_request', __('This site already exists.', 'fluent-security'));
        }

        $fomattedData['secret_key'] = wp_generate_password(32, false);
        $previousSites[$fomattedData['site_id']] = $fomattedData;

        update_option('__fls_child_sites', $previousSites, false);

        $serverConfig = json_encode([
            'server_token' => $fomattedData['secret_key'],
            'callback'     => rest_url('fluent-auth/child-sites/validate-token'),
            'server_url'   => site_url(),
            'site_id'      => $fomattedData['site_id']
        ], JSON_UNESCAPED_SLASHES);

        return [
            'message'      => __('Site has been added successfully', 'fluent-security'),
            'server_token' => $serverConfig
        ];
    }

    public static function getChildSites(\WP_REST_Request $request)
    {

        if (!(new ServerModeHandler())->isEnabled()) {
            return new \WP_Error('invalid_request', __('This feature is only available in the server mode.', 'fluent-security'));
        }

        $sites = get_option('__fls_child_sites', []);

        $formattedSites = [];
        foreach ($sites as $site) {
            $formattedSites[] = [
                'title'   => $site['title'],
                'url'     => $site['site_url'],
                'site_id' => $site['site_id'],
            ];
        }

        return [
            'sites' => $formattedSites,
        ];
    }

    public static function validateChildSiteToken(\WP_REST_Request $request)
    {

        $data = [
            'user_token'   => $request->get_param('user_token'),
            'server_token' => $request->get_param('server_token'),
            'site_id'      => $request->get_param('site_id'),
        ];

        if (!is_string($data['user_token']) || !is_string($data['server_token']) || !is_string($data['site_id'])) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'), ['status' => 400]);
        }

        if (empty($data['user_token']) || empty($data['server_token']) || empty($data['site_id'])) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'), ['status' => 400]);
        }

        $sites = get_option('__fls_child_sites', []);

        /*
         * Indexed directly rather than through Arr::get(), which reads a dot in the key as
         * a step down into the array. The id arrives from the network on the one route here
         * that answers without a signed-in user, and a dotted one walked into a child site's
         * own record - reaching a string where an array was expected, and taking the
         * secret_key comparison below with it.
         */
        $site = isset($sites[$data['site_id']]) && is_array($sites[$data['site_id']])
            ? $sites[$data['site_id']]
            : null;

        if (empty($site) || empty($site['secret_key'])) {
            return new \WP_Error('invalid_request', __('Invalid Site ID', 'fluent-security'), ['status' => 403]);
        }

        if (!hash_equals($site['secret_key'], $data['server_token'])) {
            return new \WP_Error('invalid_request', __('Invalid server token', 'fluent-security'), ['status' => 403]);
        }

        $userToken = explode('___', $data['user_token']);

        $userId = Arr::get($userToken, '1', null);

        if (!$userId) {
            return new \WP_Error('invalid_request', __('Invalid user token', 'fluent-security'), ['status' => 403]);
        }

        $user = get_user_by('ID', $userId);
        $userMeta = get_user_meta($userId, '__flsc_temp_token', true);

        if (empty($user) || empty($userMeta) || !hash_equals($userMeta, $data['user_token'])) {
            return new \WP_Error('invalid_request', __('Invalid user token', 'fluent-security'), ['status' => 403]);
        }

        /*
         * And it has to be recent. A token is spent when it is redeemed, so one that never
         * was - a redirect somebody closed, a callback that failed - used to stay valid for
         * ever, waiting in user meta. The hop it authorises takes seconds, so a few minutes
         * is all the life it needs.
         *
         * A token with no timestamp is refused rather than trusted. The only ones are those
         * minted before this was recorded, which is exactly the set that has been sitting
         * there unspent; the cost of refusing is that somebody follows the link again and
         * gets a fresh one.
         */
        $issuedAt = (int)get_user_meta($userId, '__flsc_temp_token_at', true);
        $window = (int)apply_filters('fluent_auth/child_site_token_ttl', 5 * MINUTE_IN_SECONDS);

        if (!$issuedAt || (time() - $issuedAt) > $window) {
            delete_user_meta($userId, '__flsc_temp_token');
            delete_user_meta($userId, '__flsc_temp_token_at');

            return new \WP_Error('invalid_request', __('That sign-in link has expired. Please try again.', 'fluent-security'), ['status' => 403]);
        }

        update_user_meta($userId, '__flsc_temp_token', '');
        delete_user_meta($userId, '__flsc_temp_token_at');

        // now we will prepare the data for the user
        $data = apply_filters('fluent_auth/remote_auth_response_data', [
            'remote_user_id'  => $user->ID,
            'user_login'      => $user->user_login,
            'user_email'      => $user->user_email,
            'user_nicename'   => $user->user_nicename,
            'user_url'        => $user->user_url,
            'nickname'        => $user->nickname,
            'locale'          => $user->locale,
            'display_name'    => $user->display_name,
            'user_registered' => $user->user_registered,
            'roles'           => array_values($user->roles),
            'first_name'      => $user->first_name,
            'last_name'       => $user->last_name,
            'description'     => $user->description,
        ], $user, $site);

        return [
            'user_data' => $data,
        ];
    }

    public static function installPlugin(\WP_REST_Request $request)
    {
        $plugin = $request->get_param('plugin');

        if (!$plugin) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'));
        }

        if (!current_user_can('install_plugins')) {
            return new \WP_Error('permission_denied', __('You do not have permission to install plugins', 'fluent-security'), 403);
        }

        if (defined('FLUENTMAIL_PLUGIN_FILE')) {
            return new \WP_Error('already_installed', __('FluentSMTP is already installed as part of Fluent Mail plugin.', 'fluent-security'));
        }

        $plugin_id = 'fluent-smtp';
        $plugin = [
            'name'      => 'FluentSMTP',
            'repo-slug' => 'fluent-smtp',
            'file'      => 'fluent-smtp.php',
        ];

        self::backgroundInstaller($plugin, $plugin_id);

        if (!defined('FLUENTMAIL_PLUGIN_FILE')) {
            return new \WP_Error('installation_failed', __('Plugin installation failed. Please try again.', 'fluent-security'));
        }

        return [
            'message'      => __('FluentSMTP has been installed successfully', 'fluent-security'),
            'settings_url' => admin_url('options-general.php?page=fluent-mail#/'),
        ];
    }


    private static function backgroundInstaller($plugin_to_install, $plugin_id)
    {
        if (!empty($plugin_to_install['repo-slug'])) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
            require_once ABSPATH . 'wp-admin/includes/plugin.php';

            WP_Filesystem();

            $skin = new \Automatic_Upgrader_Skin();
            $upgrader = new \WP_Upgrader($skin);
            $installed_plugins = array_reduce(array_keys(\get_plugins()), array(self::class, 'associate_plugin_file'), array());
            $plugin_slug = $plugin_to_install['repo-slug'];
            $plugin_file = isset($plugin_to_install['file']) ? $plugin_to_install['file'] : $plugin_slug . '.php';
            $installed = false;
            $activate = false;

            // See if the plugin is installed already.
            if (isset($installed_plugins[$plugin_file])) {
                $installed = true;
                $activate = !is_plugin_active($installed_plugins[$plugin_file]);
            }

            // Install this thing!
            if (!$installed) {
                // Suppress feedback.
                ob_start();

                try {
                    $plugin_information = plugins_api(
                        'plugin_information',
                        array(
                            'slug'   => $plugin_slug,
                            'fields' => array(
                                'short_description' => false,
                                'sections'          => false,
                                'requires'          => false,
                                'rating'            => false,
                                'ratings'           => false,
                                'downloaded'        => false,
                                'last_updated'      => false,
                                'added'             => false,
                                'tags'              => false,
                                'homepage'          => false,
                                'donate_link'       => false,
                                'author_profile'    => false,
                                'author'            => false,
                            ),
                        )
                    );

                    if (is_wp_error($plugin_information)) {
                        throw new \Exception($plugin_information->get_error_message());
                    }

                    if (!is_object($plugin_information) || empty($plugin_information->download_link)) {
                        throw new \Exception(__('Could not retrieve plugin download link.', 'fluent-security'));
                    }

                    $package = $plugin_information->download_link;
                    $download = $upgrader->download_package($package);

                    if (is_wp_error($download)) {
                        throw new \Exception($download->get_error_message());
                    }

                    $working_dir = $upgrader->unpack_package($download, true);

                    if (is_wp_error($working_dir)) {
                        throw new \Exception($working_dir->get_error_message());
                    }

                    $result = $upgrader->install_package(
                        array(
                            'source'                      => $working_dir,
                            'destination'                 => WP_PLUGIN_DIR,
                            'clear_destination'           => false,
                            'abort_if_destination_exists' => false,
                            'clear_working'               => true,
                            'hook_extra'                  => array(
                                'type'   => 'plugin',
                                'action' => 'install',
                            ),
                        )
                    );

                    if (is_wp_error($result)) {
                        throw new \Exception($result->get_error_message());
                    }

                    $activate = true;

                } catch (\Exception $e) {
                }

                // Discard feedback.
                ob_end_clean();
            }

            wp_clean_plugins_cache();

            // Activate this thing.
            if ($activate) {
                try {
                    $result = activate_plugin($installed ? $installed_plugins[$plugin_file] : $plugin_slug . '/' . $plugin_file);

                    if (is_wp_error($result)) {
                        throw new \Exception($result->get_error_message());
                    }
                } catch (\Exception $e) {
                }
            }
        }
    }

    private static function associate_plugin_file($plugins, $key)
    {
        $path = explode('/', $key);
        $filename = end($path);
        $plugins[$filename] = $key;
        return $plugins;
    }
}
