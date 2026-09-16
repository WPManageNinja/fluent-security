<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;
use FluentAuth\App\Services\SystemEmailService;

class BasicTasksHandler
{
    public function register()
    {
        // Maybe Remove Application Password Login
        add_filter('wp_is_application_passwords_available', [$this, 'maybeDisableAppPassword']);

        // Disable xmlrpc
        add_filter('xmlrpc_enabled', [$this, 'maybeDisableXmlRpc']);
        add_filter('xmlrpc_methods', [$this, 'maybeRemovePingbackMethods']);
        add_filter('wp_headers', [$this, 'maybeRemovePingbackHeader']);

        // Maybe disable List Users REST
        add_filter('rest_user_query', [$this, 'maybeInterceptRestUserQuery']);
        add_filter('rest_prepare_user', [$this, 'maybeInterceptRestUserResponse'], 10, 3);

        /*
         * The same switch, applied to the other places core hands out usernames. Hiding
         * the REST list while /?author=1 still redirects to /author/admin/ hides nothing.
         * Before redirect_canonical (10), which is what performs that redirect.
         */
        add_action('template_redirect', [$this, 'maybeBlockAuthorIdLookup'], 0);
        add_filter('wp_sitemaps_add_provider', [$this, 'maybeHideUserSitemap'], 10, 2);
        add_action('template_redirect', [$this, 'maybeNotFoundUserSitemap'], 0);

        add_action('admin_notices', [$this, 'maybeAddAdminNotice']);

        /*
         * Clean Up Old Logs
         */
        add_action('fluent_auth_daily_tasks', function () {
            $this->maybeSendDigestEMail();
            \FluentAuth\App\Helpers\Helper::cleanUpLogs();

            /*
             * Ask the web server whether the uploads folder runs PHP, out here where nobody is
             * waiting. The check caches its answer, so warming it on the schedule means the
             * security screen almost always reads a stored result rather than paying for an
             * HTTP request while somebody watches the page load.
             */
            (new \FluentAuth\App\Services\Checks\Files\UploadsExecutionCheck())->refresh();
        });

        /*
         * The rest of a password reset run. A site with thousands of users cannot be mailed
         * inside the request that started it, so the queue reschedules itself until it is
         * empty - see RecoveryService::processQueue().
         */
        add_action('fluent_auth_recovery_resets', function () {
            \FluentAuth\App\Services\Recovery\RecoveryService::processQueue();
        });

        /*
         * Maybe Disable Admin Bar
         */
        add_filter('show_admin_bar', function ($status) {
            if (!$status) {
                return $status;
            }

            if (is_admin()) {
                return $status;
            }

            if (Helper::getSetting('disable_admin_bar') !== 'yes') {
                return $status;
            }

            $roles = Helper::getSetting('disable_bar_roles');

            $user = get_user_by('ID', get_current_user_id());

            if (!$user || !$roles) {
                return $status;
            }

            if (array_intersect($roles, array_values($user->roles)) && !current_user_can('publish_posts')) {
                return false;
            }

            return $status;
        });

        /*
        * Maybe Redirect Non-Admin Users
        */
        add_action('admin_init', function () {

            if (Helper::getSetting('disable_admin_bar') !== 'yes' || wp_doing_ajax()) {
                return;
            }

            $roles = Helper::getSetting('disable_bar_roles');

            $user = get_user_by('ID', get_current_user_id());

            if (!$user || !$roles) {
                return;
            }

            if (array_intersect($roles, array_values($user->roles)) && !current_user_can('publish_posts')) {
                wp_safe_redirect(home_url()); // Replace this with the URL to redirect to.
                exit;
            }

        }, 999);

        // Maybe send scan report
        add_action('fluent_auth_hourly_tasks', function () {
            $settings = IntegrityHelper::getSettings();
            if ($settings['auto_scan'] != 'yes' || $settings['status'] != 'active') {
                return;
            }
            IntegrityHelper::maybeSendScanReport();
        });

    }

    public function maybeDisableAppPassword($status)
    {
        if (!$status || Helper::getSetting('disable_app_login') === 'yes') {
            return false;
        }
        return $status;
    }

    public function maybeDisableXmlRpc($status)
    {
        if (!$status || Helper::getSetting('disable_xmlrpc') === 'yes') {
            return false;
        }

        return $status;
    }

    /**
     * Core's `xmlrpc_enabled` only refuses the methods that log in. Pingbacks never log
     * in, so with the switch off xmlrpc.php still answered `pingback.ping` for anyone -
     * the method behind most of the reflected traffic that makes people want XML-RPC
     * off in the first place. Only the pingback methods go: anything else registered
     * here, Jetpack's included, authenticates its own way and is left alone.
     *
     * @param $methods array
     * @return array
     */
    public function maybeRemovePingbackMethods($methods)
    {
        if (Helper::getSetting('disable_xmlrpc') !== 'yes') {
            return $methods;
        }

        unset($methods['pingback.ping'], $methods['pingback.extensions.getPingbacks']);

        return $methods;
    }

    /**
     * Stops advertising an endpoint that no longer answers.
     *
     * @param $headers array
     * @return array
     */
    public function maybeRemovePingbackHeader($headers)
    {
        if (Helper::getSetting('disable_xmlrpc') === 'yes') {
            unset($headers['X-Pingback']);
        }

        return $headers;
    }

    public function maybeInterceptRestUserQuery($query)
    {
        if ($this->hidesUsers()) {
            $query['login'] = 'someRandomStringForThis_' . time();
        }

        return $query;
    }

    public function maybeInterceptRestUserResponse($response, $user, $request)
    {
        // Everyone may read their own record; the block editor asks for it on every load.
        if (!empty($request['id']) && (int)$request['id'] === get_current_user_id()) {
            return $response;
        }

        if (!empty($request['id']) && $this->hidesUsers()) {
            return new \WP_Error(
                'permission_error',
                __('You do not have access to list users. Restriction added from fluent auth plugin', 'fluent-security'),
                // Without a status the REST server reports a refusal as a 500.
                ['status' => rest_authorization_required_code()]
            );
        }
        return $response;
    }

    /**
     * Whether usernames are to be kept from whoever is asking.
     *
     * One answer for every place the switch applies. Anyone who may manage users, or who
     * edits other people's posts and so needs to see who wrote them - the block editor's
     * author picker is the usual reason - is shown the list; everybody else is not.
     *
     * @return bool
     */
    private function hidesUsers()
    {
        if (Helper::getSetting('disable_users_rest') !== 'yes') {
            return false;
        }

        return !current_user_can('list_users') && !current_user_can('edit_others_posts');
    }

    /**
     * Refuses to turn a numeric author id into an author archive.
     *
     * Walking /?author=1, 2, 3 and reading the slug each one redirects to is the oldest
     * username harvest there is. With pretty permalinks on, nothing legitimate links that
     * way - core itself writes /author/name/ - so the query form can only be a probe. With
     * plain permalinks it is the real link to every author archive and has to be left alone.
     *
     * @return void
     */
    public function maybeBlockAuthorIdLookup()
    {
        if (!isset($_GET['author']) || is_array($_GET['author'])) {
            return;
        }

        /*
         * Normalised the way WP_Query normalises it - everything but digits stripped -
         * rather than tested for being all digits. Core accepts "1%0A" as author 1 and
         * redirect_canonical() follows it to the slug, so a stricter test here than
         * core's own is a hole, not a safeguard.
         */
        $authorId = preg_replace('/[^0-9]/', '', (string)wp_unslash($_GET['author']));

        if ($authorId === '') {
            return;
        }

        if (!get_option('permalink_structure') || !$this->hidesUsers()) {
            return;
        }

        wp_safe_redirect(home_url('/'));
        exit();
    }

    /**
     * Drops the users sitemap, which lists every author archive by slug.
     *
     * @param $provider \WP_Sitemaps_Provider
     * @param $name string
     * @return \WP_Sitemaps_Provider|false
     */
    public function maybeHideUserSitemap($provider, $name)
    {
        if ($name === 'users' && $this->hidesUsers()) {
            return false;
        }

        return $provider;
    }

    /**
     * Answers the users sitemap URL with a 404 once its provider is gone.
     *
     * Core leaves the rewrite in place and, finding no provider behind it, simply carries
     * on - which renders the home page at /wp-sitemap-users-1.xml. Nothing leaks, but a
     * URL that used to be a sitemap should say it is gone rather than serve a copy of the
     * front page.
     *
     * @return void
     */
    public function maybeNotFoundUserSitemap()
    {
        if (get_query_var('sitemap') !== 'users' || !$this->hidesUsers()) {
            return;
        }

        global $wp_query;

        $wp_query->set_404();
        status_header(404);
        nocache_headers();
    }

    public function maybeAddAdminNotice()
    {
        if (get_option('__fls_auth_settings') || !current_user_can('manage_options')) {
            return '';
        }

        $url = admin_url('admin.php?page=fluent-auth#/settings');

        ?>
        <div style="padding-bottom: 10px;" class="notice notice-warning">
            <?php /* translators: %s: Plugin Name  */ ?>
            <p><?php echo wp_kses_post(\sprintf(__('Thank you for installing %s Plugin. Please configure the security settings to enable enhanced security of your site', 'fluent-security'), '<b>FluentAuth</b>')); ?></p>
            <a href="<?php echo esc_url($url); ?>"><?php esc_html_e('Configure Fluent Auth', 'fluent-security'); ?></a>
        </div>
        <?php
    }

    /**
     * Today, in the site's timezone. wp_date() is the only primitive that honours it
     * regardless of what PHP's default zone has been set to; date() on a shifted
     * timestamp is right only while that default is still UTC.
     *
     * @param $format string
     * @return string
     */
    private function siteDate($format)
    {
        if (function_exists('wp_date')) {
            return (string)wp_date($format);
        }

        return date($format, current_time('timestamp'));
    }

    public function maybeSendDigestEMail()
    {
        $frequency = Helper::getSetting('digest_summary');
        $adminEmail = Helper::getSetting('notification_email');

        if (!$frequency || !$adminEmail) {
            return false;
        }

        $adminEmail = str_replace('{admin_email}', get_bloginfo('admin_email'), $adminEmail);
        if (!$adminEmail) {
            return false;
        }

        /*
         * The screen offers a day of the week, stored as 'sun' .. 'sat'. 'weekly' is
         * what it stored before those existed and has always meant Monday. Everything
         * is judged in the site's timezone: whether it is the first of the month or a
         * Monday is a question about the site's day, not the server's.
         */
        $weekdays = [
            'sun' => 'Sun', 'mon' => 'Mon', 'tue' => 'Tue', 'wed' => 'Wed',
            'thu' => 'Thu', 'fri' => 'Fri', 'sat' => 'Sat'
        ];

        if ($frequency === 'weekly') {
            $frequency = 'mon';
        }

        if ($frequency === 'daily') {
            $cutOut = 23 * HOUR_IN_SECONDS;
            $period = 'daily';
        } elseif ($frequency === 'monthly') {
            if ($this->siteDate('d') !== '01') {
                return false;
            }
            $cutOut = 27 * DAY_IN_SECONDS;
            $period = 'monthly';
        } elseif (isset($weekdays[$frequency])) {
            if ($this->siteDate('D') !== $weekdays[$frequency]) {
                return false;
            }
            $cutOut = 6 * DAY_IN_SECONDS;
            $period = 'weekly';
        } else {
            return false;
        }

        $lastSent = get_option('_fls_last_digest_sent', 0);

        if ($lastSent && (current_time('timestamp') - strtotime($lastSent)) < $cutOut) {
            return false;
        }

        if (!$lastSent) {
            $lastSent = date('Y-m-d H:i:s', current_time('timestamp') - $cutOut);
        }

        $counts = flsDb()->table('fls_auth_logs')
            ->select(['status', flsDb()->raw('count(*) as total')])
            ->where('created_at', '>=', $lastSent)
            ->groupBy('status')
            ->get();

        $items = [
            'success' => [
                'count' => 0,
                'title' => __('Successful Logins', 'fluent-security')
            ],
            'failed'  => [
                'count' => 0,
                'title' => __('Failed Logins', 'fluent-security')
            ],
            'blocked' => [
                'count' => 0,
                'title' => __('Blocked Logins', 'fluent-security')
            ]
        ];

        foreach ($counts as $countItem) {
            if (isset($items[$countItem->status])) {
                $items[$countItem->status]['count'] = $countItem->total;
            }
        }

        if (Helper::getSetting('magic_login') === 'yes') {
            $items['magic_login'] = [
                'title' => __('Login via URL', 'fluent-security'),
                'count' => flsDb()->table('fls_login_hashes')
                    ->where('status', 'used')
                    ->where('use_type', 'magic_login')
                    ->where('created_at', '>=', $lastSent)
                    ->count()
            ];
        }

        $validItems = [];
        foreach ($items as $item) {
            if ($item['count']) {
                $validItems[] = $item;
            }
        }

        if (!$validItems) {
            return false;
        }

        $infoHtml = '<ul style="padding-left:20px;line-height:25px;font-size: 14px;background: #f9f9f9;padding-top: 20px;padding-bottom: 20px;font-family: monospace;">';
        foreach ($validItems as $item) {
            $infoHtml .= '<li><b>' . $item['title'] . ':</b> ' . $item['count'] . '</li>';
        }
        $infoHtml .= '</ul>';

        $lines = [
            sprintf('<p style="font-size: 16px; line-height: 25px;">Hello there, <br />Here is the %1$s digest report of your site\'s (%2$s) login activity.</p>', $period, site_url()),
            $infoHtml
        ];

        $data = [
            'body'        => implode('', $lines),
            'pre_header'  => sprintf('Auth Report for %s', get_bloginfo('name')),
            'show_footer' => true
        ];

        $body = Helper::loadView('notification', $data);
        $subject = sprintf('%1$s report for %2$s - %3$s', ucfirst($period), get_bloginfo('name'), date('d, M Y', current_time('timestamp')));

        $headers = SystemEmailService::getEmailHeaders();

        \wp_mail($adminEmail, $subject, $body, $headers);

        update_option('_fls_last_digest_sent', current_time('mysql'), false);
    }

}
