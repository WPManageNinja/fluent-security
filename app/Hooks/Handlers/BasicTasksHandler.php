<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

class BasicTasksHandler
{
    public function register()
    {
        // Maybe Remove Application Password Login
        add_filter('wp_is_application_passwords_available', [$this, 'maybeDisableAppPassword']);

        // Disable xmlrpc
        add_filter('xmlrpc_enabled', [$this, 'maybeDisableXmlRpc']);

        // Maybe disable List Users REST
        add_filter('rest_user_query', [$this, 'maybeInterceptRestUserQuery']);

        // Maybe disable List Users REST
        add_filter('rest_user_query', [$this, 'maybeInterceptRestUserQuery']);
        add_filter('rest_prepare_user', [$this, 'maybeInterceptRestUserResponse'], 10, 3);

        add_action('admin_notices', [$this, 'maybeAddAdminNotice']);

        /*
         * Clean Up Old Logs
         */
        add_action('fluent_auth_daily_tasks', function () {
            $this->maybeSendDigestEMail();
            \FluentAuth\App\Helpers\Helper::cleanUpLogs();
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

    public function maybeInterceptRestUserQuery($query)
    {
        if (Helper::getSetting('disable_users_rest') === 'yes' && !current_user_can('edit_others_posts')) {
            $query['login'] = 'someRandomStringForThis_' . time();
        }

        return $query;
    }

    public function maybeInterceptRestUserResponse($response, $user, $request)
    {
        if (!empty($request['id']) && Helper::getSetting('disable_users_rest') === 'yes' && !current_user_can('edit_others_posts')) {
            return new \WP_Error('permission_error', __('You do not have access to list users. Restriction added from fluent auth plugin', 'fluent-security'));
        }
        return $response;
    }

    public function maybeAddAdminNotice()
    {
        if (get_option('__fls_auth_settings') || !current_user_can('manage_options')) {
            return '';
        }

        $url = admin_url('options-general.php?page=fluent-auth#/settings');

        ?>
        <div style="padding-bottom: 10px;" class="notice notice-warning">
            <p><?php echo sprintf(__('Thank you for installing %s Plugin. Please configure the security settings to enable enhanced security of your site', 'fluent-security'), '<b>FluentAuth</b>'); ?></p>
            <a href="<?php echo esc_url($url); ?>"><?php _e('Configure Fluent Auth', 'fluent-security'); ?></a>
        </div>
        <?php
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

        if ($frequency == 'monthly' && date('d') != '01') {
            return false;
        }

        if ($frequency == 'weekly' && date('D') != 'Mon') {
            return false;
        }

        $cutOuts = [
            'daily'   => 23 * HOUR_IN_SECONDS,
            'weekly'  => 6 * DAY_IN_SECONDS,
            'monthly' => 27 * DAY_IN_SECONDS
        ];

        $cutOut = (isset($cutOuts[$frequency])) ? $cutOuts[$frequency] : 0;

        if (!$cutOut) {
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

        $period = $frequency;

        if (!in_array($frequency, ['monthly', 'weekly'])) {
            $period = 'daily';
        }

        $infoHtml = '<ul style="padding-left:20px;line-height:25px;font-size: 14px;background: #f9f9f9;padding-top: 20px;padding-bottom: 20px;font-family: monospace;">';
        foreach ($validItems as $item) {
            $infoHtml .= '<li><b>' . $item['title'] . ':</b> ' . $item['count'] . '</li>';
        }
        $infoHtml .= '</ul>';

        $lines = [
            sprintf('<p style="font-size: 16px; line-height: 25px;">Hello there, <br />Here is the %1s digest report of your site\'s (%2s) login activity.</p>', $period, site_url()),
            $infoHtml
        ];

        $data = [
            'body'        => implode('', $lines),
            'pre_header'  => sprintf('Auth Report for %s', get_bloginfo('name')),
            'show_footer' => true
        ];

        $body = Helper::loadView('notification', $data);
        $subject = sprintf('%1s report for %2s - %3s', ucfirst($period), get_bloginfo('name'), date('d, M Y', current_time('timestamp')));

        $headers = array('Content-Type: text/html; charset=UTF-8');

        \wp_mail($adminEmail, $subject, $body, $headers);

        update_option('_fls_last_digest_sent', current_time('mysql'), false);
    }

}
