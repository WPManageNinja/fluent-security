<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class LoginSecurityHandler
{
    private $failedLogged = false;

    public function register()
    {
        add_filter('authenticate', [$this, 'maybeCheckLoginAttempts'], 999, 3);
        add_filter('lostpassword_errors', [$this, 'maybeBlockPasswordReset'], 10, 2);
        add_action('wp_login_failed', [$this, 'logFailedAuth'], 10, 2);
        add_action('wp_login', [$this, 'logAuthSuccess'], 10, 2);
    }

    /**
     * @param $user \WP_User | \WP_Error
     * @param $username
     * @param $password
     * @return bool|mixed|\WP_Error|\WP_User
     */
    public function maybeCheckLoginAttempts($user, $username, $password)
    {
        if (empty($_POST) && !$username) {
            return $user;
        }

        $isLimitExceeded = $this->checkLoginAttempt($user, $username);

        if (is_wp_error($isLimitExceeded)) {
            $this->logBlockedAuth($user, $username);
            return $isLimitExceeded;
        }

        if (is_wp_error($user)) {
            $errorCode = $user->get_error_code();
            if ($errorCode == 'invalid_username' || $errorCode == 'incorrect_password') {
                return new \WP_Error(
                    $errorCode,
                    __('<strong>Error</strong>: The username or the password is invalid. Please try different combination.', 'fluent-security')
                );
            }
            return $user;
        }

        do_action('fluent_auth/login_attempts_checked', $user);

        return $user;
    }

    /**
     * @param $errors \WP_Error
     * @param $userData \WP_User || false
     * @return mixed|\WP_Error
     */
    public function maybeBlockPasswordReset($errors, $userData)
    {
        $minutes = Helper::getSetting('login_try_timing');
        $limit = Helper::getSetting('login_try_limit');

        if (!$minutes || !$limit) {
            return $errors;
        }

        global $wpdb;
        $ip = Helper::getIp();
        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);

        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` IN ('failed','blocked', 'password_reset')", $ip, $dateTime));

        if (!$count || $limit >= $count) {

            $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

            $userAgent = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);

            // Just log here
            flsDb()->table('fls_auth_logs')
                ->insert([
                    'username'   => ($userData) ? $userData->user_login : '',
                    'user_id'    => ($userData) ? $userData->ID : '',
                    'agent'      => $userAgent,
                    'ip'         => Helper::getIp(),
                    'browser'    => $browserDetection->getBrowser($userAgent)['browser_name'],
                    'device_os'  => $browserDetection->getOS($userAgent)['os_family'],
                    'status'     => 'password_reset',
                    'media'      => 'web',
                    'created_at' => current_time('mysql'),
                    'updated_at' => current_time('mysql'),
                ]);

            return $errors;
        }

        return new \WP_Error('blocked', sprintf(__('You are blocked for next %d minutes. Please try after that time'), $minutes));
    }

    /**
     * @param $username string
     * @param $error \WP_Error
     * @return void
     */
    public function logFailedAuth($username, $error)
    {
        if ($this->failedLogged || !Helper::getSetting('enable_auth_logs')) {
            return;
        }

        global $wpdb;

        $byField = 'login';
        if (is_email($username)) {
            $byField = 'email';
        }

        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $user = get_user_by($byField, $username);

        $userAgent = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);

        $data = [
            'username'    => $username,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql'),
            'agent'       => sanitize_text_field($userAgent),
            'ip'          => Helper::getIp(),
            'error_code'  => $error->get_error_code(),
            'description' => $error->get_error_message(),
            'browser'     => $browserDetection->getBrowser($userAgent)['browser_name'],
            'device_os'   => $browserDetection->getOS($userAgent)['os_family'],
            'status'      => 'failed',
            'count'       => 1
        ];

        if ($user) {
            $data['user_id'] = $user->ID;
        }

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);

        $this->failedLogged = true;
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    public function logAuthSuccess($userName, $user)
    {
        if (!Helper::getSetting('enable_auth_logs')) {
            return;
        }

        $media = Helper::getLoginMedia();

        global $wpdb;

        // Check if HTTP_USER_AGENT exists before accessing it
        $agent = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : 'Unknown User Agent';

        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $data = [
            'username'    => $user->user_login,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql'),
            'agent'       => sanitize_text_field($agent),
            'ip'          => Helper::getIp(),
            'browser'     => $browserDetection->getBrowser($agent)['browser_name'],
            'device_os'   => $browserDetection->getOS($agent)['os_family'],
            'description' => '',
            'media'       => $media,
            'status'      => 'success',
            'user_id'     => $user->ID
        ];

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);

        do_action('fluent_auth/user_login_success', $user);

        $this->maybeSendSuccessEmail($user, $media);
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    private function logBlockedAuth($user, $username)
    {
        global $wpdb;

        $ipAddress = Helper::getIp();

        // get previous blocked row for this user in the last 1 hour
        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - 60 * 60);
        $prev = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` = 'blocked' LIMIT 1", $ipAddress, $dateTime));

        if ($prev) {
            $wpdb->update($wpdb->prefix . 'fls_auth_logs', [
                'updated_at' => current_time('mysql'),
                'count'      => $prev->count + 1
            ], [
                'id' => $prev->id
            ]);
            $this->failedLogged = true;
            return;
        }

        $agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();
        $browserData = $browserDetection->getBrowser($agent);

        $data = [
            'username'    => $username,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql'),
            'agent'       => sanitize_text_field($agent),
            'ip'          => $ipAddress,
            'error_code'  => 'blocked',
            'browser'     => Arr::get($browserData, 'browser_name'),
            'device_os'   => Arr::get($browserData, 'os_family'),
            'description' => 'Blocked by Fluent Auth',
            'status'      => 'blocked',
            'count'       => 1
        ];

        if (!is_wp_error($user)) {
            $data['user_id'] = $user->ID;
        }

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);

        $this->failedLogged = true;

        $this->maybeSendBlockedEmail($user, $username);
    }

    private function checkLoginAttempt($user, $userName)
    {
        $minutes = Helper::getSetting('login_try_timing');
        $limit = Helper::getSetting('login_try_limit');

        if (!$minutes || !$limit) {
            return true;
        }

        global $wpdb;
        $ip = Helper::getIp();
        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);

        // check if already blocked then no need to create a new row
        $blocked = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` = 'blocked' LIMIT 1", $ip, $dateTime));

        if ($blocked) {
            $wpdb->update($wpdb->prefix . 'fls_auth_logs', [
                'created_at' => current_time('mysql'),
                'count'      => $blocked->count + 1
            ], [
                'id' => $blocked->id
            ]);
        } else {
            $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` IN ('failed','blocked')", $ip, $dateTime));

            if (!$count || $limit >= $count) {
                return true;
            }
        }

        return new \WP_Error('login_error', sprintf(__('You are trying too much. Please try after %d minutes', 'fluent-security'), $minutes));
    }

    /**
     * @param $user \WP_User
     * @return bool
     */
    private function maybeSendSuccessEmail($user, $media = '')
    {
        $notificationUserRoles = Helper::getSetting('notification_user_roles');
        if (!$notificationUserRoles || !array_intersect($notificationUserRoles, (array)$user->roles)) {
            return false;
        }

        $adminEmail = Helper::getSetting('notification_email');
        if (!$adminEmail) {
            return false;
        }

        $adminEmail = str_replace('{admin_email}', get_bloginfo('admin_email'), $adminEmail);
        if (!$adminEmail) {
            return false;
        }

        $userEditLInk = add_query_arg('user_id', $user->ID, self_admin_url('user-edit.php'));

        $agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $userRoles = (array)$user->roles;

        $roleNames = implode(', ', $userRoles);

        $ip = Helper::getIp();
        $infoHtml = '<ul style="padding-left:20px;line-height:25px;font-size: 14px;background: #f9f9f9;padding-top: 20px;padding-bottom: 20px;font-family: monospace;">';
        $infoHtml .= '<li><b>Site URL:</b> <a href="' . site_url() . '">' . site_url() . '</a></li>';
        $infoHtml .= '<li><b>Username:</b> <a href="' . $userEditLInk . '">' . $user->user_login . '</a></li>';
        $infoHtml .= '<li><b>User Role:</b> ' . $roleNames . '</li>';
        if ($media && $media != 'web') {
            $infoHtml .= '<li><b>Media:</b> ' . $media . '</li>';
        }
        $infoHtml .= '<li><b>Email:</b> ' . $user->user_email . '</li>';
        $infoHtml .= '<li><b>Name:</b> ' . $user->first_name . ' ' . $user->last_name . '</li>';
        $infoHtml .= '<li><b>Login IP Address:</b> <a href="https://ipinfo.io/' . $ip . '">' . $ip . '</a></li>';
        $infoHtml .= '<li><b>Browser:</b> ' . $browserDetection->getOS($agent)['os_family'] . ' / ' . $browserDetection->getBrowser($agent)['browser_name'] . '</li>';
        $infoHtml .= '</ul>';

        $lines = [
            '<p style="font-size: 16px; line-height: 25px;">Hello there, <br />The following user has been logged in to your site. Here is the details:</p>',
            $infoHtml
        ];

        $siteName = get_bloginfo('name');
        $data = [
            'body'        => implode('', $lines),
            'pre_header'  => 'Login success at ' . $siteName,
            'show_footer' => true
        ];

        $body = Helper::loadView('notification', $data);
        $subject = '[' . $siteName . '] Login success for ' . $user->user_login;

        $headers = array('Content-Type: text/html; charset=UTF-8');

        return \wp_mail($adminEmail, $subject, $body, $headers);
    }

    /**
     * @param $user \WP_User | \WP_Error
     * @param $userName string
     * @return bool
     */
    private function maybeSendBlockedEmail($user, $userName)
    {
        if (Helper::getSetting('notify_on_blocked') !== 'yes') {
            return false;
        }

        $adminEmail = Helper::getSetting('notification_email');
        if (!$adminEmail) {
            return false;
        }

        $adminEmail = str_replace('{admin_email}', get_bloginfo('admin_email'), $adminEmail);
        if (!$adminEmail) {
            return false;
        }

        // get last send email time
        $lastSendTime = get_option('fls_last_blocked_email_send_time', 0);
        if ($lastSendTime && (time() - $lastSendTime) < 60) {
            return false;
        }

        update_option('fls_last_blocked_email_send_time', time(), false);

        $agent = sanitize_text_field($_SERVER['HTTP_USER_AGENT']);
        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $ip = Helper::getIp();
        $infoHtml = '<ul style="padding-left:20px;line-height:25px;font-size: 14px;background: #f9f9f9;padding-top: 20px;padding-bottom: 20px;font-family: monospace;">';
        $infoHtml .= '<li><b>Site URL:</b> <a href="' . site_url() . '">' . site_url() . '</a></li>';
        $infoHtml .= '<li><b>Username:</b> ' . $userName . '</li>';
        $infoHtml .= '<li><b>Login IP Address:</b> <a href="https://ipinfo.io/' . $ip . '">' . $ip . '</a></li>';
        $infoHtml .= '<li><b>Browser:</b> ' . $browserDetection->getOS($agent)['os_family'] . ' / ' . $browserDetection->getBrowser($agent)['browser_name'] . '</li>';

        if (is_wp_error($user)) {
            $infoHtml .= '<li>' . wp_kses_post($user->get_error_message()) . '</li>';
        } else if ($user instanceof \WP_User) {
            $userEditLInk = add_query_arg('user_id', $user->ID, self_admin_url('user-edit.php'));
            $infoHtml .= '<li><b>Username:</b> <a href="' . $userEditLInk . '">' . $user->user_login . '</a></li>';
            $infoHtml .= '<li><b>Email:</b> ' . $user->user_email . '</li>';
            $infoHtml .= '<li><b>Name:</b> ' . $user->first_name . ' ' . $user->last_name . '</li>';
        }
        $infoHtml .= '</ul>';

        $lines = [
            '<p style="font-size: 16px; line-height: 25px;">Hello there, <br />The following user has been blocked from logged in from your site. Here is the details:</p>',
            $infoHtml
        ];

        $siteName = get_bloginfo('name');
        $data = [
            'body'        => implode('', $lines),
            'pre_header'  => 'Blocked from login ' . $siteName,
            'show_footer' => true
        ];

        $body = Helper::loadView('notification', $data);
        $subject = '[' . $siteName . '] Blocked from login - ' . $userName;

        $headers = array('Content-Type: text/html; charset=UTF-8');

        return \wp_mail($adminEmail, $subject, $body, $headers);
    }
}
