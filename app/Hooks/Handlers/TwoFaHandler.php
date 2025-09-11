<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class TwoFaHandler
{
    public function register()
    {
        add_action('fluent_auth/login_attempts_checked', [$this, 'maybe2FaRedirect'], 1, 1);
        add_action('login_form_fls_2fa_email', [$this, 'render2FaForm'], 1);
        add_action('wp_ajax_nopriv_fluent_auth_2fa_email', [$this, 'verify2FaEmailCode']);
        add_action('wp_ajax_fluent_auth_2fa_email', function () {
            $hash = sanitize_text_field(Arr::get($_REQUEST, 'login_hash'));

            $logHash = flsDb()->table('fls_login_hashes')
                ->where('login_hash', $hash)
                ->where('use_type', 'email_2_fa')
                ->orderBy('id', 'DESC')
                ->first();

            $user = get_user_by('ID', get_current_user_id());
            $redirectTo = admin_url();
            if ($logHash && $logHash->redirect_intend) {
                $redirectTo = $logHash->redirect_intend;
                $redirectTo = apply_filters('login_redirect', $redirectTo, $logHash->redirect_intend, $user);
            }

            wp_send_json([
                'redirect' => $redirectTo
            ]);
        });
    }

    public function render2FaForm()
    {
        if (!$this->isEnabled()) {
            return false;
        }

        if (!isset($_GET['fls_2fa']) || $_GET['fls_2fa'] != 'email') {
            return;
        }

        login_header(__('Provide Login Code', 'fluent-security'), '', null);
        do_action('fls_load_login_helper');
        echo $this->get2FaFormHtml($_REQUEST); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        login_footer();
        exit();
    }

    public function maybe2FaRedirect($user)
    {
        // If it's an ajax call and not our own ajax calls then we will just return it
        // Until we get a better work-around for other plugins
        if (wp_doing_ajax() && empty($_REQUEST['_is_fls_form'])) {
            return false;
        }

        $return = $this->sendAndGet2FaConfirmFormUrl($user, 'both');

        if (!$return) {
            return false;
        }

        if (wp_doing_ajax()) {
            wp_send_json([
                'load_2fa'    => 'yes',
                'two_fa_form' => $this->get2FaFormHtml($return)
            ]);
        }

        wp_redirect($return['redirect_to']);
        exit();
    }

    public function sendAndGet2FaConfirmFormUrl($user, $return = 'url')
    {
        if (!$this->isEnabled($user)) {
            return false;
        }

        try {
            $twoFaCode = random_int(100123, 900987);
        } catch (\Exception $e) {
            $twoFaCode = mt_rand(100123, 900987);
        }

        $twoFaCode = (string) $twoFaCode;

        $string = $user->ID . '-' . wp_generate_uuid4() . mt_rand(1, 99999999);
        $hash = wp_hash_password($string);
        $hash = sanitize_title($hash, '', 'display');
        $hash .= $user->ID . '-' . time();

        $redirectIntend = '';
        if (isset($_REQUEST['redirect_to'])) {
            $redirectIntend = esc_url($_REQUEST['redirect_to']);
        }

        if (isset($_REQUEST['rememberme'])) {
            $hash .= '-auth';
        }

        $data = array(
            'login_hash'       => $hash,
            'user_id'          => $user->ID,
            'status'           => 'issued',
            'ip_address'       => Helper::getIp(),
            'redirect_intend'  => $redirectIntend,
            'use_type'         => 'email_2_fa',
            'two_fa_code_hash' => wp_hash_password($twoFaCode),
            'valid_till'       => date('Y-m-d H:i:s', current_time('timestamp') + 10 * 60),
            'created_at'       => current_time('mysql'),
            'updated_at'       => current_time('mysql')
        );

        flsDb()->table('fls_login_hashes')
            ->insert($data);

        $autoLoginUrl = add_query_arg([
            'fls_2fa'    => 'email',
            'login_hash' => $hash,
            'action'     => 'fls_2fa_email',
            'auto_code'  => $twoFaCode
        ], wp_login_url());

        $data['two_fa_code'] = $twoFaCode;

        $this->send2FaEmail($data, $user, $autoLoginUrl);

        if ($return === 'url') {
            return add_query_arg([
                'fls_2fa'    => 'email',
                'login_hash' => $hash,
                'action'     => 'fls_2fa_email'
            ], wp_login_url());
        }

        return [
            'redirect_to' => add_query_arg([
                'fls_2fa'    => 'email',
                'login_hash' => $hash,
                'action'     => 'fls_2fa_email'
            ], wp_login_url()),
            'login_hash'  => $hash
        ];
    }

    public function verify2FaEmailCode()
    {
        $code = sanitize_text_field(Arr::get($_REQUEST, 'login_passcode'));
        $hash = sanitize_text_field(Arr::get($_REQUEST, 'login_hash'));

        if (!$code || !$hash) {
            wp_send_json([
                'message' => __('Please provide a valid login code', 'fluent-security')
            ], 422);
        }

        $logHash = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $hash)
            ->where('use_type', 'email_2_fa')
            ->orderBy('id', 'DESC')
            ->first();

        if (!$logHash) {
            wp_send_json([
                'message' => __('Your provided code or url is not valid', 'fluent-security')
            ], 422);
        }

        if (!wp_check_password($code, $logHash->two_fa_code_hash)) {
            flsDb()->table('fls_login_hashes')
                ->where('id', $logHash->id)
                ->update([
                    'used_count' => $logHash->used_count + 1
                ]);

            wp_send_json([
                'message' => __('Your provided code is not valid. Please try again', 'fluent-security')
            ], 422);
        }

        $user = get_user_by('ID', $logHash->user_id);

        if (!$this->isEnabled($user)) {
            wp_send_json([
                'message' => __('Sorry, You can not use this verification method', 'fluent-security')
            ], 422);
        }

        if (strtotime($logHash->created_at) < current_time('timestamp') - 600 || !$user || $logHash->status != 'issued' || $logHash->used_count > 5) {
            wp_send_json([
                'message' => __('Sorry, your login code has been expired. Please try to login again', 'fluent-security')
            ], 422);
        }

        remove_action('fluent_auth/login_attempts_checked', [$this, 'maybe2FaRedirect'], 1);

        add_filter('authenticate', array($this, 'allowProgrammaticLogin'), 10, 3);    // hook in earlier than other callbacks to short-circuit them
        $user = wp_signon(array(
                'user_login' => $user->user_login,
                'user_password' => '',
                'remember'   => (bool) strpos($logHash->login_hash, '-auth')
            )
        );

        remove_filter('authenticate', array($this, 'allowProgrammaticLogin'), 10);

        if ($user instanceof \WP_User) {
            wp_set_current_user($user->ID, $user->user_login);
            if (is_user_logged_in()) {
                flsDb()->table('fls_login_hashes')
                    ->where('id', $logHash->id)
                    ->update([
                        'status'             => 'used',
                        'success_ip_address' => Helper::getIp()
                    ]);

                $redirectTo = $logHash->redirect_intend;
                if (!$redirectTo) {
                    $redirectTo = admin_url();
                }

                Helper::setLoginMedia('two_factor_email');

                $redirectTo = apply_filters('login_redirect', $redirectTo, $logHash->redirect_intend, $user);

                wp_send_json([
                    'redirect' => $redirectTo
                ]);
            }
        }

        wp_send_json([
            'message' => __('There has an error when log you in. Please try to login again', 'fluent-security')
        ], 422);
    }


    private function send2FaEmail($data, $user, $autoLoginUrl = false)
    {
        $blogName = html_entity_decode(get_bloginfo('name'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $emailSubject = sprintf(__('Your Login code for %1s - %d', 'fluent-security'), $blogName, $data['two_fa_code']);

        $emailLines = [
            sprintf(__('Hello %s,', 'fluent-security'), $user->display_name),
            sprintf(__('Someone requested to login to %s and here is the Login code that you can use in the login form', 'fluent-security'), $blogName),
            '<b>' . __('Your Login Code: ', 'fluent-security') . '</b>',
            '<p style="font-size: 22px;border: 2px dashed #555454;padding: 5px 10px;text-align: center;background: #fffaca;letter-spacing: 7px;color: #555454;display:block;">' . $data['two_fa_code'] . '</p>',
            sprintf(__('This code will expire in %d minutes and can only be used once.', 'fluent-security'), 10),
            ' ',
            '<hr />'
        ];

        $callToAction = false;

        if ($autoLoginUrl) {
            $emailLines[] = ' ';
            $emailLines[] = __('You can also login by clicking the following button', 'fluent-security');
            $callToAction = [
                'btn_text' => sprintf(__('Sign in to %s', 'fluent-security'), $blogName),
                'url'      => $autoLoginUrl
            ];
        }


        $footerLines = [
            ' ',
            __('If you did not make this request, you can safely ignore this email.', 'fluent-security')
        ];

        $emailBody = '';
        $emailBody .= Helper::loadView('magic_login.header', [
            'pre_header' => $emailSubject
        ]);

        $emailBody .= Helper::loadView('magic_login.line_block', [
            'lines' => $emailLines
        ]);

        if ($callToAction) {
            $emailBody .= Helper::loadView('magic_login.call_to_action', $callToAction);
        }

        $emailBody .= Helper::loadView('magic_login.line_block', [
            'lines' => $footerLines
        ]);

        $emailBody .= Helper::loadView('magic_login.footer', []);

        return \wp_mail($user->user_email, $emailSubject, $emailBody, array(
            'Content-Type: text/html; charset=UTF-8'
        ));
    }

    public function allowProgrammaticLogin($user, $username, $password)
    {
        return get_user_by('login', $username);
    }

    private function isEnabled($user = false)
    {
        if (Helper::getSetting('email2fa') !== 'yes') {
            return false;
        }

        if (!$user) {
            return true;
        }

        $roles = Helper::getSetting('email2fa_roles');

        return (bool)array_intersect($roles, array_values($user->roles));
    }


    private function get2FaFormHtml($data = [])
    {
        $redirectTo = Arr::get($data, 'redirect_to');

        if($redirectTo) {
            $redirectTo = esc_url_raw($redirectTo);
        }

        ob_start();
        ?>
        <form
            style="margin-top: 20px;margin-left: 0;padding: 26px 24px 34px;font-weight: 400;overflow: hidden;background: #fff;border: 1px solid #c3c4c7;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);"
            class="fls_2fs" id="fls_2fa_form">
            <input type="hidden" name="login_hash" value="<?php echo esc_attr(Arr::get($data, 'login_hash')); ?>"/>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirectTo); ?>"/>
            <div class="user-pass-wrap">
                <p style="margin-bottom: 20px;"><?php _e('Please check your email inbox and get the 2 factor Authentication code and Provide here to login', 'fluent-security'); ?></p>
                <label for="login_passcode"><?php _e('Two-Factor Authentication Code', 'fluent-security'); ?></label>
                <div class="wp-pwd">
                    <input style="font-size: 14px;" placeholder="<?php _e('Login Code', 'fluent-security'); ?>"
                           type="text"
                           value="<?php echo (isset($data['auto_code'])) ? esc_attr($data['auto_code']) : ''; ?>"
                           name="login_passcode" id="login_passcode" class="input" size="20"/>
                </div>
                <div>
                    <button
                        style="display: block; cursor: pointer; width: 100%;border: 1px solid #2271b1;background: #2271b1;color: #fff;text-decoration: none;text-shadow: none;min-height: 32px;line-height: 2.30769231;padding: 4px 12px;font-size: 13px;border-radius: 3px;"
                        id="fls_2fa_confirm" type="submit">
                        <?php _e('Login', 'fluent-security'); ?>
                    </button>
                </div>
            </div>
        </form>
        <?php

        return ob_get_clean();
    }
}
