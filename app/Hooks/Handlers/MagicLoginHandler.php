<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\LoginAssets;
use FluentAuth\App\Services\SmartCodeParser;
use FluentAuth\App\Services\SystemEmailService;
use FluentAuth\App\Services\TwoFa\AuthFactor;

class MagicLoginHandler
{
    private $assetLoaded = false;

    public function register()
    {
        add_action('login_form', array($this, 'maybePushMagicForm'));
        add_action('login_enqueue_scripts', array($this, 'pushAssets'));
        add_action('wp_ajax_nopriv_fls_magic_send_magic_email', array($this, 'handleMagicLoginAjax'));

        add_action('init', function () {
            if (isset($_GET['fls_al'])) {
                $hash = sanitize_text_field($_GET['fls_al']);
                $this->makeLogin($hash);
            }

            if (isset($_GET['redirect_to']) && !wp_doing_ajax()) {
                if (get_current_user_id()) {
                    return;
                }

                $redirectTo = esc_url_raw($_REQUEST['redirect_to']);
                if (filter_var($redirectTo, FILTER_VALIDATE_URL)) {
                    // set cookie to redirect after login
                    setcookie('_fls_redirect_to', $redirectTo, time() + 600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
                }
            }
        }, 1);

        add_filter('login_form_bottom', [$this, 'maybeMagicFormOnLoginFunc']);

        /*
         * Programmatic Generation of the login token
         */
        add_filter('fluent_auth/login_token_by_user_id', function ($hash, $userId, $minutes) {

            if (!$this->isEnabled()) {
                return '';
            }

            $user = get_user_by('ID', $userId);
            if (!$user) {
                return '';
            }

            return $this->generateHash($user, $minutes);

        }, 10, 3);
        add_filter('fluent_auth/login_token_by_user_email', function ($hash, $emailId, $minutes) {
            if (!$this->isEnabled()) {
                return '';
            }

            $user = get_user_by('user_email', $emailId);
            if (!$user) {
                return '';
            }

            return $this->generateHash($user, $minutes);
        }, 10, 3);
    }

    public function maybePushMagicForm()
    {
        if (!$this->isEnabled()) {
            return '';
        }

        if (apply_filters('fluent_auth/will_disable_magic_form', false)) {
            return '';
        }

        $this->pushAssets();
        ?>
        <div style="display: none;" id="fls_magic_login">
            <div class="fls_magic_initial">
                <div class="fls_or_wrap">
                    <div class="fls_magic-or">
                        <span><?php esc_html_e('Or', 'fluent-security') ?></span>
                    </div>
                </div>

                <div class="fls_magic_login_btn">
                    <button class="fls_magic_show_btn magic_btn_secondary button button-primary button-large">
                        <?php esc_html_e('Login Via Magic URL', 'fluent-security'); ?>
                    </button>
                </div>
            </div>
            <div style="display: none" class="fls_magic_login_form">
                <p class="fls_magic_text">
                    <?php esc_html_e('Enter the email address or username associated with your account, and we\'ll send a magic link to your inbox.', 'fluent-security'); ?>
                </p>
                <label for="fls_magic_logon">
                    <?php esc_html_e('Your Email/Username', 'fluent-security'); ?>
                </label>
                <input placeholder="<?php esc_html_e('Your Email/Username', 'fluent-security'); ?>" id="fls_magic_logon"
                       class="fls_magic_input" type="text" name="fls_magic_logon_email"/>
                <input id="fls_magic_logon_nonce" type="hidden" name="fls_magic_logon_nonce"
                       value="<?php echo esc_attr(wp_create_nonce('fls_magic_logon_nonce')); ?>"/>
                <div class="fls_magic_submit_wrapper">
                    <button class="button button-primary button-large" id="fls_magic_submit">
                        <?php esc_html_e('Continue', 'fluent-security'); ?>
                    </button>
                </div>

                <div class="magic_back_regular">
                    <div class="fls_or_wrap">
                        <div class="fls_magic-or">
                            <span><?php esc_html_e('Or', 'fluent-security') ?></span>
                        </div>
                    </div>
                    <div class="fls_magic_login_back">
                        <button class="fls_magic_show_regular magic_btn_secondary">
                            <?php esc_html_e('Use Regular Login form', 'fluent-security'); ?>
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    public function maybeMagicFormOnLoginFunc($html)
    {
        if (!$this->isEnabled()) {
            return $html;
        }

        ob_start();
        $this->maybePushMagicForm();
        $newHtml = ob_get_clean();

        return $html . $newHtml;
    }

    public function pushAssets()
    {
        if ($this->assetLoaded || !$this->isEnabled()) {
            return;
        }

        /*
         * The magic form's behaviour moved into login_helper.js, so that it and the
         * passkey button - which both move themselves into the login form - run in a
         * known order rather than in whichever order the browser parsed two files.
         * LoginAssets carries the settings this used to localise of its own.
         */
        LoginAssets::enqueue();

        $this->assetLoaded = true;
    }

    public function isEnabled()
    {
        return Helper::getSetting('magic_login') === 'yes';
    }

    public function handleMagicLoginAjax()
    {
        if (!$this->isEnabled()) {
            wp_send_json([
                'message' => __('Login via URL is not activated', 'fluent-security')
            ], 422);
        }

        /*
         * Zero means the site turned the login attempt limit off, not that no link may ever
         * be sent. Read literally - which is what `>= $loginLimit` did with a zero - it
         * refused every request on such a site, so magic login simply stopped working the
         * moment somebody relaxed an unrelated setting.
         *
         * A bound of this endpoint's own stands in, because the thing being limited here is
         * not guessing: every request that gets through sends an email to somebody else's
         * address, and that has to have a ceiling whatever the attempt limit says.
         */
        $loginLimit = (int)Helper::getSetting('login_try_limit', 5);
        $timingMinutes = (int)Helper::getSetting('login_try_timing', 30);

        if ($loginLimit < 1 || $timingMinutes < 1) {
            $loginLimit = (int)apply_filters('fluent_auth/magic_login_floor_limit', 10);
            $timingMinutes = (int)apply_filters('fluent_auth/magic_login_floor_timing', 30);
        }

        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $timingMinutes * 60);

        $existingCount = flsDb()->table('fls_login_hashes')
            ->where('ip_address', Helper::getIp())
            // Scoped to magic links: 2FA and signup codes live in this table too, and
            // counting those meant an ordinary 2FA login ate into this allowance.
            ->where('use_type', 'magic_login')
            ->where('created_at', '>', $dateTime)
            ->count();

        if ($existingCount >= $loginLimit) {
            wp_send_json([
                /* translators: %d: Minite  */
                'message' => sprintf(__('You are trying too much. Please try after %d minutes', 'fluent-security'), $timingMinutes)
            ], 422);
        }

        $username = sanitize_text_field($_REQUEST['email']);
        $nonce = sanitize_text_field($_REQUEST['_nonce']);

        // Verify the nonce now
        if (!wp_verify_nonce($nonce, 'fls_magic_logon_nonce')) {
            wp_send_json(array(
                'message' => __('Nonce Verification failed. Please try again', 'fluent-security')
            ), 422);
        }

        // Let's prepare
        if (strpos($username, '@')) {
            $user = get_user_by('email', $username);
            if (!$user) {
                $user = get_user_by('login', $username);
            }
        } else {
            $user = get_user_by('login', $username);
        }

        $canUseMagicLogin = apply_filters('fluent_auth/magic_login_can_use', $this->canUseMagic($user), $user);

        if (!$canUseMagicLogin) {
            /*
             * An account that exists and an account that does not have to answer the same,
             * or this form is a way to ask the site whether a given address has an account -
             * which is the question the login form was hardened against answering, a few
             * files away, by replacing core's "invalid username" with a message that does
             * not say which half was wrong.
             *
             * It was also the cheaper question to ask. The allowance counted above is
             * measured in rows, and a row is only written once a user has been found, so
             * probing for addresses that do not exist cost nothing and was unlimited. The
             * attempt is recorded first, so a probe is spent from the same budget as a real
             * request.
             *
             * A site that would rather say no out loud can still do it through the filter;
             * what changed is the default, and that it no longer says no by accident.
             */
            $this->recordMagicProbe();

            if ($user) {
                $error_message = apply_filters(
                    'fluent_auth/magic_login_error_message',
                    __('Sorry, You can not login via magic url. Please use regular login form', 'fluent-security'),
                    $user
                );

                wp_send_json(array(
                    'message' => $error_message
                ), 422);
            }

            wp_send_json($this->sentConfirmation($username), 200);
        }

        // Now we have a valid user and let's send the email
        $validity = apply_filters('fluent_auth/default_token_validity', 10, $user);

        if (!empty($_REQUEST['redirect_to']) && filter_var($_REQUEST['redirect_to'], FILTER_VALIDATE_URL)) {
            $redirect_to = sanitize_url($_REQUEST['redirect_to']);
        } else {
            $redirect_to = $this->getLoginRedirect($user);
        }

        $loginUrl = esc_url($this->getMagicLoginUrl($user, $validity, false, $redirect_to));


        $emailData = $this->getCustomizedEmailSubjectBody($user, $loginUrl);
        if (empty($emailData['subject']) || empty($emailData['body'])) {
            /* translators: %s: Site Name  */
            $emailSubject = sprintf(__('Sign in to %s', 'fluent-security'), get_bloginfo('name'));

            $emailLines = [
                /* translators: %s: user's display name  */
                sprintf(__('Hello %s,', 'fluent-security'), $user->display_name),
                /* translators: %s: Site Name  */
                sprintf(__('Click the link below to sign in to your %s account', 'fluent-security'), get_bloginfo('name')),
                /* translators: %d: Minute  */
                sprintf(__('This link will expire in %d minutes and can only be used once.', 'fluent-security'), $validity)
            ];

            $callToAction = [
                /* translators: %s: Site Name  */
                'btn_text' => sprintf(__('Sign in to %s', 'fluent-security'), get_bloginfo('name')),
                'url'      => $loginUrl
            ];

            $footerLines = [
                __('If the button above does not work, paste this link into your web browser:', 'fluent-security'),
                esc_url($loginUrl),
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

            $emailBody .= Helper::loadView('magic_login.call_to_action', $callToAction);

            $emailBody .= Helper::loadView('magic_login.line_block', [
                'lines' => $footerLines
            ]);

            $emailBody .= Helper::loadView('magic_login.footer', []);

            $emailData['subject'] = $emailSubject;
            $emailData['body'] = $emailBody;
        }

        $result = \wp_mail($user->user_email, $emailData['subject'], $emailData['body'], array(
            'Content-Type: text/html; charset=UTF-8'
        ));

        $confirmation = $this->sentConfirmation($username);
        $confirmation['result'] = $result;

        wp_send_json($confirmation, 200);
    }

    /**
     * What this form says once it has finished, whoever was typed into it.
     *
     * The address is echoed back as it was typed rather than read off the account. In the
     * ordinary case they are the same string; where they are not - somebody whose username
     * happens to look like an email address, signing in with it - reading it off the account
     * would print an address the person at the keyboard had not supplied.
     *
     * @param string $username whatever was typed
     * @return array
     */
    private function sentConfirmation($username)
    {
        $message = __('We just emailed a login link to your registered email. Click the link to sign in.', 'fluent-security');

        if (is_email($username)) {
            /* translators: %s: User Email  */
            $message = sprintf(__('We just emailed a magic link to %s. Click the link to sign in.', 'fluent-security'), $username);
        }

        return [
            'heading' => __('Check your inbox', 'fluent-security'),
            'result'  => true,
            'message' => $message
        ];
    }

    /**
     * Spend one from the address's allowance without sending anything.
     *
     * The allowance is counted in rows of this table, so a request that never reaches the
     * point of writing one is a request that never counted. This writes the row that a
     * refused attempt would otherwise not leave behind.
     *
     * Deliberately not redeemable: no user, a status nothing looks for, and a validity that
     * has already passed. It exists to be counted.
     *
     * @return void
     */
    private function recordMagicProbe()
    {
        $now = date('Y-m-d H:i:s', current_time('timestamp'));

        flsDb()->table('fls_login_hashes')->insert([
            'login_hash'  => 'probe-' . wp_generate_password(32, false),
            'user_id'     => 0,
            'use_limit'   => 0,
            'used_count'  => 0,
            'status'      => 'probe',
            'use_type'    => 'magic_login',
            'ip_address'  => Helper::getIp(),
            'valid_till'  => $now,
            'created_at'  => $now,
            'updated_at'  => $now
        ]);
    }

    private function getCustomizedEmailSubjectBody($user, $autoLoginUrl = '')
    {
        $customSetting = SystemEmailService::getEmailSettingsByType('magic_email_to_user');

        if (Arr::get($customSetting, 'status', '') !== 'active' || !$autoLoginUrl) {
            return [
                'subject' => '',
                'body'    => ''
            ];
        }

        $subject = Arr::get($customSetting, 'email.subject', '');
        $body = Arr::get($customSetting, 'email.body', '');

        $replaces = [
            '##user.secure_signin_url##' => $autoLoginUrl,
            '{{user.secure_signin_url}}' => $autoLoginUrl,
        ];

        $subject = strtr($subject, $replaces);
        $body = strtr($body, $replaces);

        $body = SystemEmailService::withHtmlTemplate($body, null, $user);

        $body = (new SmartCodeParser())->parse($body, $user);
        $subject = (new SmartCodeParser())->parse($subject, $user);

        return [
            'subject' => $subject,
            'body'    => $body
        ];
    }


    private function getMagicLoginUrl($user, $validity = 5, $baseUrl = false, $redirectIntend = '')
    {
        if (!$baseUrl) {
            $baseUrl = site_url('index.php');
        }

        if (!$redirectIntend && isset($_GET['redirect_to'])) {
            $redirectIntend = esc_url($_GET['redirect_to']);
        }

        $args = [
            'fls_al'         => $this->generateHash($user, $validity, $redirectIntend),
            'force_redirect' => 'yes'
        ];

        return add_query_arg($args, $baseUrl);
    }

    private function generateHash($user, $validity = 5, $redirectIntend = '') // $validity in minutes
    {
        if (!$user || !$this->isEnabled()) {
            return false;
        }

        /*
         * Straight from the CSPRNG rather than md5 over a uuid and mt_rand().
         *
         * On a current WordPress the old line was fine - wp_generate_uuid4() routes through
         * random_int() there - but this plugin supports back to 5.0, where it was plain
         * mt_rand(), and mt_rand() supplied the rest of the input too. That makes the
         * strength of a sign-in token depend on which WordPress the site happens to run,
         * which is not a thing anybody should have to know to answer "is this safe".
         */
        $string = bin2hex(random_bytes(32));
        $hash = wp_hash_password($string);

        $data = array(
            'login_hash'      => $hash,
            'user_id'         => $user->ID,
            'status'          => 'issued',
            'ip_address'      => Helper::getIp(),
            'created_by'      => get_current_user_id(),
            'redirect_intend' => $redirectIntend,
            'valid_till'      => date('Y-m-d H:i:s', current_time('timestamp') + $validity * 60),
            'created_at'      => current_time('mysql'),
            'updated_at'      => current_time('mysql')
        );

        $insertId = flsDb()->table('fls_login_hashes')
            ->insert($data);

        return $string . ':' . $insertId;
    }

    public function makeLogin($hash)
    {
        if (!$this->isEnabled()) {
            return false;
        }

        $hashes = explode(':', $hash);

        if (count($hashes) != 2) {
            return false;
        }

        $rowId = $hashes[1];
        $hash = $hashes[0];

        // Check if user logged in
        if (is_user_logged_in()) {
            $userId = get_current_user_id();
            flsDb()->table('fls_login_hashes')
                ->where('user_id', $userId)
                ->where('id', $rowId)
                ->update([
                    'status'             => 'already_logged_in',
                    'success_ip_address' => Helper::getIp(),
                    'updated_at'         => current_time('mysql')
                ]);
            return true;
        }

        $row = flsDb()->table('fls_login_hashes')
            ->where('id', $rowId)
            ->where('use_type', 'magic_login')
            ->where('status', 'issued')
            ->first();

        if (!$row) {
            return false;
        }

        if (!$this->isPasswordEqual($hash, $row->login_hash)) {
            return false;
        }

        $currentTimeStamp = current_time('timestamp');
        $validityTimestamp = strtotime($row->valid_till, $currentTimeStamp);

        if ($validityTimestamp < $currentTimeStamp) {
            // this is an invalid timestamp
            flsDb()->table('fls_login_hashes')
                ->where('id', $row->id)
                ->update([
                    'status'     => 'expired',
                    'updated_at' => current_time('mysql')
                ]);
            return false;
        }

        // The hash is valid now make the user logged in
        $userId = $row->user_id;
        $user = get_user_by('ID', $userId);

        if (!apply_filters('fluent_auth/magic_login_can_use', $this->canUseMagic($user), $user)) {
            return false;
        }

        /*
         * Claimed before it is used, not after.
         *
         * The row was read as `issued` here and only written back as `used` once the sign-in
         * had finished, which leaves a window: two requests carrying the same link both read
         * it as unspent and both go on to sign in. "Can only be used once" is what the email
         * promises and what the row's status is for, so the claim has to be the thing that
         * decides, and it has to be one statement.
         *
         * Written through $wpdb rather than the query builder because this needs the number
         * of rows the UPDATE actually matched, and the builder's update() returns nothing.
         * Nobody wins the race twice: whoever matched the row proceeds, everyone else is
         * told the link is spent.
         */
        global $wpdb;

        $claimed = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}fls_login_hashes
             SET status = 'used', success_ip_address = %s, updated_at = %s
             WHERE id = %d AND status = 'issued'",
            Helper::getIp(),
            current_time('mysql'),
            $row->id
        ));

        if (!$claimed) {
            return false;
        }

        Helper::setLoginMedia('magic_login');

        // The link came from their inbox, so the attempt limit must not block it.
        Helper::setTokenVerifiedLogin(true);

        /*
         * Redeeming the link is proof of the mailbox, so a second factor that proves the
         * same mailbox is not asked for again - it would be one factor twice. Anything
         * proving something else, an authenticator app or a passkey, still is: skipping
         * those would leave the mailbox as the only thing guarding an account that
         * explicitly asked for a stronger factor.
         */
        Helper::setSatisfiedFactors([AuthFactor::EMAIL]);

        add_filter('authenticate', array($this, 'allowProgrammaticLogin'), 10, 3);    // hook in earlier than other callbacks to short-circuit them
        $user = wp_signon(array(
                'user_login'    => $user->user_login,
                'user_password' => ''
            )
        );
        remove_filter('authenticate', array($this, 'allowProgrammaticLogin'), 10);

        Helper::setTokenVerifiedLogin(false);

        if ($user instanceof \WP_User) {
            wp_set_current_user($user->ID, $user->user_login);

            $user = wp_get_current_user();

            if ($user && $user->exists()) {
                flsDb()->table('fls_login_hashes')
                    ->where('id', $row->id)
                    ->update([
                        'status'             => 'used',
                        'success_ip_address' => Helper::getIp(),
                        'updated_at'         => current_time('mysql')
                    ]);

                Helper::setLoginMedia('magic_login');

                if (!wp_doing_ajax()) {
                    if (isset($_GET['force_redirect']) && $_GET['force_redirect'] == 'yes') {
                        if ($row->redirect_intend) {
                            wp_safe_redirect($row->redirect_intend);
                        } else {
                            wp_safe_redirect($this->getLoginRedirect($user));
                        }
                        exit();
                    }
                }

                return true;
            }
        }

        return false;
    }

    private function isPasswordEqual($password, $stored_hash)
    {
        return wp_check_password($password, $stored_hash);
    }

    public function allowProgrammaticLogin($user, $username, $password)
    {
        return get_user_by('login', $username);
    }

    private function getLoginRedirect($user)
    {
        $requested_redirect_to = isset($_REQUEST['redirect_to']) ? esc_url($_REQUEST['redirect_to']) : site_url();
        return apply_filters('login_redirect', $requested_redirect_to, $requested_redirect_to, $user);
    }

    /**
     * @param $user \WP_User
     * @return bool|mixed
     */
    private function canUseMagic($user)
    {
        if (!$user) {
            return false;
        }

        $restrictedRoles = Helper::getSetting('magic_restricted_roles');

        if (!$restrictedRoles) {
            return true;
        }

        return !array_intersect($restrictedRoles, array_values($user->roles));
    }

}
