<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\SmartCodeParser;
use FluentAuth\App\Services\SystemEmailService;

/**
 * A one time code mailed to the account address.
 *
 * This proves the mailbox, which is exactly what a magic link proves, so the
 * dispatcher skips it for a user who arrived that way. See AuthFactor.
 */
class EmailTwoFaMethod extends BaseTwoFaMethod
{
    /**
     * How long an issued code stays usable, in minutes.
     */
    const VALIDITY_MINUTES = 10;

    public function getKey()
    {
        return 'email_2_fa';
    }

    /**
     * Codes issued because the account itself is under attack. Recorded separately so
     * the code stays usable even where email 2FA is not otherwise enabled.
     */
    public function getChallengeKey()
    {
        return '2fa_challenge';
    }

    public function getTitle()
    {
        return __('Email Code', 'fluent-security');
    }

    /**
     * The address is already on the account, so a code can be sent to a user who never
     * turned this on. That is what makes it the fallback for an account under attack.
     */
    public function supportsUnenrolledChallenge()
    {
        return true;
    }

    public function getSatisfiedFactor()
    {
        return AuthFactor::EMAIL;
    }

    public function getHandoffText()
    {
        return __('We have emailed you a login code.', 'fluent-security');
    }

    public function getLoginMedia()
    {
        return 'two_factor_email';
    }

    /**
     * @param $user \WP_User
     * @return bool
     */
    /**
     * Whether this method is in force for anybody at all.
     *
     * Switched on and given no roles is switched on for nobody, so both halves have to
     * hold. Asked by screens that report on second factors rather than apply them - the
     * enrollment list has nothing to list if no method is live.
     *
     * @return bool
     */
    public static function isEnabledForAnyRole()
    {
        if (Helper::getSetting('email2fa') !== 'yes') {
            return false;
        }

        $roles = Helper::getSetting('email2fa_roles');

        return is_array($roles) && (bool)$roles;
    }

    public function isAvailableForUser($user)
    {
        if (Helper::getSetting('email2fa') !== 'yes') {
            return false;
        }

        if (!$user instanceof \WP_User) {
            return true;
        }

        $roles = Helper::getSetting('email2fa_roles');

        return (bool)array_intersect($roles, array_values($user->roles));
    }

    /**
     * @param $user \WP_User
     * @return array
     */
    public function prepareChallenge($user)
    {
        try {
            $code = random_int(100123, 900987);
        } catch (\Exception $e) {
            $code = mt_rand(100123, 900987);
        }

        $code = (string)$code;

        return [
            'columns' => [
                'two_fa_code_hash' => wp_hash_password($code),
                'valid_till'       => date('Y-m-d H:i:s', current_time('timestamp') + self::VALIDITY_MINUTES * 60)
            ],
            'secret'  => $code
        ];
    }

    /**
     * @param $user \WP_User
     * @param $challenge array
     * @param $context array
     * @return void
     */
    public function dispatchChallenge($user, $challenge, $context)
    {
        $code = Arr::get($challenge, 'secret');

        $autoLoginUrl = TwoFaService::getChallengeUrl(Arr::get($context, 'login_hash'), [
            'auto_code' => $code
        ]);

        $data = Arr::get($context, 'row', []);
        $data['two_fa_code'] = $code;

        /*
         * The row is always written and the caller always gets a redirect, so 2FA stays
         * enforced no matter what. Only the outgoing mail is throttled - someone holding
         * the password can otherwise trigger an unlimited number of them.
         */
        if (!$this->hasReachedCodeRequestLimit($user)) {
            $this->send2FaEmail($data, $user, $autoLoginUrl);
        }

        do_action('fls_send_2fa_code', $data, $user, $autoLoginUrl);
    }

    /**
     * @param $user \WP_User
     * @param $logHash object
     * @param $request array
     * @return bool|\WP_Error
     */
    public function verifyProof($user, $logHash, $request)
    {
        $code = sanitize_text_field(Arr::get($request, 'login_passcode'));

        if (!$code) {
            return new \WP_Error(
                'invalid_code',
                __('Please provide a valid login code', 'fluent-security')
            );
        }

        return (bool)wp_check_password($code, $logHash->two_fa_code_hash);
    }

    public function renderForm($data = [])
    {
        $redirectTo = Arr::get($data, 'redirect_to');

        if ($redirectTo) {
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
                <p style="margin-bottom: 20px;"><?php esc_html_e('Please check your email inbox and get the 2 factor Authentication code and Provide here to login', 'fluent-security'); ?></p>
                <label for="login_passcode"><?php esc_html_e('Two-Factor Authentication Code', 'fluent-security'); ?></label>
                <div class="wp-pwd">
                    <input style="font-size: 14px;" placeholder="<?php esc_html_e('Login Code', 'fluent-security'); ?>"
                           type="number"
                           value="<?php echo (isset($data['auto_code'])) ? esc_attr($data['auto_code']) : ''; ?>"
                           name="login_passcode" id="login_passcode" class="input" size="20"/>
                </div>
                <div>
                    <button
                        style="display: block; cursor: pointer; width: 100%;border: 1px solid #2271b1;background: #2271b1;color: #fff;text-decoration: none;text-shadow: none;min-height: 32px;line-height: 2.30769231;padding: 4px 12px;font-size: 13px;border-radius: 3px;"
                        id="fls_2fa_confirm" type="submit">
                        <?php esc_html_e('Login', 'fluent-security'); ?>
                    </button>
                </div>
            </div>
        </form>
        <?php

        return ob_get_clean();
    }

    /**
     * Whether we have already mailed this user enough codes for now.
     *
     * Keyed on the user rather than the IP - the point is protecting their inbox, and
     * the requests come from whoever holds the password.
     *
     * @param $user \WP_User
     * @return bool
     */
    private function hasReachedCodeRequestLimit($user)
    {
        $minutes = (int)Helper::getSetting('login_try_timing');
        $limit = (int)Helper::getSetting('login_try_limit');

        $limit = (int)apply_filters('fluent_auth/2fa_code_request_limit', $limit, $user);
        $minutes = (int)apply_filters('fluent_auth/2fa_code_request_timing', $minutes, $user);

        /*
         * A floor of its own, because these two settings are about something else.
         *
         * They configure the login attempt limit, and a site is entitled to turn that off -
         * behind a WAF, or on a login page nobody else can reach. But this function was
         * reading them as though they also meant "how many emails may we send", so switching
         * the attempt limit off switched off the only thing standing between somebody
         * holding a password and an unbounded number of code emails into that person's
         * inbox. Each password submission raises one, and the headless paths raise them too.
         *
         * So the settings can only make this tighter, never absent: whichever gate is
         * reached first stops the send.
         */
        $floorLimit = (int)apply_filters('fluent_auth/2fa_code_request_floor_limit', 10, $user);
        $floorMinutes = (int)apply_filters('fluent_auth/2fa_code_request_floor_timing', 15, $user);

        if (!$minutes || !$limit) {
            $minutes = $floorMinutes;
            $limit = $floorLimit;
        } elseif ($floorMinutes > 0 && $floorLimit > 0 && $this->overFloor($user, $floorLimit, $floorMinutes)) {
            return true;
        }

        if (!$minutes || !$limit) {
            return false;
        }

        return $this->overFloor($user, $limit, $minutes);
    }

    /**
     * How many codes this account has been sent inside a window.
     *
     * @param $user \WP_User
     * @param $limit int
     * @param $minutes int
     * @return bool
     */
    private function overFloor($user, $limit, $minutes)
    {
        $count = flsDb()->table('fls_login_hashes')
            ->where('user_id', $user->ID)
            ->whereIn('use_type', [$this->getKey(), $this->getChallengeKey()])
            ->where('created_at', '>', date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60))
            ->count();

        return $count > $limit;
    }

    private function send2FaEmail($data, $user, $autoLoginUrl = false)
    {
        $emailData = $this->getCustomizedEmailSubjectBody($data, $user, $autoLoginUrl);

        if (empty($emailData['subject']) || empty($emailData['body'])) {
            $blogName = html_entity_decode(get_bloginfo('name'), ENT_QUOTES | ENT_HTML5, 'UTF-8');

            /* translators: %1$1s: Site Name, %2$d: verification code */
            $emailSubject = sprintf(__('Your Login code for %1$1s - %2$d', 'fluent-security'), $blogName, $data['two_fa_code']);

            $emailLines = [
                /* translators: %s: User's Display Name  */
                sprintf(__('Hello %s,', 'fluent-security'), $user->display_name),
                /* translators: %s: Site Name  */
                sprintf(__('Someone requested to login to %s and here is the Login code that you can use in the login form', 'fluent-security'), $blogName),
                '<b>' . __('Your Login Code: ', 'fluent-security') . '</b>',
                '<p style="font-size: 22px;border: 2px dashed #555454;padding: 5px 10px;text-align: center;background: #fffaca;letter-spacing: 7px;color: #555454;display:block;">' . $data['two_fa_code'] . '</p>',
                /* translators: %d: Minute  */
                sprintf(__('This code will expire in %d minutes and can only be used once.', 'fluent-security'), self::VALIDITY_MINUTES),
                ' ',
                '<hr />'
            ];

            $callToAction = false;

            if ($autoLoginUrl) {
                $emailLines[] = ' ';
                $emailLines[] = __('You can also login by clicking the following button', 'fluent-security');
                $callToAction = [
                    /* translators: %s: Site Name  */
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

            $emailData = [
                'subject' => $emailSubject,
                'body'    => $emailBody
            ];
        }

        return \wp_mail($user->user_email, $emailData['subject'], $emailData['body'], array(
            'Content-Type: text/html; charset=UTF-8'
        ));
    }

    private function getCustomizedEmailSubjectBody($data, $user, $autoLoginUrl = false)
    {
        $customSetting = SystemEmailService::getEmailSettingsByType('two_fa_email_to_user');

        if (Arr::get($customSetting, 'status', '') !== 'active') {
            return [
                'subject' => '',
                'body'    => ''
            ];
        }

        $subject = Arr::get($customSetting, 'email.subject', '');
        $body = Arr::get($customSetting, 'email.body', '');

        $replaces = [
            '{{user.two_fa_code}}'       => $data['two_fa_code'],
            '##user.two_fa_code##'       => $data['two_fa_code'],
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
}
