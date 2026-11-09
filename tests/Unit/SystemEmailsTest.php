<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\MagicLoginHandler;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\SystemEmailService;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;

/**
 * Every email under Settings → System Emails, sent through the path that really sends it.
 *
 * Each one has three answers to give: "WordPress default" leaves core's email alone,
 * "Customized" replaces it, and "Disabled" (where offered) sends nothing. The mail is
 * caught at pre_wp_mail, after the wp_mail filter, so what is asserted is what would
 * have reached the mailer.
 */
class SystemEmailsTest extends BaseTestCase
{
    /** @var array[] */
    private $sent = [];

    private $catcher;

    public function setUp(): void
    {
        parent::setUp();

        delete_option('fa_system_email_settings');
        SystemEmailService::resetStatics();

        $_SERVER['REMOTE_ADDR'] = '198.51.100.21';

        $this->sent = [];
        $this->catcher = function ($return, $atts) {
            $this->sent[] = $atts;
            return true;
        };
        add_filter('pre_wp_mail', $this->catcher, 10, 2);
    }

    public function tearDown(): void
    {
        remove_filter('pre_wp_mail', $this->catcher, 10);
        // Added for the rest of the request by a FluentAuth signup.
        remove_filter('wp_send_new_user_notification_to_user', '__return_false', 99);

        wp_set_current_user(0);
        $_POST = [];
        $_REQUEST = [];
        unset($_SERVER['REMOTE_ADDR']);

        delete_option('fa_system_email_settings');
        delete_option('__fls_auth_settings');
        SystemEmailService::resetStatics();
        Helper::resetStatics();

        parent::tearDown();
    }

    /* ---------------------------------------------------------------- helpers */

    private function setEmail($type, $status, $email = [], $templateSettings = [])
    {
        $settings = get_option('fa_system_email_settings', []);
        $settings['emails'][$type]['status'] = $status;

        if ($email) {
            $settings['emails'][$type]['email'] = $email;
        }

        if ($templateSettings) {
            $settings['template_settings'] = $templateSettings;
        }

        update_option('fa_system_email_settings', $settings, false);
        SystemEmailService::resetStatics();
    }

    private function makeUser($login, $role = 'subscriber')
    {
        $id = $this->factory->user->create([
            'user_login'   => $login,
            'user_email'   => $login . '@example.test',
            'display_name' => ucfirst($login),
            'role'         => $role,
        ]);

        return get_user_by('ID', $id);
    }

    private function mailTo($address)
    {
        return array_values(array_filter($this->sent, function ($mail) use ($address) {
            $to = is_array($mail['to']) ? implode(',', $mail['to']) : $mail['to'];
            return strpos($to, $address) !== false;
        }));
    }

    private function onlyMailTo($address)
    {
        $mails = $this->mailTo($address);
        $this->assertCount(1, $mails, 'exactly one email to ' . $address);

        return $mails[0];
    }

    private function headers($mail)
    {
        return is_array($mail['headers']) ? $mail['headers'] : array_filter(explode("\n", (string)$mail['headers']));
    }

    private function assertIsCustomizedHtml($mail)
    {
        $this->assertStringContainsString('<html', strtolower($mail['message']));
        $this->assertContains('Content-Type: text/html; charset=UTF-8', $this->headers($mail));
    }

    /**
     * Pulls the reset/set-password link out of a message and asserts WordPress accepts it.
     */
    private function assertWorkingPasswordLink($message, $user)
    {
        $this->assertSame(1, preg_match('/wp-login\.php\?[^"\s<>]*action=rp[^"\s<>]*/', $message, $m), 'the email carries a password link');
        parse_str(parse_url(html_entity_decode($m[0]), PHP_URL_QUERY), $query);

        $this->assertSame($user->user_login, $query['login']);
        $this->assertNotWPError(check_password_reset_key($query['key'], $user->user_login), 'the link in the email still works');
    }

    /* ------------------------------------------ New User Registration (to user) */

    public function test_registration_to_user_wordpress_default_is_cores_email()
    {
        $user = $this->makeUser('nina');

        wp_new_user_notification($user->ID, null, 'user');

        $mail = $this->onlyMailTo('nina@example.test');
        $this->assertStringContainsString('Login Details', $mail['subject']);
        $this->assertWorkingPasswordLink($mail['message'], $user);
    }

    /**
     * The reported bug: Users → Add New and FluentCRM's "Create WordPress User" make a user
     * with no default_password_nag, and the customized email used to be cancelled outright.
     */
    public function test_registration_to_user_customized_reaches_a_user_an_admin_added()
    {
        $this->setEmail('user_registration_to_user', 'active', [
            'subject' => 'Welcome aboard {{user.display_name}}',
            'body'    => '<p>Set it here: ##user.password_set_url##</p>',
        ]);
        $user = $this->makeUser('adam');
        $this->assertEmpty(get_user_meta($user->ID, 'default_password_nag', true));

        wp_new_user_notification($user->ID, null, 'both');

        $mail = $this->onlyMailTo('adam@example.test');
        $this->assertSame('Welcome aboard Adam', $mail['subject']);
        $this->assertIsCustomizedHtml($mail);
        $this->assertWorkingPasswordLink($mail['message'], $user);
    }

    public function test_registration_to_user_customized_reaches_a_wp_login_self_signup()
    {
        $this->setEmail('user_registration_to_user', 'active', [
            'subject' => 'Your account on {{site.title}}',
            'body'    => '<p>##user.password_set_url##</p>',
        ]);

        $userId = register_new_user('selfie', 'selfie@example.test');
        $this->assertIsInt($userId);
        $this->assertNotEmpty(get_user_meta($userId, 'default_password_nag', true));

        $mail = $this->onlyMailTo('selfie@example.test');
        $this->assertStringStartsWith('Your account on', $mail['subject']);
        $this->assertWorkingPasswordLink($mail['message'], get_user_by('ID', $userId));
    }

    public function newUserCases()
    {
        // welcome status, password generated (nag), who is signed in, expected email
        return [
            'chose a password, welcome customized'       => ['active', false, 'nobody', 'welcome'],
            'chose a password, welcome default'          => ['system', false, 'nobody', 'registration'],
            'chose a password, welcome disabled'         => ['disabled', false, 'nobody', 'registration'],
            'signed in as themselves, welcome customized' => ['active', false, 'self', 'welcome'],
            'generated password, welcome customized'     => ['active', true, 'nobody', 'registration'],
            'added by an admin, welcome customized'      => ['active', false, 'admin', 'registration'],
        ];
    }

    /**
     * Someone who picked their own password gets the welcome email. Anyone who never saw
     * their password - it was generated, or an admin made the account - gets the
     * registration email and its link.
     *
     * @dataProvider newUserCases
     */
    public function test_the_new_user_gets_the_email_that_fits_how_the_account_was_made($welcomeStatus, $generated, $signedIn, $expected)
    {
        $this->setEmail('user_registration_to_user', 'active', [
            'subject' => 'Set your password',
            'body'    => '<p>##user.password_set_url##</p>',
        ]);
        $this->setEmail('fluent_auth_welcome_email_to_user', $welcomeStatus, [
            'subject' => 'Welcome',
            'body'    => '<p>Welcome</p>',
        ]);

        if ($signedIn === 'admin') {
            wp_set_current_user($this->makeUser('siteadmin', 'administrator')->ID);
        }

        $userId = wp_create_user('newcomer', 'Chosen-Pass-123', 'newcomer@example.test');
        if ($generated) {
            update_user_option($userId, 'default_password_nag', true, true);
        }
        if ($signedIn === 'self') {
            wp_set_current_user($userId);
        }

        wp_send_new_user_notifications($userId, 'user');

        $mail = $this->onlyMailTo('newcomer@example.test');

        if ($expected === 'welcome') {
            $this->assertSame('Welcome', $mail['subject']);
            $this->assertStringNotContainsString('action=rp', $mail['message']);
        } else {
            $this->assertSame('Set your password', $mail['subject']);
            $this->assertWorkingPasswordLink($mail['message'], get_user_by('ID', $userId));
        }
    }

    /* ----------------------------------------- New User Registration (to admin) */

    public function test_registration_to_admin_wordpress_default_is_cores_email()
    {
        $this->makeUser('quiet');
        $user = get_user_by('login', 'quiet');

        wp_new_user_notification($user->ID, null, 'admin');

        $mail = $this->onlyMailTo(get_option('admin_email'));
        $this->assertStringContainsString('New User Registration', $mail['subject']);
        $this->assertStringContainsString('quiet', $mail['message']);
    }

    public function test_registration_to_admin_customized_replaces_cores_email()
    {
        $this->setEmail('user_registration_to_admin', 'active', [
            'subject' => 'New member: {{user.user_login}}',
            'body'    => '<p>Edit: ##user.profile_edit_url##</p>',
        ]);
        $user = $this->makeUser('member');

        wp_new_user_notification($user->ID, null, 'admin');

        $mail = $this->onlyMailTo(get_option('admin_email'));
        $this->assertSame('New member: member', $mail['subject']);
        $this->assertStringContainsString('user-edit.php?user_id=' . $user->ID, $mail['message']);
        $this->assertIsCustomizedHtml($mail);
    }

    public function test_registration_to_admin_disabled_sends_nothing_to_the_admin_only()
    {
        $this->setEmail('user_registration_to_admin', 'disabled');
        $user = $this->makeUser('silent');

        wp_new_user_notification($user->ID, null, 'both');

        $this->assertCount(0, $this->mailTo(get_option('admin_email')));
        $this->assertCount(1, $this->mailTo('silent@example.test'));
    }

    /* --------------------------------------------------- Password Reset Request */

    public function test_password_reset_wordpress_default_is_cores_email()
    {
        $user = $this->makeUser('forgetful');

        $this->assertTrue(retrieve_password('forgetful'));

        $mail = $this->onlyMailTo('forgetful@example.test');
        $this->assertStringContainsString('Password Reset', $mail['subject']);
        $this->assertWorkingPasswordLink($mail['message'], $user);
    }

    public function test_password_reset_customized_carries_a_working_reset_link()
    {
        $this->setEmail('password_reset_to_user', 'active', [
            'subject' => 'Reset for {{user.display_name}}',
            'body'    => '<p>##user.password_reset_url##</p>',
        ]);
        $user = $this->makeUser('resetter');

        $this->assertTrue(retrieve_password('resetter'));

        $mail = $this->onlyMailTo('resetter@example.test');
        $this->assertSame('Reset for Resetter', $mail['subject']);
        $this->assertIsCustomizedHtml($mail);
        $this->assertWorkingPasswordLink($mail['message'], $user);
    }

    /* ----------------------------------------- Email Address Change Confirmation */

    private function requestEmailChange($user, $newEmail)
    {
        wp_set_current_user($user->ID);
        $_POST = ['user_id' => $user->ID, 'email' => $newEmail];

        send_confirmation_on_profile_email();
    }

    public function test_email_change_confirmation_wordpress_default_is_cores_email()
    {
        $user = $this->makeUser('mover');

        $this->requestEmailChange($user, 'mover-new@example.test');

        $mail = $this->onlyMailTo('mover-new@example.test');
        $this->assertStringContainsString('Email Change Request', $mail['subject']);
        $this->assertStringContainsString('newuseremail=', $mail['message']);
    }

    public function test_email_change_confirmation_customized_carries_the_confirm_link()
    {
        $this->setEmail('email_change_notification_to_user', 'active', [
            'subject' => 'Confirm your new address, {{user.display_name}}',
            'body'    => '<p>Confirm {{user.new_changing_email_id}}: ##user.confirm_email_change_url##</p>',
        ]);
        $user = $this->makeUser('shifter');

        $this->requestEmailChange($user, 'shifter-new@example.test');

        $mail = $this->onlyMailTo('shifter-new@example.test');
        $this->assertSame('Confirm your new address, Shifter', $mail['subject']);
        $this->assertIsCustomizedHtml($mail);

        $hash = get_user_meta($user->ID, '_new_email', true)['hash'];
        $this->assertStringContainsString('profile.php?newuseremail=' . $hash, $mail['message']);
        $this->assertStringContainsString('shifter-new@example.test', $mail['message']);
    }

    /**
     * Templates saved before the picker was fixed hold the code without "user.".
     */
    public function test_email_change_confirmation_still_fills_the_old_new_email_code()
    {
        $this->setEmail('email_change_notification_to_user', 'active', [
            'subject' => 'Confirm {{new_changing_email_id}}',
            'body'    => '<p>New address: {{new_changing_email_id}}</p>',
        ]);
        $user = $this->makeUser('legacy');

        $this->requestEmailChange($user, 'legacy-new@example.test');

        $mail = $this->onlyMailTo('legacy-new@example.test');
        $this->assertSame('Confirm legacy-new@example.test', $mail['subject']);
        $this->assertStringContainsString('New address: legacy-new@example.test', $mail['message']);
    }

    /**
     * The subject is swapped in through a one-shot wp_mail filter; the next email sent in
     * the same request has to keep its own subject.
     */
    public function test_email_change_confirmation_does_not_rename_the_next_email()
    {
        $this->setEmail('email_change_notification_to_user', 'active', [
            'subject' => 'Confirm your new address',
            'body'    => '<p>##user.confirm_email_change_url##</p>',
        ]);
        $user = $this->makeUser('oneshot');

        $this->requestEmailChange($user, 'oneshot-new@example.test');
        wp_mail('someone@example.test', 'Unrelated', 'Body');

        $this->assertSame('Unrelated', $this->onlyMailTo('someone@example.test')['subject']);
    }

    /* --------------------------------- Email Address Changed (after confirmation) */

    public function test_email_changed_wordpress_default_is_cores_email()
    {
        $user = $this->makeUser('oldie');

        wp_update_user(['ID' => $user->ID, 'user_email' => 'oldie-new@example.test']);

        $mail = $this->onlyMailTo('oldie@example.test');
        $this->assertStringContainsString('Email Changed', $mail['subject']);
    }

    public function test_email_changed_customized_goes_to_the_old_address()
    {
        $this->setEmail('email_change_notification_after_confimation', 'active', [
            'subject' => 'Your email was changed',
            'body'    => '<p>It used to be {{user._previous_email_address_}}</p>',
        ]);
        $user = $this->makeUser('former');

        wp_update_user(['ID' => $user->ID, 'user_email' => 'former-new@example.test']);

        $mail = $this->onlyMailTo('former@example.test');
        $this->assertSame('Your email was changed', $mail['subject']);
        $this->assertStringContainsString('It used to be former@example.test', $mail['message']);
        $this->assertIsCustomizedHtml($mail);
    }

    /* ------------------------------------------ Welcome email after FluentAuth signup */

    private function fluentAuthSignup($login)
    {
        $userId = AuthService::registerNewUser($login, $login . '@example.test', 'Chosen-Pass-123', [
            '__validated' => true,
        ]);
        $this->assertIsInt($userId);

        return get_user_by('ID', $userId);
    }

    public function test_fluentauth_signup_with_wordpress_default_sends_cores_email()
    {
        $this->fluentAuthSignup('plainjoin');

        $mail = $this->onlyMailTo('plainjoin@example.test');
        $this->assertStringContainsString('Login Details', $mail['subject']);
    }

    /**
     * Someone who picked their own password is not sent a "set your password" email.
     * The admin is still told.
     */
    public function test_fluentauth_signup_skips_the_customized_set_password_email()
    {
        $this->setEmail('user_registration_to_user', 'active', [
            'subject' => 'Set your password',
            'body'    => '<p>##user.password_set_url##</p>',
        ]);

        $this->fluentAuthSignup('chooser');

        $this->assertCount(0, $this->mailTo('chooser@example.test'));
        $this->assertCount(1, $this->mailTo(get_option('admin_email')));
    }

    public function test_fluentauth_signup_customized_welcome_replaces_cores_email()
    {
        $this->setEmail('fluent_auth_welcome_email_to_user', 'active', [
            'subject' => 'Welcome to {{site.name}}',
            'body'    => '<p>Hi {{user.user_login}}</p>',
        ]);

        $this->fluentAuthSignup('joiner');

        $mail = $this->onlyMailTo('joiner@example.test');
        $this->assertStringStartsWith('Welcome to', $mail['subject']);
        $this->assertStringContainsString('Hi joiner', $mail['message']);
        $this->assertIsCustomizedHtml($mail);
    }

    /**
     * Both customized: the person who picked a password gets the welcome email only,
     * not a second "set your password" email as well.
     */
    public function test_fluentauth_signup_sends_one_email_when_both_are_customized()
    {
        $this->setEmail('user_registration_to_user', 'active', [
            'subject' => 'Set your password',
            'body'    => '<p>##user.password_set_url##</p>',
        ]);
        $this->setEmail('fluent_auth_welcome_email_to_user', 'active', [
            'subject' => 'Welcome',
            'body'    => '<p>Welcome</p>',
        ]);

        $this->fluentAuthSignup('bothways');

        $this->assertSame('Welcome', $this->onlyMailTo('bothways@example.test')['subject']);
    }

    public function test_fluentauth_signup_with_welcome_disabled_sends_the_user_nothing()
    {
        $this->setEmail('fluent_auth_welcome_email_to_user', 'disabled');

        $this->fluentAuthSignup('nomail');

        $this->assertCount(0, $this->mailTo('nomail@example.test'));
        $this->assertCount(1, $this->mailTo(get_option('admin_email')), 'the admin is still told');
    }

    /* ----------------------------------------------------------- 2FA code email */

    private function send2FaEmail($user, $code)
    {
        $method = new \ReflectionMethod(EmailTwoFaMethod::class, 'send2FaEmail');
        $method->setAccessible(true);

        return $method->invoke(new EmailTwoFaMethod(), ['two_fa_code' => $code], $user, 'https://example.test/secure-signin');
    }

    public function test_2fa_email_default_is_fluentauths_own_email()
    {
        $user = $this->makeUser('twofa');

        $this->assertTrue($this->send2FaEmail($user, '482913'));

        $mail = $this->onlyMailTo('twofa@example.test');
        $this->assertStringContainsString('482913', $mail['subject']);
        $this->assertStringContainsString('482913', $mail['message']);
    }

    public function test_2fa_email_customized_carries_the_code_and_link()
    {
        $this->setEmail('two_fa_email_to_user', 'active', [
            'subject' => 'Code {{user.two_fa_code}} for {{user.display_name}}',
            'body'    => '<p>Type ##user.two_fa_code## or open ##user.secure_signin_url##</p>',
        ]);
        $user = $this->makeUser('coded');

        $this->assertTrue($this->send2FaEmail($user, '104729'));

        $mail = $this->onlyMailTo('coded@example.test');
        $this->assertSame('Code 104729 for Coded', $mail['subject']);
        $this->assertStringContainsString('Type 104729 or open https://example.test/secure-signin', $mail['message']);
        $this->assertIsCustomizedHtml($mail);
    }

    /* --------------------------------------------------------- Magic login email */

    private function requestMagicLink($user)
    {
        $settings = get_option('__fls_auth_settings', []);
        $settings['magic_login'] = 'yes';
        $settings['magic_restricted_roles'] = [];
        update_option('__fls_auth_settings', $settings, false);
        Helper::resetStatics();

        $_REQUEST = [
            'email'  => $user->user_email,
            '_nonce' => wp_create_nonce('fls_magic_logon_nonce'),
        ];

        $die = function () {
            return function () {
                throw new \WPDieException('sent');
            };
        };
        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', $die);

        try {
            ob_start();
            (new MagicLoginHandler())->handleMagicLoginAjax();
        } catch (\WPDieException $e) {
            // wp_send_json() ends in wp_die().
        } finally {
            ob_end_clean();
            remove_filter('wp_doing_ajax', '__return_true');
            remove_filter('wp_die_ajax_handler', $die);
            flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->delete();
        }
    }

    public function test_magic_email_default_is_fluentauths_own_email()
    {
        $user = $this->makeUser('magician');

        $this->requestMagicLink($user);

        $mail = $this->onlyMailTo('magician@example.test');
        $this->assertStringStartsWith('Sign in to', $mail['subject']);
        $this->assertStringContainsString('fls_al=', $mail['message']);
    }

    public function test_magic_email_customized_carries_the_signin_link()
    {
        $this->setEmail('magic_email_to_user', 'active', [
            'subject' => 'Your link, {{user.display_name}}',
            'body'    => '<p><a href="##user.secure_signin_url##">Sign in</a></p>',
        ]);
        $user = $this->makeUser('wizard');

        $this->requestMagicLink($user);

        $mail = $this->onlyMailTo('wizard@example.test');
        $this->assertSame('Your link, Wizard', $mail['subject']);
        $this->assertStringContainsString('fls_al=', $mail['message']);
        $this->assertIsCustomizedHtml($mail);
    }

    /* ------------------------------------------------------ smartcode picker */

    /**
     * Every code the editor offers has to resolve. The 2FA code and the sign-in link are
     * filled in by their own senders before the parser runs, so they are left out here.
     */
    public function test_every_smartcode_the_editor_offers_is_replaced()
    {
        $user = $this->makeUser('picker');
        update_user_meta($user->ID, '_new_email', ['hash' => 'abc123', 'newemail' => 'picker-new@example.test']);
        $user->_previous_email_address_ = 'picker-old@example.test';

        $filledBySender = ['##user.two_fa_code##', '##user.secure_signin_url##'];
        $parser = new \FluentAuth\App\Services\SmartCodeParser();

        foreach (SystemEmailService::getEmailIndexes() as $type => $email) {
            foreach (array_keys(Arr::get($email, 'additional_smartcodes', [])) as $code) {
                if (in_array($code, $filledBySender, true)) {
                    continue;
                }

                $parsed = $parser->parse($code, $user);
                $this->assertNotSame($code, $parsed, $type . ' offers ' . $code . ', which is never replaced');
                $this->assertNotSame('', $parsed, $type . ' offers ' . $code . ', which comes out empty');
            }
        }
    }

    /* ------------------------------------------------- From / Reply-To headers */

    public function test_customized_emails_carry_the_from_and_reply_to_settings()
    {
        $this->setEmail('user_registration_to_user', 'active', [
            'subject' => 'Hello',
            'body'    => '<p>##user.password_set_url##</p>',
        ], [
            'from_name'      => 'Acme Shop',
            'from_email'     => 'hello@acme.test',
            'reply_to_name'  => 'Acme Help',
            'reply_to_email' => 'help@acme.test',
        ]);
        $user = $this->makeUser('headed');

        wp_new_user_notification($user->ID, null, 'user');

        $headers = $this->headers($this->onlyMailTo('headed@example.test'));
        $this->assertContains('From: Acme Shop <hello@acme.test>', $headers);
        $this->assertContains('Reply-To: Acme Help <help@acme.test>', $headers);
    }
}
