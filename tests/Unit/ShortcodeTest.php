<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\GoogleOneTapAuthHandler;
use FluentAuth\App\Hooks\Handlers\MagicLoginHandler;
use FluentAuth\App\Hooks\Handlers\SocialAuthHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
use FluentAuth\App\Services\TwoFa\EnrollmentTwoFaMethod;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;

/**
 * The front end shortcodes, and what the second factor work did to them.
 *
 * The forms these render are the one login path that is not wp-login.php, so every
 * factor added since has to arrive through them too. The contract between the two is
 * narrow and entirely undeclared: handleLoginAjax() answers with JSON, and
 * src/public/login_helper.js decides what to do with it by looking for `load_2fa`,
 * `two_fa_form`, `recovery_codes` and `redirect`. Nothing in PHP references those
 * names, so a rename on either side breaks the front end silently and only there -
 * wp-login.php would carry on working. That is what these pin down.
 */
class ShortcodeTest extends BaseTestCase
{
    private $handler;

    private $twoFa;

    private $serverBackup = [];

    public function setUp(): void
    {
        parent::setUp();

        foreach (['REQUEST_METHOD', 'HTTP_HOST', 'REQUEST_URI'] as $key) {
            if (array_key_exists($key, $_SERVER)) {
                $this->serverBackup[$key] = $_SERVER[$key];
            }
        }

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_auth_logs");
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_login_hashes");

        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        $this->handler = new CustomAuthHandler();
        $this->twoFa = new TwoFaHandler();

        $this->enableAuthForms();

        // The shortcode callbacks are registered on the real handlers, as the plugin does.
        $this->handler->register();
    }

    public function tearDown(): void
    {
        foreach ([
            'fluent_auth_login', 'fluent_auth_signup', 'fluent_auth',
            'fluent_auth_reset_password', 'fluent_auth_magic_login',
            'fs_auth_buttons', 'fluent_auth_google_one_tap'
        ] as $tag) {
            remove_shortcode($tag);
        }

        unset($_REQUEST['_is_fls_form'], $_REQUEST['_nonce'], $_REQUEST['log'], $_REQUEST['pwd'], $_REQUEST['login_hash']);
        unset($_POST['log'], $_POST['pwd']);
        unset($_COOKIE[TwoFaHandler::PENDING_COOKIE]);

        foreach (['REQUEST_METHOD', 'HTTP_HOST', 'REQUEST_URI'] as $key) {
            if (array_key_exists($key, $this->serverBackup)) {
                $_SERVER[$key] = $this->serverBackup[$key];
            } else {
                unset($_SERVER[$key]);
            }
        }

        TwoFaService::resetMethods();
        parent::tearDown();
    }

    // ------------------------------------------------------- the shortcodes exist

    public function test_every_shortcode_the_plugin_documents_is_registered()
    {
        (new SocialAuthHandler())->register();
        (new GoogleOneTapAuthHandler())->register();

        foreach ([
            'fluent_auth_login',
            'fluent_auth_signup',
            'fluent_auth',
            'fluent_auth_reset_password',
            'fluent_auth_magic_login',
            'fs_auth_buttons',
            'fluent_auth_google_one_tap'
        ] as $tag) {
            $this->assertTrue(shortcode_exists($tag), $tag . ' is no longer registered');
        }
    }

    // ------------------------------------------------------------ plain rendering

    public function test_the_login_shortcode_renders_the_form_the_front_end_js_binds_to()
    {
        $html = do_shortcode('[fluent_auth_login]');

        // The wrapper the 2FA form replaces wholesale - see handleSuccess() in the JS.
        $this->assertStringContainsString('id="fls_login_form"', $html);

        // The form and submit button the JS attaches its submit handler to.
        $this->assertStringContainsString('id="loginform"', $html);
        $this->assertStringContainsString('id="wp-submit"', $html);

        $this->assertStringContainsString('name="log"', $html);
        $this->assertStringContainsString('name="pwd"', $html);
    }

    public function test_the_login_shortcode_stays_out_of_the_way_when_the_forms_are_off()
    {
        $this->enableAuthForms('no');

        $this->assertSame('', do_shortcode('[fluent_auth_login]'));
        $this->assertSame('', do_shortcode('[fluent_auth]'));
        $this->assertSame('', do_shortcode('[fluent_auth_reset_password]'));
    }

    public function test_the_login_shortcode_tells_a_signed_in_visitor_they_are_already_in()
    {
        update_option('users_can_register', 1);
        wp_set_current_user($this->factory->user->create(['role' => 'subscriber']));

        $this->assertStringContainsString('already logged in', do_shortcode('[fluent_auth_login]'));
        $this->assertStringContainsString('already logged in', do_shortcode('[fluent_auth_signup]'));
        $this->assertStringContainsString('already logged in', do_shortcode('[fluent_auth_reset_password]'));
    }

    public function test_the_signup_shortcode_says_so_when_registration_is_closed()
    {
        update_option('users_can_register', 0);

        $this->assertStringContainsString('registration is not enabled', do_shortcode('[fluent_auth_signup]'));
    }

    public function test_the_signup_shortcode_renders_its_own_nonce_and_form_id()
    {
        update_option('users_can_register', 1);

        $html = do_shortcode('[fluent_auth_signup]');

        $this->assertStringContainsString('id="flsRegistrationForm"', $html);
        $this->assertStringContainsString('name="_fls_signup_nonce"', $html);
        $this->assertStringContainsString('id="fls_submit"', $html);
    }

    public function test_the_reset_password_shortcode_renders_its_own_nonce_and_form_id()
    {
        $html = do_shortcode('[fluent_auth_reset_password]');

        $this->assertStringContainsString('id="flsResetPasswordForm"', $html);
        $this->assertStringContainsString('name="_fls_reset_pass_nonce"', $html);
        $this->assertStringContainsString('id="fls_reset_pass"', $html);
    }

    /**
     * [fluent_auth] is three shortcodes inside one, run through do_shortcode() again.
     * A nested shortcode that stopped resolving would leave the raw text on the page.
     */
    public function test_the_combined_shortcode_resolves_all_three_of_its_children()
    {
        update_option('users_can_register', 1);

        $html = do_shortcode('[fluent_auth]');

        $this->assertStringContainsString('id="loginform"', $html);
        $this->assertStringContainsString('id="flsRegistrationForm"', $html);
        $this->assertStringContainsString('id="flsResetPasswordForm"', $html);

        $this->assertStringNotContainsString('[fluent_auth_login', $html);
        $this->assertStringNotContainsString('[fluent_auth_signup', $html);
        $this->assertStringNotContainsString('[fluent_auth_reset_password', $html);
    }

    public function test_the_magic_login_shortcode_follows_the_magic_login_setting()
    {
        $this->setSettings(['magic_login' => 'no']);
        $this->assertSame('', do_shortcode('[fluent_auth_magic_login]'));

        $this->setSettings(['magic_login' => 'yes']);
        $html = do_shortcode('[fluent_auth_magic_login]');

        $this->assertStringContainsString('id="fls_magic_login"', $html);
        $this->assertStringContainsString('id="fls_magic_logon_nonce"', $html);
    }

    // --------------------------------------------------------- the social buttons

    public function test_the_social_buttons_shortcode_renders_the_providers_that_are_on()
    {
        (new SocialAuthHandler())->register();
        $this->enableSocialAuth();

        $html = do_shortcode('[fs_auth_buttons]');

        $this->assertStringContainsString('fm_login_wrapper', $html);
        $this->assertStringContainsString('fs_auth_btn', $html);
    }

    public function test_the_social_buttons_shortcode_is_empty_when_social_login_is_off()
    {
        (new SocialAuthHandler())->register();
        $this->enableSocialAuth(['enabled' => 'no']);

        $this->assertSame('', do_shortcode('[fs_auth_buttons]'));
    }

    public function test_the_social_buttons_shortcode_is_empty_for_a_signed_in_visitor()
    {
        (new SocialAuthHandler())->register();
        $this->enableSocialAuth();
        wp_set_current_user($this->factory->user->create(['role' => 'subscriber']));

        $this->assertSame('', do_shortcode('[fs_auth_buttons]'));
    }

    public function test_the_one_tap_shortcode_follows_its_own_setting()
    {
        (new GoogleOneTapAuthHandler())->register();

        $this->enableSocialAuth(['google_one_tap' => 'no']);
        $this->assertSame('', do_shortcode('[fluent_auth_google_one_tap]'));

        $this->enableSocialAuth(['google_one_tap' => 'yes']);
        $this->assertStringContainsString(
            'id="fluent-google-one-tap-button"',
            do_shortcode('[fluent_auth_google_one_tap]')
        );
    }

    // ------------------------------------------- the handoff to the second factor

    /**
     * The whole point of the exercise. A shortcode login by someone who owes a factor
     * must come back as the challenge form, not as a redirect - a redirect here would
     * mean the front end believed a login that never issued a cookie.
     */
    public function test_a_shortcode_login_owing_a_factor_answers_with_the_challenge_form()
    {
        $user = $this->userWithEmail2Fa();

        $response = $this->postLogin($user, 'correct-horse');

        $this->assertSame('yes', $response['load_2fa'], 'the front end looks for exactly this key');
        $this->assertArrayHasKey('two_fa_form', $response);
        $this->assertArrayNotHasKey('redirect', $response);

        $this->assertStringContainsString('id="fls_2fa_form"', $response['two_fa_form']);
    }

    public function test_the_shortcode_login_issues_no_auth_cookie_while_a_factor_is_owed()
    {
        $user = $this->userWithEmail2Fa();

        $issued = [];
        $spy = function ($send, $expiration, $userId) use (&$issued) {
            $issued[] = $userId;
            return $send;
        };
        add_filter('send_auth_cookies', $spy, 10, 3);

        $this->postLogin($user, 'correct-horse');

        remove_filter('send_auth_cookies', $spy, 10);

        $this->assertEmpty(
            array_filter($issued),
            'a cookie was sent for a login that still owed a second factor'
        );
    }

    public function test_a_shortcode_login_owing_nothing_answers_with_a_redirect()
    {
        $this->setSettings(['email2fa' => 'no', 'email2fa_roles' => []]);

        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);
        wp_set_password('correct-horse', $user->ID);

        $response = $this->postLogin($user, 'correct-horse');

        $this->assertArrayHasKey('redirect', $response);
        $this->assertArrayNotHasKey('load_2fa', $response);
    }

    public function test_a_shortcode_login_without_the_form_marker_is_refused()
    {
        $user = $this->userWithEmail2Fa();

        $response = $this->postLogin($user, 'correct-horse', ['omit_marker' => true]);

        $this->assertSame('Invalid request', $response['message']);
    }

    public function test_a_shortcode_login_with_a_bad_nonce_is_refused()
    {
        $user = $this->userWithEmail2Fa();

        $response = $this->postLogin($user, 'correct-horse', ['nonce' => 'not-the-nonce']);

        $this->assertStringContainsString('Security verification failed', $response['message']);
    }

    // ------------------------------- the challenge form, once it is on the page

    /**
     * The form arrives as a string of HTML and is put on the page with innerHTML. The
     * JS then re-binds by id, so every method has to agree on the same three names.
     *
     * @dataProvider challengeMethods
     */
    public function test_every_challenge_form_carries_the_ids_the_front_end_rebinds_to($methodClass)
    {
        $html = $this->renderChallengeFor($methodClass);

        $this->assertStringContainsString('id="fls_2fa_form"', $html, $methodClass . ' lost the form id');
        $this->assertStringContainsString('id="fls_2fa_confirm"', $html, $methodClass . ' lost the submit id');
        $this->assertStringContainsString('name="login_hash"', $html, $methodClass . ' lost the login hash field');
    }

    /**
     * The rule the whole arrangement rests on. Assigning to innerHTML does not run
     * <script> tags - the HTML spec says so and every browser obeys it - so a challenge
     * form that carried its own behaviour would render on the front end and do nothing,
     * while the identical form worked on wp-login.php, which never re-inserts it. Every
     * ceremony therefore lives in login_helper.js and every form ships data only.
     *
     * @dataProvider challengeMethods
     */
    public function test_no_challenge_form_needs_an_inline_script_to_be_usable($methodClass)
    {
        $html = $this->renderChallengeFor($methodClass);

        $withoutJsonIslands = preg_replace('#<script type="application/json".*?</script>#s', '', $html);

        $this->assertDoesNotMatchRegularExpression(
            '#<script(?![^>]*type="application/json")[^>]*>\s*\S#',
            $withoutJsonIslands,
            $methodClass . ' puts working code in an inline <script>. login_helper.js installs'
            . ' this form with innerHTML, which never executes it, so the form would be'
            . ' inert on any page built from the [fluent_auth_login] shortcode. Move the'
            . ' behaviour into src/public/login_helper.js and leave a JSON island behind.'
        );
    }

    /**
     * What replaced the inline script: the form carries its ceremony as data, and
     * login_helper.js supplies the behaviour. The island has to survive innerHTML, so
     * it must be a <script type="application/json"> - parsed as an element, read with
     * textContent - and it must carry everything the ceremony needs, because the script
     * has no other way to learn it.
     */
    public function test_the_passkey_challenge_hands_its_ceremony_over_as_data()
    {
        $html = $this->renderChallengeFor(PasskeyTwoFaMethod::class);

        $config = $this->readIsland($html, 'fls_passkey_config');

        $this->assertIsArray($config['options'], 'the browser needs the request options');
        $this->assertNotEmpty($config['options']['challenge']);

        foreach (['unsupported', 'prompting', 'cancelled', 'verifying'] as $key) {
            $this->assertNotEmpty($config['messages'][$key], $key . ' has no translated text');
        }
    }

    public function test_the_enrollment_form_hands_its_ceremony_over_as_data()
    {
        $html = $this->renderChallengeFor(EnrollmentTwoFaMethod::class, ['passkeys' => true]);

        $config = $this->readIsland($html, 'fls_enroll_config');

        $this->assertNotEmpty($config['options']['challenge']);
        $this->assertNotEmpty($config['options']['user']['id']);

        foreach (['prompting', 'cancelled', 'saving'] as $key) {
            $this->assertNotEmpty($config['messages'][$key], $key . ' has no translated text');
        }
    }

    /**
     * And there is no second chance. maybe2FaRedirect() - the path a shortcode login
     * takes - answers with the form and stops; it never drops the pending cookie that
     * maybeDenyHeadlessLogin() and raiseChallengeForDirectLogin() leave behind. So the
     * resume on the next page load, which is what rescues every other stuck challenge,
     * does not apply here: reloading returns an empty login form and the password has
     * to be typed again, for the same dead form.
     */
    public function test_a_shortcode_challenge_leaves_no_pending_cookie_to_resume_from()
    {
        unset($_COOKIE[TwoFaHandler::PENDING_COOKIE]);

        $user = $this->userWithEmail2Fa();
        $response = $this->postLogin($user, 'correct-horse');

        $this->assertSame('yes', $response['load_2fa']);
        $this->assertArrayNotHasKey(
            TwoFaHandler::PENDING_COOKIE,
            $_COOKIE,
            'a resume cookie here would give a stuck challenge a way back'
        );
    }

    /**
     * Enrollment gets off more lightly. Its passkey pane is hidden until the script
     * reveals it and the authenticator pane is visible from the start, so a front end
     * that never runs the script degrades to app-only setup rather than to nothing.
     * Worth pinning: it is the reason this one is a missing option and not an outage.
     */
    public function test_the_enrollment_form_still_offers_the_authenticator_without_its_script()
    {
        $html = $this->renderChallengeFor(EnrollmentTwoFaMethod::class, ['passkeys' => true]);

        $this->assertStringContainsString('id="fls_enroll_passkey"', $html);
        $this->assertMatchesRegularExpression(
            '#id="fls_enroll_passkey"[^>]*style="[^"]*display:\s*none#',
            $html,
            'the passkey pane is expected to start hidden'
        );

        // The app pane carries a real submit button and no display:none of its own.
        $this->assertStringContainsString('id="fls_enroll_app"', $html);
        $this->assertMatchesRegularExpression(
            '#id="fls_2fa_confirm" type="submit"#',
            $html,
            'the authenticator pane must stay operable without the script'
        );
    }

    public function challengeMethods()
    {
        return [
            'email'      => [EmailTwoFaMethod::class],
            'totp'       => [TotpTwoFaMethod::class],
            'passkey'    => [PasskeyTwoFaMethod::class],
            'enrollment' => [EnrollmentTwoFaMethod::class]
        ];
    }

    // ------------------------------------------------------------------- plumbing

    private function enableAuthForms($enabled = 'yes')
    {
        update_option('__fls_auth_forms_settings', ['enabled' => $enabled]);

        $this->setSettings([
            'login_try_limit'  => 5,
            'login_try_timing' => 30
        ]);
    }

    /**
     * Pulls one JSON island out of rendered markup and decodes it.
     *
     * @return array
     */
    private function readIsland($html, $id)
    {
        $pattern = '#<script type="application/json" id="' . preg_quote($id, '#') . '">(.*?)</script>#s';

        $this->assertMatchesRegularExpression($pattern, $html, $id . ' island is missing');

        preg_match($pattern, $html, $matches);

        $decoded = json_decode(trim($matches[1]), true);

        $this->assertIsArray($decoded, $id . ' island is not valid JSON');

        return $decoded;
    }

    private function enableSocialAuth($overrides = [])
    {
        update_option('__fls_social_auth_settings', array_merge([
            'enabled'              => 'yes',
            'enable_google'        => 'yes',
            'google_one_tap'       => 'yes',
            'google_key_method'    => 'db',
            'google_client_id'     => '1234567890-test.apps.googleusercontent.com',
            'google_client_secret' => 'a-secret-worth-keeping'
        ], $overrides));

        Helper::resetStatics();
    }

    private function setSettings($settings)
    {
        update_option('__fls_auth_settings', array_merge(
            (array)get_option('__fls_auth_settings'),
            $settings
        ));

        Helper::resetStatics();
    }

    private function userWithEmail2Fa()
    {
        $this->setSettings([
            'email2fa'       => 'yes',
            'email2fa_roles' => ['administrator']
        ]);

        $user = $this->factory->user->create_and_get(['role' => 'administrator']);
        wp_set_password('correct-horse', $user->ID);

        return get_user_by('ID', $user->ID);
    }

    /**
     * Drives handleLoginAjax() the way the shortcode's JS does and captures the JSON.
     *
     * @return array
     */
    private function postLogin($user, $password, $options = [])
    {
        $_REQUEST['log'] = $_POST['log'] = $user->user_login;
        $_REQUEST['pwd'] = $_POST['pwd'] = $password;
        $_REQUEST['_nonce'] = isset($options['nonce'])
            ? $options['nonce']
            : wp_create_nonce('fsecurity_login_nonce');

        if (empty($options['omit_marker'])) {
            $_REQUEST['_is_fls_form'] = 'yes';
        } else {
            unset($_REQUEST['_is_fls_form']);
        }

        // LoginSecurityHandler fires the action the challenge hangs off.
        $security = new \FluentAuth\App\Hooks\Handlers\LoginSecurityHandler();
        $security->register();
        $this->twoFa->register();

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        ob_start();
        try {
            $this->handler->handleLoginAjax();
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        return (array)json_decode($output, true);
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    /**
     * Raises a real challenge of the given kind and returns the form HTML the
     * shortcode path would hand to the browser.
     *
     * @return string
     */
    private function renderChallengeFor($methodClass, $options = [])
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);
        $method = new $methodClass();

        if ($methodClass === PasskeyTwoFaMethod::class) {
            $this->setSettings([
                'passkey_2fa'       => 'yes',
                'passkey_2fa_roles' => ['administrator'],
                'totp_2fa'          => 'no',
                'email2fa'          => 'no'
            ]);
            PasskeyStore::ensureTable();

            $authenticator = new WebAuthnFixture();
            $challenge = random_bytes(32);
            $response = $authenticator->createRegistrationResponse(['challenge' => $challenge]);
            PasskeyStore::add($user, Registration::verify($response, $challenge), 'Test key');
        }

        if ($methodClass === EnrollmentTwoFaMethod::class) {
            $this->setSettings(['totp_2fa' => 'yes', 'totp_2fa_roles' => ['administrator']]);

            if (!empty($options['passkeys'])) {
                $this->setSettings(['passkey_2fa' => 'yes', 'passkey_2fa_roles' => ['administrator']]);
                PasskeyStore::ensureTable();
            }
        }

        $return = $this->twoFa->sendAndGet2FaConfirmFormUrl($user, 'both', '', $method);

        $this->assertNotFalse($return, 'could not raise a ' . $methodClass . ' challenge');

        return $method->renderForm($return);
    }
}
