<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\LoginSecurityHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;

/**
 * The emailed 2FA code is only ~800k possible values, so the number of guesses
 * allowed against it is the whole of its strength. These tests pin that bound down.
 */
class TwoFaHandlerTest extends BaseTestCase
{
    private $handler;

    private $user;

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

        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = ['administrator'];
        $settings['login_try_limit'] = 5;
        $settings['login_try_timing'] = 30;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->handler = new TwoFaHandler();
        $this->user = $this->factory->user->create_and_get(['role' => 'administrator']);

        unset($_REQUEST['login_passcode'], $_REQUEST['login_hash']);
    }

    public function tearDown(): void
    {
        unset($_REQUEST['login_passcode'], $_REQUEST['login_hash']);
        unset($_REQUEST['redirect_to'], $_REQUEST['redirect'], $_REQUEST['_is_fls_form']);
        unset($_COOKIE[TwoFaHandler::PENDING_COOKIE], $_COOKIE[LOGGED_IN_COOKIE]);
        unset($_SERVER['HTTP_REFERER']);
        foreach (['REQUEST_METHOD', 'HTTP_HOST', 'REQUEST_URI'] as $key) {
            if (array_key_exists($key, $this->serverBackup)) {
                $_SERVER[$key] = $this->serverBackup[$key];
            } else {
                unset($_SERVER[$key]);
            }
        }
        parent::tearDown();
    }

    private function pendingRowFor($user)
    {
        return flsDb()->table('fls_login_hashes')
            ->where('user_id', $user->ID)
            ->where('status', 'issued')
            ->orderBy('id', 'DESC')
            ->first();
    }

    /**
     * @return string|null where it tried to send the user, or null if it did not
     */
    private function captureRedirect($callback)
    {
        $captured = null;

        $catch = function ($location) use (&$captured) {
            $captured = $location;
            throw new \RuntimeException('redirected');
        };

        add_filter('wp_redirect', $catch);

        try {
            $callback();
        } catch (\RuntimeException $e) {
            // Expected: this is how the exit() below the redirect is escaped.
        } finally {
            remove_filter('wp_redirect', $catch);
        }

        return $captured;
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    /**
     * verify2FaEmailCode() terminates through wp_send_json(); capture what it emitted.
     */
    private function verify($code, $hash)
    {
        $_REQUEST['login_passcode'] = $code;
        $_REQUEST['login_hash'] = $hash;

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        ob_start();
        try {
            $this->handler->verify2FaEmailCode();
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        return json_decode($output, true);
    }

    /**
     * Issues a real code through the normal path and captures its plaintext value.
     */
    private function issueCode()
    {
        $captured = null;

        $spy = function ($data) use (&$captured) {
            $captured = $data;
        };

        add_action('fls_send_2fa_code', $spy, 10, 1);
        $return = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        remove_action('fls_send_2fa_code', $spy, 10);

        return [
            'code' => $captured['two_fa_code'],
            'hash' => $return['login_hash'],
        ];
    }

    private function hashRow($hash)
    {
        return flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->first();
    }

    /*
     * Logins with nowhere to show the challenge.
     *
     * A theme's popup form posts to admin-ajax.php and expects JSON of its own shape;
     * REST and XML-RPC callers cannot follow a redirect to a form. Those used to be let
     * straight through, which made every one of them a way around the second factor.
     */

    private function withHeadlessAjax(callable $fn)
    {
        unset($_REQUEST['_is_fls_form']);
        add_filter('wp_doing_ajax', '__return_true');

        try {
            return $fn();
        } finally {
            remove_filter('wp_doing_ajax', '__return_true');
        }
    }

    public function testAnotherPluginsAjaxLoginIsRefusedWhileASecondFactorIsOwed()
    {
        $result = $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    public function testAnAjaxLoginThroughTheWholeChainDoesNotSetTheCookie()
    {
        $user = $this->factory->user->create_and_get([
            'role'      => 'administrator',
            'user_pass' => 'correct horse battery staple',
        ]);

        $result = $this->withHeadlessAjax(function () use ($user) {
            return wp_signon([
                'user_login'    => $user->user_login,
                'user_password' => 'correct horse battery staple',
            ]);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');

        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT status FROM {$wpdb->prefix}fls_auth_logs WHERE user_id = %d",
            $user->ID
        ));

        // Neither a success (it was not) nor a failure (the password was right).
        $this->assertSame([], $rows);
    }

    public function testThePluginsOwnAjaxFormIsNotRefused()
    {
        $_REQUEST['_is_fls_form'] = 'yes';
        add_filter('wp_doing_ajax', '__return_true');

        try {
            $result = $this->handler->maybeDenyHeadlessLogin($this->user);
        } finally {
            remove_filter('wp_doing_ajax', '__return_true');
            unset($_REQUEST['_is_fls_form']);
        }

        $this->assertSame($this->user, $result);
    }

    public function testAHeadlessRefusalRaisesTheChallengeAndHandsOverTheLink()
    {
        $result = $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');

        $row = $this->pendingRowFor($this->user);
        $this->assertNotNull($row, 'The code should have been issued, not just refused');
        $this->assertSame('email_2_fa', $row->use_type);

        $url = $result->get_error_data()['challenge_url'];
        $this->assertStringContainsString('fls_2fa=email', $url);
        $this->assertStringContainsString('login_hash=' . $row->login_hash, $url);

        // A browser gets a link it can click...
        $this->assertStringContainsString('<a href="', $result->get_error_message());
        $this->assertStringContainsString('emailed you a login code', $result->get_error_message());

        // ...and a page reload is caught by the cookie.
        $this->assertSame($row->login_hash, $_COOKIE[TwoFaHandler::PENDING_COOKIE]);
    }

    public function testTheChallengeRemembersWhereTheLoginCameFrom()
    {
        // WooCommerce sends `redirect`.
        $_REQUEST['redirect'] = home_url('/my-account/');
        $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });
        $this->assertSame(home_url('/my-account/'), $this->pendingRowFor($this->user)->redirect_intend);

        // An off-site target is ignored and the page the form was on is used instead.
        unset($_REQUEST['redirect']);
        $_REQUEST['redirect_to'] = 'https://evil.example/steal';
        $_SERVER['HTTP_REFERER'] = home_url('/community/');
        $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });
        $this->assertSame(home_url('/community/'), $this->pendingRowFor($this->user)->redirect_intend);

        // Coming from the login screen itself is no destination at all.
        unset($_REQUEST['redirect_to']);
        $_SERVER['HTTP_REFERER'] = wp_login_url();
        $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });
        $this->assertSame('', $this->pendingRowFor($this->user)->redirect_intend);
    }

    /*
     * The auth cookie itself.
     */

    public function testADirectlySetAuthCookieIsWithheldWhileASecondFactorIsOwed()
    {
        $send = $this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID);

        $this->assertFalse($send);
        $this->assertTrue(TwoFaHandler::hasWithheldCookiesFor($this->user->ID));

        $row = $this->pendingRowFor($this->user);
        $this->assertNotNull($row, 'The challenge is raised so the next page can show it');
        $this->assertSame($row->login_hash, $_COOKIE[TwoFaHandler::PENDING_COOKIE]);

        // The plugin that set the cookie goes on to announce a login that did not happen.
        do_action('wp_login', $this->user->user_login, $this->user);

        $success = flsDb()->table('fls_auth_logs')
            ->where('user_id', $this->user->ID)
            ->where('status', 'success')
            ->count();
        $this->assertSame(0, $success);
    }

    public function testTheCookieGoesThroughTheWholeStackForADirectSetter()
    {
        // The test library refuses every cookie up front; step out of its way so ours
        // is the filter that decides. Headers are long gone, so nothing is actually sent.
        remove_filter('send_auth_cookies', '__return_false');

        try {
            // What FluentCommunity, FluentCart and WooCommerce do after their own checks.
            wp_set_auth_cookie($this->user->ID);
        } finally {
            add_filter('send_auth_cookies', '__return_false');
        }

        $this->assertTrue(TwoFaHandler::hasWithheldCookiesFor($this->user->ID));
        $this->assertNotNull($this->pendingRowFor($this->user));
    }

    public function testAnAuthCookieForAnAccountOwingNothingIsSent()
    {
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $this->assertTrue($this->handler->maybeWithholdAuthCookies(true, 0, 0, $subscriber->ID));
        $this->assertFalse(TwoFaHandler::hasWithheldCookiesFor($subscriber->ID));
    }

    public function testAnAuthCookieReissuedToWhoeverIsAlreadySignedInIsSent()
    {
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($this->user->ID, time() + 3600, 'logged_in');

        $this->assertTrue($this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID));
        $this->assertNull($this->pendingRowFor($this->user));
    }

    public function testClearingCookiesIsNeverInterferedWith()
    {
        // wp_clear_auth_cookie() runs the same filter with no user.
        $this->assertTrue($this->handler->maybeWithholdAuthCookies(true, 0, 0, 0));
    }

    public function testTheCookieCheckCanBeSwitchedOffByFilter()
    {
        add_filter('fluent_auth/enforce_2fa_on_auth_cookie', '__return_false');

        try {
            $this->assertTrue($this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID));
        } finally {
            remove_filter('fluent_auth/enforce_2fa_on_auth_cookie', '__return_false');
        }
    }

    /*
     * Picking the challenge up on the next page.
     */

    private function raisePendingChallenge()
    {
        $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });

        return $this->pendingRowFor($this->user);
    }

    private function arriveAt($path, $method = 'GET')
    {
        wp_set_current_user(0);
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['HTTP_HOST'] = parse_url(home_url(), PHP_URL_HOST);
        $_SERVER['REQUEST_URI'] = $path;
    }

    public function testAPendingChallengeIsShownOnTheNextPageAndReturnsThere()
    {
        $row = $this->raisePendingChallenge();
        $this->assertSame('', $row->redirect_intend);

        $this->arriveAt('/community/');

        $sentTo = $this->captureRedirect(function () {
            $this->handler->maybeResumePendingChallenge();
        });

        $this->assertNotNull($sentTo);
        $this->assertStringContainsString('login_hash=' . $row->login_hash, $sentTo);

        // Where they were going becomes where they come back to.
        $this->assertSame(home_url('/community/'), $this->pendingRowFor($this->user)->redirect_intend);

        // One shot.
        $this->assertArrayNotHasKey(TwoFaHandler::PENDING_COOKIE, $_COOKIE);
    }

    public function testAKnownDestinationIsNotOverwrittenOnResume()
    {
        $_REQUEST['redirect'] = home_url('/my-account/');
        $row = $this->raisePendingChallenge();
        unset($_REQUEST['redirect']);

        $this->arriveAt('/checkout/');
        $this->captureRedirect(function () {
            $this->handler->maybeResumePendingChallenge();
        });

        $this->assertSame(home_url('/my-account/'), $this->pendingRowFor($this->user)->redirect_intend);
    }

    public function testAPendingChallengeIsNotResumedForSomeoneAlreadySignedIn()
    {
        $this->raisePendingChallenge();

        $this->arriveAt('/community/');
        wp_set_current_user($this->user->ID);

        $sentTo = $this->captureRedirect(function () {
            $this->handler->maybeResumePendingChallenge();
        });

        $this->assertNull($sentTo);
        $this->assertArrayNotHasKey(TwoFaHandler::PENDING_COOKIE, $_COOKIE, 'Nothing left to resume');
    }

    public function testAPendingChallengeIsNotResumedOnAFormPost()
    {
        $this->raisePendingChallenge();

        $this->arriveAt('/community/', 'POST');

        $this->assertNull($this->captureRedirect(function () {
            $this->handler->maybeResumePendingChallenge();
        }));
        $this->assertArrayHasKey(TwoFaHandler::PENDING_COOKIE, $_COOKIE, 'Still waiting for a page load');
    }

    public function testAStaleCookieIsDroppedQuietly()
    {
        $_COOKIE[TwoFaHandler::PENDING_COOKIE] = 'no-such-hash';

        $this->arriveAt('/community/');

        $this->assertNull($this->captureRedirect(function () {
            $this->handler->maybeResumePendingChallenge();
        }));
        $this->assertArrayNotHasKey(TwoFaHandler::PENDING_COOKIE, $_COOKIE);
    }

    public function testAnOrdinaryPageLoginIsLeftToTheRedirect()
    {
        unset($_REQUEST['_is_fls_form']);

        $this->assertSame($this->user, $this->handler->maybeDenyHeadlessLogin($this->user));
    }

    public function testAnAccountThatOwesNoSecondFactorIsNotRefused()
    {
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $result = $this->withHeadlessAjax(function () use ($subscriber) {
            return $this->handler->maybeDenyHeadlessLogin($subscriber);
        });

        $this->assertSame($subscriber, $result);
    }

    public function testAnErrorFromEarlierInTheChainPassesThrough()
    {
        $error = new \WP_Error('incorrect_password', 'nope');

        $result = $this->withHeadlessAjax(function () use ($error) {
            return $this->handler->maybeDenyHeadlessLogin($error);
        });

        $this->assertSame($error, $result);
    }

    public function testACorrectCodeIsAccepted()
    {
        $issued = $this->issueCode();

        $response = $this->verify($issued['code'], $issued['hash']);

        $this->assertArrayHasKey('redirect', $response);
        $this->assertSame('used', $this->hashRow($issued['hash'])->status);

        // The log should say how they got in, not "web" as if the code never happened.
        $row = flsDb()->table('fls_auth_logs')
            ->where('user_id', $this->user->ID)
            ->where('status', 'success')
            ->first();
        $this->assertNotNull($row);
        $this->assertSame('two_factor_email', $row->media);
        $this->assertSame('Email code', Helper::getLoginMediaLabel($row->media));
    }

    public function testAWrongCodeIsRejectedAndCounted()
    {
        $issued = $this->issueCode();

        $response = $this->verify('000000', $issued['hash']);

        $this->assertArrayNotHasKey('redirect', $response);
        $this->assertSame(1, (int)$this->hashRow($issued['hash'])->used_count);
        $this->assertSame('issued', $this->hashRow($issued['hash'])->status);
    }

    /**
     * The whole point: the attempt cap used to sit after the code comparison, so it
     * only ever applied to a code that had already matched. A wrong code could be
     * retried without limit until it hit.
     */
    public function testCodeIsBurnedAfterMaxAttemptsAndTheRealCodeNoLongerWorks()
    {
        $issued = $this->issueCode();

        for ($i = 0; $i < TwoFaHandler::MAX_VERIFY_ATTEMPTS; $i++) {
            $response = $this->verify('000000', $issued['hash']);
            $this->assertArrayNotHasKey('redirect', $response);
        }

        $row = $this->hashRow($issued['hash']);
        $this->assertSame('failed', $row->status, 'The code must be burned');
        $this->assertSame(TwoFaHandler::MAX_VERIFY_ATTEMPTS, (int)$row->used_count);

        // Even the genuine code is dead now.
        $response = $this->verify($issued['code'], $issued['hash']);
        $this->assertArrayNotHasKey('redirect', $response);
    }

    public function testFurtherGuessesAfterTheCapDoNotKeepIncrementing()
    {
        $issued = $this->issueCode();

        for ($i = 0; $i < TwoFaHandler::MAX_VERIFY_ATTEMPTS + 4; $i++) {
            $this->verify('000000', $issued['hash']);
        }

        $this->assertSame(
            TwoFaHandler::MAX_VERIFY_ATTEMPTS,
            (int)$this->hashRow($issued['hash'])->used_count
        );
    }

    /**
     * The first factor already passed to reach 2FA, so nothing was recorded as a
     * failure. Without this the IP limit never sees the guessing at all.
     */
    public function testAFailedGuessIsRecordedForTheIpAttemptLimit()
    {
        global $wpdb;

        // A fresh logger: the plugin's own instance may have already logged this request.
        $logger = new LoginSecurityHandler();
        add_action('wp_login_failed', [$logger, 'logFailedAuth'], 10, 2);

        $issued = $this->issueCode();
        $this->verify('000000', $issued['hash']);

        remove_action('wp_login_failed', [$logger, 'logFailedAuth'], 10);

        $count = (int)$wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs
             WHERE `status` = 'failed' AND `media` = 'two_factor_email'"
        );

        $this->assertGreaterThanOrEqual(1, $count);
    }

    public function testAnExpiredCodeIsRejectedWithoutBeingCompared()
    {
        $issued = $this->issueCode();

        flsDb()->table('fls_login_hashes')
            ->where('login_hash', $issued['hash'])
            ->update(['created_at' => date('Y-m-d H:i:s', current_time('timestamp') - 11 * 60)]);

        $response = $this->verify($issued['code'], $issued['hash']);

        $this->assertArrayNotHasKey('redirect', $response);
        $this->assertSame(0, (int)$this->hashRow($issued['hash'])->used_count);
    }

    public function testAnAlreadyUsedCodeCannotBeReplayed()
    {
        $issued = $this->issueCode();

        flsDb()->table('fls_login_hashes')
            ->where('login_hash', $issued['hash'])
            ->update(['status' => 'used']);

        $response = $this->verify($issued['code'], $issued['hash']);

        $this->assertArrayNotHasKey('redirect', $response);
    }

    /**
     * Someone holding the password can trigger the 2FA mail over and over. Throttle the
     * mail, but never the enforcement - returning nothing here would let the login
     * through without a second factor at all.
     */
    public function testCodeEmailsAreThrottledWhileTwoFactorStaysEnforced()
    {
        $sent = 0;
        $counter = function ($args) use (&$sent) {
            $sent++;
            return $args;
        };
        add_filter('wp_mail', $counter);

        $returns = [];
        for ($i = 0; $i < 9; $i++) {
            $returns[] = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        }

        remove_filter('wp_mail', $counter);

        $this->assertSame(5, $sent, 'Emails stop once the request limit is passed');

        foreach ($returns as $i => $return) {
            $this->assertNotFalse($return, "Request {$i} must still enforce 2FA");
            $this->assertNotEmpty($return['login_hash']);
            $this->assertNotEmpty($return['redirect_to']);
        }
    }

    private function disableEmail2Fa()
    {
        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    /**
     * The account challenge has to work on sites that never turned email 2FA on -
     * that is the whole point of escalating instead of denying.
     */
    public function testAChallengeIssuesACodeEvenWhenEmail2FaIsOff()
    {
        $this->disableEmail2Fa();

        $this->assertFalse(
            $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both'),
            'No 2FA without a challenge when the feature is off'
        );

        add_filter('fluent_auth/2fa_challenge_required', '__return_true');
        $handler = new TwoFaHandler();
        $issued = null;
        $spy = function ($data) use (&$issued) {
            $issued = $data;
        };
        add_action('fls_send_2fa_code', $spy, 10, 1);
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        remove_action('fls_send_2fa_code', $spy, 10);
        remove_filter('fluent_auth/2fa_challenge_required', '__return_true');

        $this->assertNotFalse($return);
        $this->assertNotEmpty($return['login_hash']);

        $row = $this->hashRow($return['login_hash']);
        $this->assertSame(TwoFaHandler::CHALLENGE_USE_TYPE, $row->use_type);
        $this->assertNotEmpty($issued['two_fa_code']);
    }

    /**
     * A challenge code must stay redeemable after the attack subsides, otherwise the
     * owner is stranded holding a code the plugin no longer recognises.
     */
    public function testAChallengeCodeStillVerifiesOnceTheAttackSubsides()
    {
        $this->disableEmail2Fa();

        add_filter('fluent_auth/2fa_challenge_required', '__return_true');
        $handler = new TwoFaHandler();
        $issued = null;
        $spy = function ($data) use (&$issued) {
            $issued = $data;
        };
        add_action('fls_send_2fa_code', $spy, 10, 1);
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        remove_action('fls_send_2fa_code', $spy, 10);
        remove_filter('fluent_auth/2fa_challenge_required', '__return_true');

        // Challenge no longer required, email 2FA still off: the code must work anyway.
        $response = $this->verify($issued['two_fa_code'], $return['login_hash']);

        $this->assertArrayHasKey('redirect', $response);
        $this->assertSame('used', $this->hashRow($return['login_hash'])->status);
    }

    public function testAWrongChallengeCodeIsStillCappedAndBurned()
    {
        $this->disableEmail2Fa();

        add_filter('fluent_auth/2fa_challenge_required', '__return_true');
        $handler = new TwoFaHandler();
        $issued = null;
        $spy = function ($data) use (&$issued) {
            $issued = $data;
        };
        add_action('fls_send_2fa_code', $spy, 10, 1);
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        remove_action('fls_send_2fa_code', $spy, 10);
        remove_filter('fluent_auth/2fa_challenge_required', '__return_true');

        for ($i = 0; $i < TwoFaHandler::MAX_VERIFY_ATTEMPTS; $i++) {
            $this->verify('000000', $return['login_hash']);
        }

        $this->assertSame('failed', $this->hashRow($return['login_hash'])->status);
        $this->assertArrayNotHasKey(
            'redirect',
            $this->verify($issued['two_fa_code'], $return['login_hash'])
        );
    }

    /**
     * The magic link throttle counts rows in fls_login_hashes, which is shared with 2FA
     * and signup verification. Unscoped, an ordinary 2FA login ate into the user's
     * magic link allowance - and challenge codes would now land in that bucket too.
     */
    public function testTwoFactorCodesDoNotConsumeTheMagicLinkAllowance()
    {
        // Well past the limit of 5, but none of these are magic links.
        for ($i = 0; $i < 9; $i++) {
            $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        }

        $total = flsDb()->table('fls_login_hashes')
            ->where('ip_address', Helper::getIp())
            ->count();

        $magicOnly = flsDb()->table('fls_login_hashes')
            ->where('ip_address', Helper::getIp())
            ->where('use_type', 'magic_login')
            ->count();

        $this->assertSame(9, (int)$total, 'The unscoped count is what used to be used');
        $this->assertSame(0, (int)$magicOnly, 'Scoped, none of them touch the magic link quota');
    }

    public function testThrottledCodeStillHasToBeEnteredCorrectly()
    {
        for ($i = 0; $i < 6; $i++) {
            $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');
        }

        // The 7th is past the email throttle but must still be a working, required code.
        $issued = $this->issueCode();

        $this->assertArrayNotHasKey('redirect', $this->verify('000000', $issued['hash']));
        $this->assertArrayHasKey('redirect', $this->verify($issued['code'], $issued['hash']));
    }
}
