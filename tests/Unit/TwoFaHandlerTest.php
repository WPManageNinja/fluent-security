<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\LoginSecurityHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;

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
     * verifyChallenge() terminates through wp_send_json(); capture what it emitted.
     */
    private function verify($code, $hash)
    {
        $_REQUEST['login_passcode'] = $code;
        $_REQUEST['login_hash'] = $hash;

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        ob_start();
        try {
            $this->handler->verifyChallenge();
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

    /* ------------------------------------------------- letting a visitor through */

    /**
     * Somebody else's form, and a visitor with nothing of their own to be asked for.
     *
     * Refusing these was costing an ordinary visitor a login and handing them an error
     * telling them to finish somewhere else. They enrolled in nothing, the site requires
     * nothing of them, and they cannot publish - so what was being protected was an
     * emailed code on an account that has no other second factor to lose.
     *
     * Everything below this is a case where the answer goes back to no.
     */
    private function subscriberWithEmailCodes()
    {
        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = ['administrator', 'subscriber'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        return $this->factory->user->create_and_get(['role' => 'subscriber']);
    }

    public function testASubscriberWithNoFactorOfTheirOwnIsLetThroughAHeadlessForm()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $result = $this->withHeadlessAjax(function () use ($subscriber) {
            return $this->handler->maybeDenyHeadlessLogin($subscriber);
        });

        $this->assertSame($subscriber, $result);
        $this->assertNull($this->pendingRowFor($subscriber), 'nothing should have been raised');
    }

    /**
     * The shipped default is email codes for administrators, editors and authors with
     * nobody in the required list. Reading only the required list would have made that
     * default a way past an administrator's own second factor.
     */
    public function testAnAdministratorIsStillRefusedEvenWhenNothingIsRequiredOfThem()
    {
        $this->assertSame([], Helper::getSetting('totp_required_roles'));

        $result = $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    public function testASubscriberWhoSetUpAnAuthenticatorAppIsStillRefused()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        TotpTwoFaMethod::activate($subscriber, TotpProvider::generateSecret());

        $result = $this->withHeadlessAjax(function () use ($subscriber) {
            return $this->handler->maybeDenyHeadlessLogin($subscriber);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    public function testASubscriberTheSiteRequiresAFactorOfIsStillRefused()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $settings = Helper::getAuthSettings();
        // A requirement only stands over a method that is on - see DeviceRequirement.
        $settings['totp_2fa'] = 'yes';
        $settings['totp_required_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $result = $this->withHeadlessAjax(function () use ($subscriber) {
            return $this->handler->maybeDenyHeadlessLogin($subscriber);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    /**
     * The escalation is the one case where challenging somebody who enrolled in nothing
     * is the entire point, so it is the one case the pass-through must not cover.
     */
    /**
     * The variant the first version of this test dodged.
     *
     * It removed the subscriber from the email role list first, so the escalation had to
     * fall back to a method their roles did not have - and the guard read "under attack"
     * off exactly that fallback. With emailed codes already on for them the dispatcher
     * returns the available method, no fallback happens, and the account the site is
     * actively worried about was the one being waved through.
     */
    public function testASubscriberUnderAttackIsRefusedEvenWithEmailCodesOnForTheirRole()
    {
        $subscriber = $this->subscriberWithEmailCodes();   // subscriber IS in email2fa_roles

        add_filter('fluent_auth/2fa_challenge_required', '__return_true');
        $handler = new TwoFaHandler();

        try {
            $result = $this->withHeadlessAjax(function () use ($handler, $subscriber) {
                return $handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('fluent_auth/2fa_challenge_required', '__return_true');
        }

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    /**
     * REST has no form and no reader, so the low-privilege pass never applies to it.
     *
     * XML-RPC is tested by the same check and never arrives at it - see
     * testAnUnattendedLoginIsLetThroughWithoutMailingACode, which takes that route out
     * of this caller entirely. The check keeps both because a site that answers
     * `fluent_auth/unattended_login_request` false puts XML-RPC back here, and it should
     * land on the refusal rather than on a role test.
     *
     * Driven through the filter the production check feeds rather than by defining
     * REST_REQUEST: a constant cannot be undefined again, so defining one here would
     * silently change every test that ran afterwards in the same process.
     */
    public function testAnApiLoginIsNeverLetThrough()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        add_filter('fluent_auth/headless_pass_excludes_api', '__return_true');

        try {
            $result = $this->withHeadlessAjax(function () use ($subscriber) {
                return $this->handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('fluent_auth/headless_pass_excludes_api', '__return_true');
        }

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    /**
     * The other half of the same rule, and the half the test above cannot reach.
     *
     * Forcing the filter true proves the exclusion works but would still pass if the
     * value handed to it were hardcoded false, so this pins that the constants are what
     * actually reach it. XMLRPC_REQUEST cannot be defined here without changing every
     * test that runs afterwards in the same process.
     */
    public function testTheApiExclusionIsFedByTheRequestItself()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $seen = 'not called';
        $spy = function ($isApi) use (&$seen) {
            $seen = $isApi;
            return $isApi;
        };

        add_filter('fluent_auth/headless_pass_excludes_api', $spy);

        try {
            $this->withHeadlessAjax(function () use ($subscriber) {
                return $this->handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('fluent_auth/headless_pass_excludes_api', $spy);
        }

        $this->assertFalse($seen, 'a plain ajax login is not an API request, and the filter is told so');
    }

    /**
     * @return array the subject of every mail sent while the callback ran
     */
    private function mailsSentDuring(callable $fn)
    {
        $sent = [];

        $spy = function ($args) use (&$sent) {
            $sent[] = $args['subject'];
            return $args;
        };

        add_filter('wp_mail', $spy);

        try {
            $fn();
        } finally {
            remove_filter('wp_mail', $spy);
        }

        return $sent;
    }

    /**
     * Runs the callback as a request nobody is waiting on.
     *
     * Driven through the filter rather than by defining XMLRPC_REQUEST or WP_CLI, for
     * the reason given on testAnApiLoginIsNeverLetThrough: a constant cannot be undefined
     * again. The ajax wrapper is what makes cannotShowChallenge() answer the way
     * xmlrpc.php makes it answer in production.
     */
    private function withUnattendedRequest(callable $fn)
    {
        add_filter('fluent_auth/unattended_login_request', '__return_true');

        try {
            return $this->withHeadlessAjax($fn);
        } finally {
            remove_filter('fluent_auth/unattended_login_request', '__return_true');
        }
    }

    /**
     * A client with the right password and nobody at the keyboard - xmlrpc.php, WP-CLI,
     * cron - is let past rather than refused, and above all is not mailed a code.
     *
     * It used to be refused, which meant a code for every attempt: the client cannot read
     * a mailbox or answer a form, so it retries, and each retry mailed another code to
     * whoever owns the account. Reported as a flood of login codes nobody asked for.
     */
    public function testAnUnattendedLoginIsLetThroughWithoutMailingACode()
    {
        $result = null;

        $mails = $this->mailsSentDuring(function () use (&$result) {
            $result = $this->withUnattendedRequest(function () {
                return $this->handler->maybeDenyHeadlessLogin($this->user);
            });
        });

        $this->assertSame($this->user, $result, 'the login proceeds on the password alone');
        $this->assertNull($this->pendingRowFor($this->user), 'no challenge is raised for it');
        $this->assertSame([], $mails, 'and nothing reaches the account owner');
    }

    /**
     * The same rule at the other door: a plugin calling wp_set_auth_cookie() from a cron
     * task or a WP-CLI command. Withholding a cookie no browser will read protects
     * nothing, and the challenge raised beside it mailed a code once per run, on a timer.
     */
    public function testACookieSetWhereNobodyIsWaitingIsNotWithheld()
    {
        $send = null;

        $mails = $this->mailsSentDuring(function () use (&$send) {
            $send = $this->withUnattendedRequest(function () {
                return $this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID);
            });
        });

        $this->assertTrue($send, 'the cookie is left alone');
        $this->assertFalse(TwoFaHandler::hasWithheldCookiesFor($this->user->ID));
        $this->assertNull($this->pendingRowFor($this->user));
        $this->assertSame([], $mails);
    }

    /**
     * And at the third: maybe2FaRedirect() runs before cannotShowChallenge() can speak
     * for WP-CLI and cron, neither of which is in that list. Without the guard a sign in
     * driven from either mailed a code and then called wp_safe_redirect() and exit() in a
     * process with no browser to redirect.
     */
    public function testAnUnattendedLoginIsNotRedirectedToAChallenge()
    {
        $user = $this->user;
        $mails = [];

        $captured = $this->captureRedirect(function () use ($user, &$mails) {
            $mails = $this->mailsSentDuring(function () use ($user) {
                add_filter('fluent_auth/unattended_login_request', '__return_true');

                try {
                    $this->handler->maybe2FaRedirect($user);
                } finally {
                    remove_filter('fluent_auth/unattended_login_request', '__return_true');
                }
            });
        });

        $this->assertNull($captured, 'nothing to redirect');
        $this->assertNull($this->pendingRowFor($this->user));
        $this->assertSame([], $mails);
    }

    /**
     * Forcing the filter true proves the guard works but would pass just as well if the
     * value handed to it were hardcoded, so this pins that the request is what feeds it.
     * The constants cannot be defined here without changing every test that runs after.
     */
    public function testTheUnattendedCheckIsFedByTheRequestItself()
    {
        $seen = 'not called';

        $spy = function ($unattended) use (&$seen) {
            $seen = $unattended;
            return $unattended;
        };

        add_filter('fluent_auth/unattended_login_request', $spy);

        try {
            $this->withHeadlessAjax(function () {
                return $this->handler->maybeDenyHeadlessLogin($this->user);
            });
        } finally {
            remove_filter('fluent_auth/unattended_login_request', $spy);
        }

        $this->assertFalse($seen, 'an ajax login has a browser behind it, and the filter is told so');
    }

    /**
     * REST is the other half of the policy, and it goes the other way: the login is
     * refused, because an application password is the supported way for a client to hold
     * a session. What it must not do is mail a code - a challenge raised for a caller
     * that keeps no cookie and renders no form can never be answered, so the code only
     * ever lands in an inbox nobody asked to fill.
     */
    public function testALoginThatCannotResumeIsRefusedWithoutMailingACode()
    {
        $result = null;

        $mails = $this->mailsSentDuring(function () use (&$result) {
            add_filter('fluent_auth/2fa_challenge_resumable', '__return_false');

            try {
                $result = $this->withHeadlessAjax(function () {
                    return $this->handler->maybeDenyHeadlessLogin($this->user);
                });
            } finally {
                remove_filter('fluent_auth/2fa_challenge_resumable', '__return_false');
            }
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
        $this->assertNull($this->pendingRowFor($this->user), 'nothing to answer, so nothing is raised');
        $this->assertSame([], $mails);
        $this->assertStringContainsString('application password', $result->get_error_message());
    }

    /**
     * The half that has to keep working. Another plugin's ajax login has a real browser
     * behind it: the pending cookie carries the challenge to the next page load, so the
     * code is both answerable and wanted.
     */
    public function testAnAjaxLoginIsStillMailedItsCode()
    {
        $mails = $this->mailsSentDuring(function () {
            $this->withHeadlessAjax(function () {
                return $this->handler->maybeDenyHeadlessLogin($this->user);
            });
        });

        $this->assertCount(1, $mails);
        $this->assertNotNull($this->pendingRowFor($this->user));
    }

    /**
     * A capability that can change the site is out, and `publish_posts` alone was not
     * that line - a custom role can hold `manage_options` without it.
     */
    /**
     * allcaps is the stored capability set, not the effective one. A plugin granting a
     * capability through `user_has_cap` never touches it, so the walk alone read such a
     * user as harmless.
     */
    public function testACapabilityGrantedAtRuntimeIsStillRefused()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $grant = function ($allcaps, $caps, $args, $user) use ($subscriber) {
            if ($user && $user->ID === $subscriber->ID) {
                $allcaps['manage_options'] = true;
            }

            return $allcaps;
        };

        add_filter('user_has_cap', $grant, 10, 4);

        try {
            $result = $this->withHeadlessAjax(function () use ($subscriber) {
                return $this->handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('user_has_cap', $grant, 10);
        }

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    /** A filter returning something that is not a list must not fatal a login. */
    public function testAMalformedHarmlessCapabilityFilterDoesNotFatal()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        add_filter('fluent_auth/headless_harmless_capabilities', '__return_true');

        try {
            $result = $this->withHeadlessAjax(function () use ($subscriber) {
                return $this->handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('fluent_auth/headless_harmless_capabilities', '__return_true');
        }

        /*
         * Refused, not merely survived. `(array)true` is `[true]`, which matches no
         * capability name, so every account reads as privileged and the pass is withheld
         * - the safe direction, and worth pinning: an assertion that only says "did not
         * fatal" passes just as happily if the login were waved through instead.
         */
        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    public function testARoleThatCanManageOptionsIsStillRefused()
    {
        $subscriber = $this->subscriberWithEmailCodes();
        $subscriber->add_cap('manage_options');
        $subscriber = get_user_by('ID', $subscriber->ID);

        $result = $this->withHeadlessAjax(function () use ($subscriber) {
            return $this->handler->maybeDenyHeadlessLogin($subscriber);
        });

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    /**
     * Letting the login past the authenticate chain is only half a sign-in. The cookie
     * backstop resolves the challenge on its own, and without being told about the pass
     * it refused the cookie for the login that had just been allowed - the caller saw a
     * WP_User while the browser stayed signed out.
     */
    public function testAPassedHeadlessLoginStillGetsItsCookie()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $passed = $this->withHeadlessAjax(function () use ($subscriber) {
            return $this->handler->maybeDenyHeadlessLogin($subscriber);
        });

        $this->assertSame($subscriber, $passed, 'precondition: the login was allowed through');

        $this->assertTrue(
            $this->handler->maybeWithholdAuthCookies(true, 0, 0, $subscriber->ID),
            'the cookie has to follow the decision the login chain already made'
        );
    }

    public function testTheOldFallbackEscalationIsStillRefused()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        $settings = Helper::getAuthSettings();
        $settings['email2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        add_filter('fluent_auth/2fa_challenge_required', '__return_true');
        $handler = new TwoFaHandler();

        try {
            $result = $this->withHeadlessAjax(function () use ($handler, $subscriber) {
                return $handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('fluent_auth/2fa_challenge_required', '__return_true');
        }

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    public function testASiteCanRefuseEveryHeadlessLoginAgain()
    {
        $subscriber = $this->subscriberWithEmailCodes();

        add_filter('fluent_auth/allow_headless_login_without_challenge', '__return_false');

        try {
            $result = $this->withHeadlessAjax(function () use ($subscriber) {
                return $this->handler->maybeDenyHeadlessLogin($subscriber);
            });
        } finally {
            remove_filter('fluent_auth/allow_headless_login_without_challenge', '__return_false');
        }

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
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
        $this->assertStringContainsString('action=' . TwoFaService::LOGIN_ACTION, $url);
        $this->assertStringContainsString('login_hash=' . $row->login_hash, $url);

        // A browser gets a link it can click...
        $this->assertStringContainsString('<a href="', $result->get_error_message());
        $this->assertStringContainsString('emailed you a login code', $result->get_error_message());

        // ...and a page reload is caught by the cookie.
        $this->assertSame($row->login_hash, $_COOKIE[TwoFaHandler::PENDING_COOKIE]);
    }

    /**
     * The screen and its endpoint are reachable only under the current names - the ones
     * that shipped in 2.1.0 were replaced rather than joined. A hook name is a string
     * nothing else checks, so a typo in one would leave a challenge with no way to be
     * answered and nothing failing until somebody tried to log in.
     */
    public function testTheChallengeRouteIsRegisteredUnderItsOwnNameOnly()
    {
        $this->assertNotFalse(has_action('login_form_' . TwoFaService::LOGIN_ACTION));
        $this->assertNotFalse(has_action('wp_ajax_nopriv_' . TwoFaService::AJAX_ACTION));
        $this->assertNotFalse(has_action('wp_ajax_' . TwoFaService::AJAX_ACTION));

        $this->assertFalse(has_action('login_form_fls_2fa_email'));
        $this->assertFalse(has_action('wp_ajax_nopriv_fluent_auth_2fa_email'));
        $this->assertFalse(has_action('wp_ajax_fluent_auth_2fa_email'));

        $this->assertFalse(method_exists($this->handler, 'verify2FaEmailCode'));
        $this->assertTrue(method_exists($this->handler, 'verifyChallenge'));
    }

    /**
     * One shape, used by the redirect and by the emailed auto-login link alike.
     */
    public function testTheChallengeUrlIsShapedInOnePlace()
    {
        $url = TwoFaService::getChallengeUrl('abc');

        $this->assertStringContainsString('action=' . TwoFaService::LOGIN_ACTION, $url);
        $this->assertStringContainsString('fls_2fa=' . TwoFaService::CHALLENGE_MARKER, $url);
        $this->assertStringContainsString('login_hash=abc', $url);

        $withCode = TwoFaService::getChallengeUrl('abc', ['auto_code' => '123456']);

        $this->assertStringContainsString('auto_code=123456', $withCode);
        $this->assertStringContainsString('action=' . TwoFaService::LOGIN_ACTION, $withCode);
    }

    public function testAPlainTextHandoffCarriesAUsableUrl()
    {
        // Not ajax and not a page: what a REST client would be shown.
        $result = $this->handler->maybeDenyHeadlessLogin($this->user);
        $this->assertSame($this->user, $result, 'A page login is left to the redirect');

        $method = new \ReflectionMethod($this->handler, 'getHandoffMessage');
        $method->setAccessible(true);
        $url = \FluentAuth\App\Services\TwoFa\TwoFaService::getChallengeUrl('abc');

        add_filter('wp_doing_ajax', '__return_true');
        try {
            $html = $method->invoke($this->handler, new \FluentAuth\App\Services\TwoFa\EmailTwoFaMethod(), $url);
        } finally {
            remove_filter('wp_doing_ajax', '__return_true');
        }
        $this->assertStringContainsString('href="' . esc_url($url) . '"', $html);

        $plain = $method->invoke($this->handler, new \FluentAuth\App\Services\TwoFa\EmailTwoFaMethod(), $url);
        $this->assertStringContainsString('login_hash=abc&action=fls_2fa_verify', $plain);
        $this->assertStringNotContainsString('&#038;', $plain);
        $this->assertStringNotContainsString('<a ', $plain);
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
        // What core does on the way in when the request carries a valid cookie.
        do_action('auth_cookie_valid', [], $this->user);

        $this->assertTrue($this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID));
        $this->assertNull($this->pendingRowFor($this->user));
    }

    public function testACookieMintedInThisRequestCannotVouchForItself()
    {
        // A plugin signs the user in, writes the new cookie into $_COOKIE, and something
        // validates it - all inside the same request. That is not an arrival.
        $this->handler->rememberCookieUser('minted', 0, 0, $this->user->ID);
        do_action('auth_cookie_valid', [], $this->user);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($this->user->ID, time() + 3600, 'logged_in');

        $this->assertFalse($this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID));
        $this->assertNotNull($this->pendingRowFor($this->user));
    }

    public function testAnAdministratorMaySwitchIntoAnotherAccountWithoutItsSecondFactor()
    {
        $admin = $this->factory->user->create_and_get(['role' => 'administrator']);
        do_action('auth_cookie_valid', [], $admin);

        // User Switching, "login as customer": a cookie for somebody else.
        $this->assertTrue($this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID));
        $this->assertNull($this->pendingRowFor($this->user), 'No code is mailed to the account being entered');
    }

    public function testSomeoneWhoCannotEditTheAccountGetsNoSuchPass()
    {
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);
        do_action('auth_cookie_valid', [], $subscriber);

        $this->assertFalse($this->handler->maybeWithholdAuthCookies(true, 0, 0, $this->user->ID));
    }

    public function testReCheckingThePasswordOfWhoeverIsAlreadySignedInIsNotRefused()
    {
        do_action('auth_cookie_valid', [], $this->user);

        $result = $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });

        $this->assertSame($this->user, $result);
        $this->assertNull($this->pendingRowFor($this->user));
    }

    public function testAnApplicationPasswordLoginIsNotRefused()
    {
        // XML-RPC with an application password reaches the authenticate chain too.
        $this->handler->rememberAppPasswordAuth();

        $result = $this->withHeadlessAjax(function () {
            return $this->handler->maybeDenyHeadlessLogin($this->user);
        });

        $this->assertSame($this->user, $result);
    }

    public function testACookieRenewedAfterThisRequestsOwnCookieDiedIsStillSent()
    {
        // The request arrived signed in: core validated the cookie and said so.
        do_action('auth_cookie_valid', [], $this->user);

        // Then the password changed / the recovery sweep ran - the old cookie is dead.
        \WP_Session_Tokens::destroy_all_for_all_users();
        unset($_COOKIE[LOGGED_IN_COOKIE]);

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

    public function testResumingFromTheLoginScreenKeepsTheAdminPageAskedFor()
    {
        $row = $this->raisePendingChallenge();
        $this->assertSame('', $row->redirect_intend);

        // auth_redirect() sent them to wp-login.php?redirect_to=... first.
        $this->arriveAt('/wp-login.php');
        $GLOBALS['pagenow'] = 'wp-login.php';
        $_REQUEST['redirect_to'] = admin_url('edit.php');

        try {
            $sentTo = $this->captureRedirect(function () {
                $this->handler->maybeResumePendingChallenge();
            });
        } finally {
            $GLOBALS['pagenow'] = 'index.php';
            unset($_REQUEST['redirect_to']);
        }

        $this->assertNotNull($sentTo);
        $this->assertSame(admin_url('edit.php'), $this->pendingRowFor($this->user)->redirect_intend);
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
