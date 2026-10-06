<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\MagicLoginHandler;

/**
 * Signing in with an emailed link.
 *
 * The promise this feature makes is printed in the email itself - "this link will expire in
 * ten minutes and can only be used once" - and both halves of that sentence live in
 * makeLogin(). Neither had a test.
 *
 * The single-use half was also not quite true. The row was read as `issued`, the sign-in
 * happened, and only then was it written back as `used`, so two requests arriving together
 * both read an unspent link and both went through. It is now claimed in one statement
 * before anything else, and what is pinned here is that the loser of that race is refused.
 */
class MagicLoginTest extends BaseTestCase
{
    /** @var MagicLoginHandler */
    private $handler;

    /** @var \WP_User */
    private $user;

    public function setUp(): void
    {
        parent::setUp();

        $this->handler = new MagicLoginHandler();

        $settings = get_option('__fls_auth_settings', []);
        $settings['magic_login'] = 'yes';
        $settings['magic_restricted_roles'] = [];
        update_option('__fls_auth_settings', $settings, false);

        Helper::resetStatics();

        $_SERVER['REMOTE_ADDR'] = '198.51.100.20';

        $id = $this->factory->user->create([
            'user_login' => 'magic_probe',
            'user_email' => 'magic_probe@example.test',
            'role'       => 'subscriber'
        ]);

        $this->user = get_user_by('ID', $id);
    }

    public function tearDown(): void
    {
        wp_set_current_user(0);
        unset($_SERVER['REMOTE_ADDR']);
        flsDb()->table('fls_login_hashes')->where('use_type', 'magic_login')->delete();
        delete_option('__fls_auth_settings');
        Helper::resetStatics();

        parent::tearDown();
    }

    /**
     * @param int $validity minutes
     * @return string the `<secret>:<rowId>` pair that travels in the emailed URL
     */
    private function issueLink($validity = 10)
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'generateHash');

        return $method->invoke($this->handler, $this->user, $validity, '');
    }

    private function rowFor($link)
    {
        $parts = explode(':', $link);

        return flsDb()->table('fls_login_hashes')->where('id', end($parts))->first();
    }

    /* ------------------------------------------------------------------- the token */

    public function testTheTokenIsLongAndUnpredictable()
    {
        $seen = [];

        for ($i = 0; $i < 25; $i++) {
            $secret = strtok($this->issueLink(), ':');

            $this->assertSame(64, strlen($secret), 'a 32 byte token, hex encoded');
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $secret);

            $seen[$secret] = true;
        }

        $this->assertCount(25, $seen, 'no two links are the same');
    }

    /**
     * Only the hash is kept. Somebody reading the table must not be able to sign in from it.
     */
    public function testTheTokenItselfIsNeverStored()
    {
        $link = $this->issueLink();
        $secret = strtok($link, ':');
        $row = $this->rowFor($link);

        $this->assertNotEmpty($row->login_hash);
        $this->assertNotSame($secret, $row->login_hash);
        $this->assertStringNotContainsString($secret, $row->login_hash);
        $this->assertSame('issued', $row->status);
    }

    /* ------------------------------------------------------------------ redeeming */

    public function testAValidLinkSignsThePersonIn()
    {
        $link = $this->issueLink();

        $this->assertTrue($this->handler->makeLogin($link));
        $this->assertSame($this->user->ID, get_current_user_id());
        $this->assertSame('used', $this->rowFor($link)->status);
    }

    /**
     * The half the email promises out loud.
     */
    public function testALinkCannotBeUsedTwice()
    {
        $link = $this->issueLink();

        $this->assertTrue($this->handler->makeLogin($link));

        wp_set_current_user(0);

        $this->assertFalse($this->handler->makeLogin($link), 'a spent link is refused');
        $this->assertSame(0, get_current_user_id());
    }

    /**
     * The race the claim closes. Two requests carrying the same link used to read it as
     * unspent together, because the row was only written back after the sign-in finished.
     * Marking the row `used` first is exactly what the winner of the race does, so a second
     * attempt against that state is the loser's view of it.
     */
    public function testTheLoserOfASimultaneousRedemptionIsRefused()
    {
        $link = $this->issueLink();
        $row = $this->rowFor($link);

        /* What the other request has just done, one statement ahead of this one. */
        flsDb()->table('fls_login_hashes')
            ->where('id', $row->id)
            ->update(['status' => 'used']);

        $this->assertFalse($this->handler->makeLogin($link));
        $this->assertSame(0, get_current_user_id());
    }

    public function testAnExpiredLinkIsRefusedAndMarkedExpired()
    {
        $link = $this->issueLink();
        $row = $this->rowFor($link);

        flsDb()->table('fls_login_hashes')
            ->where('id', $row->id)
            ->update(['valid_till' => date('Y-m-d H:i:s', current_time('timestamp') - 60)]);

        $this->assertFalse($this->handler->makeLogin($link));
        $this->assertSame(0, get_current_user_id());
        $this->assertSame('expired', $this->rowFor($link)->status);
    }

    public function testAWrongSecretAgainstARealRowIsRefused()
    {
        $link = $this->issueLink();
        $parts = explode(':', $link);

        $this->assertFalse($this->handler->makeLogin(bin2hex(random_bytes(32)) . ':' . $parts[1]));
        $this->assertSame(0, get_current_user_id());

        /* And the real link still works afterwards - a wrong guess must not burn it. */
        $this->assertTrue($this->handler->makeLogin($link));
    }

    public function testAMalformedLinkIsRefused()
    {
        $this->assertFalse($this->handler->makeLogin('nonsense'));
        $this->assertFalse($this->handler->makeLogin(''));
        $this->assertSame(0, get_current_user_id());
    }

    public function testNothingIsIssuedWhenTheFeatureIsOff()
    {
        $settings = get_option('__fls_auth_settings', []);
        $settings['magic_login'] = 'no';
        update_option('__fls_auth_settings', $settings, false);
        Helper::resetStatics();

        $method = new \ReflectionMethod(MagicLoginHandler::class, 'generateHash');

        $this->assertFalse($method->invoke($this->handler, $this->user, 10, ''));
    }

    /**
     * A link issued while the feature was on must stop working when it is turned off.
     */
    public function testAnAlreadyIssuedLinkStopsWorkingWhenTheFeatureIsTurnedOff()
    {
        $link = $this->issueLink();

        $settings = get_option('__fls_auth_settings', []);
        $settings['magic_login'] = 'no';
        update_option('__fls_auth_settings', $settings, false);
        Helper::resetStatics();

        $this->assertFalse($this->handler->makeLogin($link));
        $this->assertSame(0, get_current_user_id());
    }

    /**
     * A role the site has excluded from magic login cannot redeem one either, not just be
     * refused when asking for it.
     */
    public function testARestrictedRoleCannotRedeemALink()
    {
        $link = $this->issueLink();

        $settings = get_option('__fls_auth_settings', []);
        $settings['magic_restricted_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings, false);
        Helper::resetStatics();

        $this->assertFalse($this->handler->makeLogin($link));
        $this->assertSame(0, get_current_user_id());
    }

    /* ------------------------------------------------------- what the form gives away */

    /**
     * The confirmation is the same sentence whether or not the account exists, and it
     * quotes back what was typed rather than anything read off an account.
     */
    public function testTheConfirmationDoesNotRevealWhetherAnAccountExists()
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'sentConfirmation');

        $real = $method->invoke($this->handler, 'magic_probe@example.test');
        $fake = $method->invoke($this->handler, 'nobody-here@example.test');

        $this->assertSame($real['heading'], $fake['heading']);
        $this->assertTrue($real['result']);
        $this->assertTrue($fake['result']);
        $this->assertStringContainsString('magic_probe@example.test', $real['message']);
        $this->assertStringContainsString('nobody-here@example.test', $fake['message']);

        /* Same shape, same wording - only the address typed in differs. */
        $this->assertSame(
            str_replace('magic_probe@example.test', 'X', $real['message']),
            str_replace('nobody-here@example.test', 'X', $fake['message'])
        );
    }

    /**
     * The confirmation quotes back what was typed, and the browser puts that message into
     * innerHTML - so what may be quoted matters. Only a value that passes is_email() is,
     * and nothing carrying markup does; everything else gets the sentence with no address
     * in it at all.
     */
    public function testNothingCarryingMarkupIsEverQuotedBack()
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'sentConfirmation');

        foreach ([
            '<img src=x onerror=alert(1)>@example.test',
            '"><script>alert(1)</script>',
            'a@b.c<x',
            '<b>bold</b>'
        ] as $typed) {
            $message = $method->invoke($this->handler, sanitize_text_field($typed))['message'];

            $this->assertStringNotContainsString('<', $message, $typed);
            $this->assertStringNotContainsString('>', $message, $typed);
        }

        /* And an ordinary address still is, or the message stops being useful. */
        $this->assertStringContainsString(
            'someone@example.test',
            $method->invoke($this->handler, 'someone@example.test')['message']
        );
    }

    /**
     * Probing for an address that does not exist has to cost the same as asking for a real
     * one. The allowance is counted in rows of this table, and before this a refused
     * request wrote none - so enumerating accounts was free and unlimited.
     */
    public function testARefusedRequestStillSpendsFromTheAllowance()
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'recordMagicProbe');

        $before = $this->countRecent();

        $method->invoke($this->handler);

        $this->assertSame($before + 1, $this->countRecent());
    }

    /**
     * And what it writes must never be a way in: no user, and a status nothing redeems.
     */
    public function testTheRecordedProbeIsNotRedeemable()
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'recordMagicProbe');
        $method->invoke($this->handler);

        $row = flsDb()->table('fls_login_hashes')
            ->where('status', 'probe')
            ->orderBy('id', 'DESC')
            ->first();

        $this->assertNotEmpty($row);
        $this->assertEquals(0, $row->user_id);
        $this->assertSame('probe', $row->status);
        $this->assertFalse($this->handler->makeLogin($row->login_hash . ':' . $row->id));
        $this->assertSame(0, get_current_user_id());
    }

    /* ------------------------------------------------------------ where it lands */

    /**
     * The link points at the site root, not index.php: hosts that rewrite index.php away
     * answer the old form with a 301 before WordPress ever sees the token.
     */
    public function testTheLinkPointsAtTheSiteRoot()
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'getMagicLoginUrl');

        $url = $method->invoke($this->handler, $this->user, 10);

        $this->assertStringStartsWith(site_url('/') . '?', $url);
        $this->assertStringNotContainsString('index.php', $url);
        $this->assertStringContainsString('fls_al=', $url);
    }

    /**
     * Where they asked to go when they requested the link is where the link takes them.
     */
    public function testARedeemedLinkGoesWhereThePersonAskedToGo()
    {
        $link = $this->issueLinkTo(home_url('/account/'));

        $this->assertSame(home_url('/account/'), $this->redeemAndCaptureRedirect($link));
    }

    /**
     * And it goes through login_redirect on the way, as a password sign-in does.
     */
    public function testLoginRedirectStillDecidesForAStoredDestination()
    {
        $link = $this->issueLinkTo(home_url('/account/'));

        $seen = [];
        $filter = function ($to, $requested, $user) use (&$seen) {
            $seen[] = [$to, $requested, $user instanceof \WP_User ? $user->ID : null];
            return home_url('/members/');
        };

        add_filter('login_redirect', $filter, 10, 3);
        $landed = $this->redeemAndCaptureRedirect($link);
        remove_filter('login_redirect', $filter, 10);

        $this->assertSame(home_url('/members/'), $landed);
        $this->assertSame([[home_url('/account/'), home_url('/account/'), $this->user->ID]], $seen);
    }

    public function testWithoutAStoredDestinationLoginRedirectDecides()
    {
        $link = $this->issueLink();

        $filter = function () {
            return home_url('/dashboard/');
        };

        add_filter('login_redirect', $filter);
        $landed = $this->redeemAndCaptureRedirect($link);
        remove_filter('login_redirect', $filter);

        $this->assertSame(home_url('/dashboard/'), $landed);
    }

    /**
     * A filter sending the person off the site is still caught by wp_safe_redirect().
     */
    public function testAFilterCannotSendThePersonOffSite()
    {
        $link = $this->issueLinkTo(home_url('/account/'));

        $filter = function () {
            return 'https://elsewhere.example.net/';
        };

        add_filter('login_redirect', $filter);
        $landed = $this->redeemAndCaptureRedirect($link);
        remove_filter('login_redirect', $filter);

        $this->assertSame(admin_url(), $landed);
    }

    /* --------------------------------------------------------------- Wordfence */

    /**
     * Wordfence Login Security's CAPTCHA is waived for the sign-in a claimed link makes -
     * inside wp_signon(), where Wordfence asks - and nowhere else.
     */
    public function testWordfenceCaptchaIsWaivedOnlyInsideTheLinksOwnSignIn()
    {
        $askedDuringSignIn = null;
        $probe = function ($user) use (&$askedDuringSignIn) {
            $askedDuringSignIn = apply_filters('wordfence_ls_require_captcha', true);
            return $user;
        };

        add_filter('authenticate', $probe, 25);
        $this->assertTrue($this->handler->makeLogin($this->issueLink()));
        remove_filter('authenticate', $probe, 25);

        $this->assertFalse($askedDuringSignIn, 'waived while the link signs in');
        $this->assertTrue(apply_filters('wordfence_ls_require_captcha', true), 'and restored afterwards');
    }

    /**
     * The request carrying `fls_al` is not what earns the waiver. If it were, adding
     * `?fls_al=x` to a password POST at wp-login.php would switch the CAPTCHA off.
     */
    public function testABogusLinkDoesNotSwitchTheCaptchaOff()
    {
        $this->handler->register();

        $_GET['fls_al'] = 'not-a-real-token:999999';

        $asked = null;
        $probe = function ($user) use (&$asked) {
            $asked = apply_filters('wordfence_ls_require_captcha', true);
            return $user;
        };

        try {
            do_action('init');

            add_filter('authenticate', $probe, 25);
            wp_signon(['user_login' => 'magic_probe', 'user_password' => 'a guess']);
        } finally {
            remove_filter('authenticate', $probe, 25);
            unset($_GET['fls_al']);
        }

        $this->assertTrue($asked, 'a password sign-in alongside ?fls_al still has to pass the CAPTCHA');
        $this->assertSame(0, get_current_user_id());
    }

    /* ------------------------------------------------------- requesting a link */

    /**
     * With nothing asked for, nothing is stored: login_redirect decides once, at redeem,
     * for the person who actually signed in - not ahead of time for nobody.
     */
    public function testRequestingALinkWithNoDestinationStoresNone()
    {
        $calls = 0;
        $count = function ($to) use (&$calls) {
            $calls++;
            return $to;
        };

        add_filter('login_redirect', $count);
        $row = $this->requestLink();
        remove_filter('login_redirect', $count);

        $this->assertSame('', (string)$row->redirect_intend);
        $this->assertSame(0, $calls, 'login_redirect is not run while sending');
    }

    public function testRequestingALinkKeepsThePostedDestination()
    {
        $row = $this->requestLink(['redirect_to' => home_url('/checkout/')]);

        $this->assertSame(home_url('/checkout/'), $row->redirect_intend);
    }

    /**
     * Where rememberRedirect() said they were headed goes into the link, so opening it on
     * another device - which has no such cookie - still lands there.
     */
    public function testRequestingALinkCarriesTheRememberedDestination()
    {
        $_COOKIE['_fls_redirect_to'] = home_url('/course/42/');

        try {
            $row = $this->requestLink();
        } finally {
            unset($_COOKIE['_fls_redirect_to']);
        }

        $this->assertSame(home_url('/course/42/'), $row->redirect_intend);
    }

    public function testARememberedDestinationOffTheSiteIsNotStored()
    {
        $_COOKIE['_fls_redirect_to'] = 'https://elsewhere.example.net/';

        try {
            $row = $this->requestLink();
        } finally {
            unset($_COOKIE['_fls_redirect_to']);
        }

        $this->assertSame('', (string)$row->redirect_intend);
    }

    /**
     * Drives handleMagicLoginAjax() the way the form does and returns the row it issued.
     */
    private function requestLink(array $request = [])
    {
        $_REQUEST = array_merge([
            'email'  => 'magic_probe@example.test',
            '_nonce' => wp_create_nonce('fls_magic_logon_nonce')
        ], $request);

        $die = function () {
            return function () {
                throw new \WPDieException('sent');
            };
        };

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', $die);

        try {
            ob_start();
            $this->handler->handleMagicLoginAjax();
        } catch (\WPDieException $e) {
            // Expected: wp_send_json() ends in wp_die().
        } finally {
            ob_end_clean();
            remove_filter('wp_doing_ajax', '__return_true');
            remove_filter('wp_die_ajax_handler', $die);
            $_REQUEST = [];
        }

        $row = flsDb()->table('fls_login_hashes')
            ->where('user_id', $this->user->ID)
            ->where('status', 'issued')
            ->orderBy('id', 'DESC')
            ->first();

        $this->assertNotEmpty($row, 'a link was issued');

        return $row;
    }

    private function issueLinkTo($destination)
    {
        $method = new \ReflectionMethod(MagicLoginHandler::class, 'generateHash');

        return $method->invoke($this->handler, $this->user, 10, $destination);
    }

    /**
     * makeLogin() ends in exit() when it redirects, so the redirect is intercepted at the
     * filter and thrown out of.
     *
     * @return string|null
     */
    private function redeemAndCaptureRedirect($link)
    {
        $captured = null;

        $catch = function ($location) use (&$captured) {
            $captured = $location;
            throw new \RuntimeException('redirected');
        };

        $_GET['force_redirect'] = 'yes';
        add_filter('wp_redirect', $catch);

        try {
            $this->handler->makeLogin($link);
        } catch (\RuntimeException $e) {
            // Expected: this is how the exit() below the redirect is escaped.
        } finally {
            remove_filter('wp_redirect', $catch);
            unset($_GET['force_redirect']);
        }

        return $captured;
    }

    private function countRecent()
    {
        return flsDb()->table('fls_login_hashes')
            ->where('ip_address', Helper::getIp())
            ->where('use_type', 'magic_login')
            ->where('created_at', '>', date('Y-m-d H:i:s', current_time('timestamp') - 1800))
            ->count();
    }
}
