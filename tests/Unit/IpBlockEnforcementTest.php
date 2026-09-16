<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\LoginSecurityHandler;
use FluentAuth\App\Services\IpRules;

/**
 * Whether a blocked address is actually blocked, on every way in rather than one of them.
 *
 * The block list is the one rule in this plugin with nothing hedged about it. Allow-listing
 * only relaxes the rate limit, and the role restriction only applies to the roles it names -
 * but a blocked address is a decision that this network does not sign in here, and a rule
 * like that is worth exactly as much as the least guarded door it applies to.
 *
 * It was enforced in one place: the function the password path calls. Two other ways in
 * skipped that function entirely - an emailed magic link, because redeeming one is not a
 * password guess and the whole rate limit is stood down for it, and social login, which
 * never enters the authenticate chain at all because it sets the cookie itself.
 *
 * So what is pinned here is the same answer from all three.
 */
class IpBlockEnforcementTest extends BaseTestCase
{
    /** @var LoginSecurityHandler */
    private $handler;

    /** @var \WP_User */
    private $user;

    const BLOCKED = '45.148.10.72';

    const ALLOWED = '198.51.100.20';

    public function setUp(): void
    {
        parent::setUp();

        $this->handler = new LoginSecurityHandler();

        delete_option(IpRules::OPTION);
        update_option(IpRules::OPTION, [
            'allow' => [],
            'block' => [['ip' => self::BLOCKED, 'label' => 'Brute force', 'expires_at' => '']]
        ], false);

        $_SERVER['REMOTE_ADDR'] = self::ALLOWED;

        $settings = get_option('__fls_auth_settings', []);
        $settings['trusted_proxies'] = '';
        $settings['proxy_ip_header'] = '';
        $settings['login_try_limit'] = 5;
        $settings['login_try_timing'] = 30;
        update_option('__fls_auth_settings', $settings, false);

        Helper::resetStatics();

        $id = $this->factory->user->create([
            'user_login' => 'blocked_probe',
            'user_email' => 'blocked_probe@example.test',
            'role'       => 'subscriber'
        ]);

        $this->user = get_user_by('ID', $id);
    }

    public function tearDown(): void
    {
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR']);
        Helper::setTokenVerifiedLogin(false);
        delete_option(IpRules::OPTION);
        delete_option('__fls_auth_settings');
        Helper::resetStatics();

        parent::tearDown();
    }

    private function comeFrom($ip)
    {
        $_SERVER['REMOTE_ADDR'] = $ip;
        Helper::resetStatics();
    }

    /* ------------------------------------------------- the password path (already worked) */

    public function testAPasswordLoginFromABlockedAddressIsRefused()
    {
        $this->comeFrom(self::BLOCKED);

        $_POST['log'] = $this->user->user_login;

        $result = $this->handler->maybeCheckLoginAttempts($this->user, $this->user->user_login, 'secret');

        $this->assertWPError($result);

        unset($_POST['log']);
    }

    public function testAPasswordLoginFromAnUnlistedAddressIsLetThrough()
    {
        $this->comeFrom(self::ALLOWED);

        $_POST['log'] = $this->user->user_login;

        $result = $this->handler->maybeCheckLoginAttempts($this->user, $this->user->user_login, 'secret');

        $this->assertNotWPError($result);

        unset($_POST['log']);
    }

    /* ----------------------------------------------------------------- the emailed link */

    /**
     * The exemption that let this through. Redeeming a magic link stands the rate limit
     * down, which is right - somebody reading their own inbox is not guessing a password -
     * and it used to stand the block list down with it, because the two lived in the same
     * function. An attacker who could read the mailbox could then sign in from an address
     * the owner had explicitly blocked, which is the exact thing the list was written for.
     */
    public function testAMagicLinkDoesNotCarryABlockedAddressPastTheBlockList()
    {
        $this->comeFrom(self::BLOCKED);

        Helper::setTokenVerifiedLogin(true);

        $_POST['log'] = $this->user->user_login;

        $result = $this->handler->maybeCheckLoginAttempts($this->user, $this->user->user_login, '');

        $this->assertWPError($result, 'an emailed link must not be a way around the block list');

        unset($_POST['log']);
    }

    /**
     * And the exemption it was written for still holds: the rate limit is stood down, so a
     * link redeemed from an address that is merely over its attempt budget still works.
     */
    public function testAMagicLinkIsStillExemptFromTheRateLimit()
    {
        $this->comeFrom(self::ALLOWED);

        for ($i = 0; $i < 12; $i++) {
            flsDb()->table('fls_auth_logs')->insert([
                'username'   => $this->user->user_login,
                'ip'         => self::ALLOWED,
                'status'     => 'failed',
                'created_at' => current_time('mysql'),
                'updated_at' => current_time('mysql')
            ]);
        }

        Helper::setTokenVerifiedLogin(true);

        $_POST['log'] = $this->user->user_login;

        $result = $this->handler->maybeCheckLoginAttempts($this->user, $this->user->user_login, '');

        $this->assertNotWPError($result);

        unset($_POST['log']);

        flsDb()->table('fls_auth_logs')->where('username', $this->user->user_login)->delete();
    }

    /* ------------------------------------------------------------------ social login */

    /**
     * Social login never reaches the authenticate chain - AuthService sets the cookie
     * itself - so this filter is the only thing it asks. The role restriction was carried
     * across to it when it was written; the block list was not.
     */
    public function testSocialLoginIsRefusedFromABlockedAddress()
    {
        $this->comeFrom(self::BLOCKED);

        $result = $this->handler->maybeDenyRestrictedLocation(true, $this->user, 'google');

        $this->assertWPError($result);
    }

    /**
     * The no-provider call answers with a plain false rather than an error object, because
     * that is what its caller reads - an error returned there is truthy enough to be
     * mistaken for permission.
     */
    public function testSocialLoginWithNoProviderAnswersWithAPlainFalse()
    {
        $this->comeFrom(self::BLOCKED);

        $result = $this->handler->maybeDenyRestrictedLocation(true, $this->user);

        $this->assertFalse($result);
    }

    public function testSocialLoginFromAnUnlistedAddressIsUntouched()
    {
        $this->comeFrom(self::ALLOWED);

        $this->assertTrue($this->handler->maybeDenyRestrictedLocation(true, $this->user, 'google'));
    }

    /**
     * A refusal that was already decided elsewhere is passed through rather than reopened.
     */
    public function testAnExistingRefusalIsLeftAlone()
    {
        $this->comeFrom(self::ALLOWED);

        $this->assertFalse($this->handler->maybeDenyRestrictedLocation(false, $this->user, 'google'));
    }
}
