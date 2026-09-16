<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;

/**
 * How many two-factor code emails one account can be made to receive.
 *
 * The limiter read the login attempt settings, which are about something else: how many
 * wrong passwords an address may try. A site is entitled to turn that off - behind a WAF,
 * or on a login page nobody else can reach - and doing so used to remove the only bound on
 * how many code emails somebody holding a password could send into the account holder's
 * inbox. Every password submission raises one, including the ones that never touch the
 * login form.
 *
 * So the settings may tighten this and may not remove it. What is pinned here is that both
 * gates are live at once and the first one reached is the one that stops the send.
 */
class EmailCodeRequestLimitTest extends BaseTestCase
{
    /** @var \WP_User */
    private $user;

    /** @var EmailTwoFaMethod */
    private $method;

    public function setUp(): void
    {
        parent::setUp();

        $this->method = new EmailTwoFaMethod();

        $id = $this->factory->user->create([
            'user_login' => 'code_limit_probe',
            'user_email' => 'code_limit_probe@example.test',
            'role'       => 'subscriber'
        ]);

        $this->user = get_user_by('ID', $id);

        flsDb()->table('fls_login_hashes')->where('user_id', $this->user->ID)->delete();
    }

    public function tearDown(): void
    {
        flsDb()->table('fls_login_hashes')->where('user_id', $this->user->ID)->delete();
        delete_option('__fls_auth_settings');
        \FluentAuth\App\Helpers\Helper::resetStatics();

        parent::tearDown();
    }

    /**
     * @param int $count how many codes to record as already sent
     * @param int $minutesAgo
     */
    private function recordSentCodes($count, $minutesAgo = 1)
    {
        $when = date('Y-m-d H:i:s', current_time('timestamp') - $minutesAgo * 60);

        for ($i = 0; $i < $count; $i++) {
            flsDb()->table('fls_login_hashes')->insert([
                'login_hash' => 'probe-' . $i . '-' . wp_generate_password(12, false),
                'user_id'    => $this->user->ID,
                'use_type'   => $this->method->getKey(),
                'status'     => 'issued',
                'created_at' => $when,
                'updated_at' => $when
            ]);
        }
    }

    private function limitReached()
    {
        $reflection = new \ReflectionMethod(EmailTwoFaMethod::class, 'hasReachedCodeRequestLimit');

        return $reflection->invoke($this->method, $this->user);
    }

    private function setLoginLimits($limit, $timing)
    {
        update_option('__fls_auth_settings', [
            'login_try_limit'  => $limit,
            'login_try_timing' => $timing
        ], false);

        \FluentAuth\App\Helpers\Helper::resetStatics();
    }

    public function testNothingSentYetIsUnderEveryLimit()
    {
        $this->setLoginLimits(5, 10);

        $this->assertFalse($this->limitReached());
    }

    public function testTheSettingsLimitStillApplies()
    {
        $this->setLoginLimits(3, 10);
        $this->recordSentCodes(4);

        $this->assertTrue($this->limitReached());
    }

    /**
     * The one that was missing. With the attempt limit switched off there was no bound at
     * all, and an unbounded number of emails into somebody's inbox is the whole attack.
     */
    public function testTurningTheLoginAttemptLimitOffDoesNotRemoveTheBound()
    {
        $this->setLoginLimits(0, 0);

        $this->recordSentCodes(5);
        $this->assertFalse($this->limitReached(), 'an ordinary number of codes still goes out');

        $this->recordSentCodes(20);
        $this->assertTrue($this->limitReached(), 'a flood is stopped even with the attempt limit off');
    }

    /**
     * A generous setting must not raise the floor above itself either - the two gates are
     * independent, and whichever is reached first is the one that stops the send.
     */
    public function testAVeryLooseSettingIsStillCaughtByTheFloor()
    {
        $this->setLoginLimits(5000, 10);

        $this->recordSentCodes(25);

        $this->assertTrue($this->limitReached());
    }

    /**
     * Only what was sent recently counts, or an account that used two-factor normally for a
     * year would eventually stop receiving codes.
     */
    public function testOldCodesDoNotCountAgainstTheFloor()
    {
        $this->setLoginLimits(0, 0);

        $this->recordSentCodes(30, 24 * 60);

        $this->assertFalse($this->limitReached());
    }

    public function testTheFloorCanBeLiftedByFilterForASiteThatMeansIt()
    {
        $this->setLoginLimits(0, 0);
        $this->recordSentCodes(20);

        $this->assertTrue($this->limitReached());

        $raise = function () {
            return 100;
        };

        add_filter('fluent_auth/2fa_code_request_floor_limit', $raise);

        $this->assertFalse($this->limitReached());

        remove_filter('fluent_auth/2fa_code_request_floor_limit', $raise);
    }
}
