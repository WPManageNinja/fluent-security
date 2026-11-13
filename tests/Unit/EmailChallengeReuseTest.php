<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;

class EmailChallengeReuseTest extends BaseTestCase
{
    private $user;
    private $request;
    private $server;
    private $sent;
    private $capture;

    public function setUp(): void
    {
        parent::setUp();
        $this->request = $_REQUEST;
        $this->server = $_SERVER;
        $_REQUEST = [];
        $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
        $this->user = $this->factory->user->create_and_get(['role' => 'subscriber']);
        $this->sent = 0;
        $this->capture = function () { $this->sent++; };
        add_action('fls_send_2fa_code', $this->capture);
        add_filter('pre_wp_mail', '__return_true');
    }

    public function tearDown(): void
    {
        remove_action('fls_send_2fa_code', $this->capture);
        remove_filter('pre_wp_mail', '__return_true');
        $_REQUEST = $this->request;
        $_SERVER = $this->server;
        parent::tearDown();
    }

    private function issue($redirect = '/destination', $method = null)
    {
        return (new TwoFaHandler())->sendAndGet2FaConfirmFormUrl(
            $this->user, 'both', $redirect, $method ?: new EmailTwoFaMethod()
        );
    }

    public function testIdenticalSubmissionsShareOneChallengeWithoutResettingIt()
    {
        $mailCount = 0;
        $captureMail = function ($result) use (&$mailCount) { $mailCount++; return $result; };
        add_filter('pre_wp_mail', $captureMail, 20);
        try {
            $first = $this->issue();
            $query = flsDb()->table('fls_login_hashes')->where('login_hash', $first['login_hash']);
            $query->update(['used_count' => 2]);
            $before = flsDb()->table('fls_login_hashes')->where('login_hash', $first['login_hash'])->first();
            $this->assertSame($first, $this->issue(), 'Identical submissions must share their challenge URL and hash.');
            $after = flsDb()->table('fls_login_hashes')->where('login_hash', $first['login_hash'])->first();
            $this->assertEquals($before, $after, 'Reuse must not refresh expiry, timestamps, or the guess budget.');
            $this->assertSame(1, $this->sent, 'Only one email dispatch action should run.');
            $this->assertSame(1, (int) flsDb()->table('fls_login_hashes')->where('user_id', $this->user->ID)->count());
            $this->assertLessThanOrEqual(100, strlen($first['login_hash']));
            $this->assertSame(1, $mailCount, 'One actual wp_mail call for a fresh account, even with duplicate submissions.');
        } finally {
            remove_filter('pre_wp_mail', $captureMail, 20);
        }
    }

    /** @dataProvider distinctContexts */
    public function testDifferentContextsDoNotShareChallenges($context)
    {
        $first = $this->issue();
        $redirect = '/destination';
        if ($context === 'ip') {
            $_SERVER['REMOTE_ADDR'] = '192.0.2.2';
            Helper::resetStatics();
        } elseif ($context === 'remember') {
            $_REQUEST['rememberme'] = 'forever';
        } elseif ($context === 'redirect') {
            $redirect = '/elsewhere';
        } elseif ($context === 'email') {
            $this->user->user_email = 'changed@example.test';
        } elseif ($context === 'password') {
            $this->user->user_pass = wp_hash_password('changed-password');
        } elseif ($context === 'user') {
            $this->user = $this->factory->user->create_and_get(['role' => 'subscriber']);
        }
        $this->assertNotSame($first['login_hash'], $this->issue($redirect)['login_hash']);
        $this->assertSame(2, $this->sent);
    }

    public static function distinctContexts()
    {
        return array_map(function ($value) { return [$value]; }, ['ip', 'remember', 'redirect', 'email', 'password', 'user']);
    }

    /** @dataProvider unusableChallenges */
    public function testUnusableChallengesAreNotReused($changes)
    {
        $first = $this->issue();
        $now = current_time('timestamp');
        if (isset($changes['age'])) {
            $changes = ['created_at' => date('Y-m-d H:i:s', $now - $changes['age'])];
        } elseif (isset($changes['expired'])) {
            $changes = ['valid_till' => date('Y-m-d H:i:s', $now - 1)];
        }
        flsDb()->table('fls_login_hashes')->where('login_hash', $first['login_hash'])->update($changes);
        $this->assertNotSame($first['login_hash'], $this->issue()['login_hash']);
        $this->assertSame(2, $this->sent);
    }

    public static function unusableChallenges()
    {
        return [[['age' => 6]], [['expired' => true]], [['status' => 'used']], [['status' => 'expired']], [['used_count' => 5]]];
    }

    public function testCustomEmailMethodsKeepTheirIssuanceSemantics()
    {
        $method = new class extends EmailTwoFaMethod {};
        $first = $this->issue('/destination', $method);
        $this->assertNotSame($first['login_hash'], $this->issue('/destination', $method)['login_hash']);
        $this->assertSame(2, $this->sent);
    }

    public function testForcedChallengesAreReusedSeparatelyFromRoleChallenges()
    {
        $ordinary = $this->issue();
        add_filter('fluent_auth/2fa_challenge_required', '__return_true');
        try {
            $forced = $this->issue();
            $this->assertNotSame($ordinary['login_hash'], $forced['login_hash']);
            $this->assertSame($forced, $this->issue());
            $row = flsDb()->table('fls_login_hashes')->where('login_hash', $forced['login_hash'])->first();
            $this->assertSame('2fa_challenge', $row->use_type);
        } finally {
            remove_filter('fluent_auth/2fa_challenge_required', '__return_true');
        }
    }

    public function testLockFailureStopsIssuanceWithoutSendingMail()
    {
        $failLock = function ($sql) {
            return strpos($sql, 'SELECT GET_LOCK(') === 0 ? 'SELECT 0' : $sql;
        };
        add_filter('query', $failLock);
        try {
            $this->issue();
            $this->fail('Lock failure must stop sign-in rather than return no challenge.');
        } catch (\WPDieException $exception) {
            $this->assertStringContainsString('Please try again.', $exception->getMessage());
            $this->assertSame(0, $this->sent);
            $this->assertSame(0, (int) flsDb()->table('fls_login_hashes')->where('user_id', $this->user->ID)->count());
        } finally {
            remove_filter('query', $failLock);
        }
    }

    public function testLegacyHashIsStillAnswerableAndIsNotRepurposed()
    {
        $method = new EmailTwoFaMethod();
        $challenge = $method->prepareChallenge($this->user);
        $legacy = array_merge($challenge['columns'], [
            'login_hash' => 'legacy-opaque-hash-auth', 'user_id' => $this->user->ID,
            'use_type' => 'email_2_fa', 'status' => 'issued', 'created_at' => current_time('mysql')
        ]);
        flsDb()->table('fls_login_hashes')->insert($legacy);
        $before = flsDb()->table('fls_login_hashes')->where('login_hash', $legacy['login_hash'])->first();
        $this->assertNotSame($legacy['login_hash'], $this->issue()['login_hash']);
        $after = flsDb()->table('fls_login_hashes')->where('login_hash', $legacy['login_hash'])->first();
        $this->assertEquals($before, $after);
        $this->assertTrue($method->verifyProof($this->user, $after, ['login_passcode' => $challenge['secret']]));
    }
}
