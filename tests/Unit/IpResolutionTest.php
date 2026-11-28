<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;

/**
 * REMOTE_ADDR is the only value a client cannot forge. Everything here is about when
 * the plugin is allowed to believe something else instead.
 */
class IpResolutionTest extends BaseTestCase
{
    private $serverBackup;

    public function setUp(): void
    {
        parent::setUp();

        $this->serverBackup = $_SERVER;

        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR'] as $key) {
            unset($_SERVER[$key]);
        }

        $this->setTrustedProxies('');
    }

    public function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
        parent::tearDown();
    }

    private function setTrustedProxies($value, $header = '')
    {
        $settings = Helper::getAuthSettings();
        $settings['trusted_proxies'] = $value;
        $settings['proxy_ip_header'] = $header;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    // ---------------------------------------------------------------- CF ranges

    public function testCloudflareIpv4EdgesAreRecognised()
    {
        $this->assertTrue(Helper::isCfIp('172.68.1.1'));
        $this->assertTrue(Helper::isCfIp('104.16.0.1'));
        $this->assertTrue(Helper::isCfIp('131.0.72.0'));
        $this->assertTrue(Helper::isCfIp('131.0.75.255'));
    }

    /**
     * These used to all return false: the v6 ranges were missing and the matcher was
     * built on ip2long(), which cannot represent an IPv6 address at all.
     */
    public function testCloudflareIpv6EdgesAreRecognised()
    {
        $this->assertTrue(Helper::isCfIp('2606:4700::1111'));
        $this->assertTrue(Helper::isCfIp('2400:cb00::1'));
        $this->assertTrue(Helper::isCfIp('2a06:98c0::1'));
        $this->assertTrue(Helper::isCfIp('2c0f:f248::abcd'));
    }

    public function testNonCloudflareAddressesAreRejected()
    {
        $this->assertFalse(Helper::isCfIp('8.8.8.8'));
        $this->assertFalse(Helper::isCfIp('131.0.76.0'));   // just past 131.0.72.0/22
        $this->assertFalse(Helper::isCfIp('131.0.71.255'));  // just before it
        $this->assertFalse(Helper::isCfIp('2001:4860:4860::8888'));
        $this->assertFalse(Helper::isCfIp('not-an-ip'));
        $this->assertFalse(Helper::isCfIp(''));
    }

    public function testCloudflareRangesAreFilterable()
    {
        $filter = function ($ranges) {
            return array_merge($ranges, ['198.51.100.0/24']);
        };

        add_filter('fluent_auth/cloudflare_ip_ranges', $filter);
        $result = Helper::isCfIp('198.51.100.7');
        remove_filter('fluent_auth/cloudflare_ip_ranges', $filter);

        $this->assertTrue($result);
    }

    // ------------------------------------------------------------ no proxy set

    /**
     * The headline fix: with nothing configured, a forwarded header is just noise.
     */
    public function testForwardedHeadersAreIgnoredWithoutTrustedProxies()
    {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_CLIENT_IP'] = '8.8.8.8';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9';

        $this->assertSame('127.0.0.1', Helper::getIp());
    }

    public function testAnAttackerCannotClaimAVictimsAddress()
    {
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_CLIENT_IP'] = '203.0.113.50';   // the victim

        $this->assertNotSame('203.0.113.50', Helper::getIp());
        $this->assertSame('127.0.0.1', Helper::getIp());
    }

    // ------------------------------------------------------------- cloudflare

    public function testCloudflareVisitorIpIsUsedForAnIpv4Edge()
    {
        $_SERVER['REMOTE_ADDR'] = '172.68.1.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    public function testCloudflareVisitorIpIsUsedForAnIpv6Edge()
    {
        $_SERVER['REMOTE_ADDR'] = '2606:4700::1111';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    public function testCloudflareHeaderIsIgnoredFromANonCloudflareConnection()
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.4';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';

        $this->assertSame('198.51.100.4', Helper::getIp());
    }

    public function testAGarbageCloudflareHeaderFallsBackToTheConnection()
    {
        $_SERVER['REMOTE_ADDR'] = '172.68.1.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = 'not-an-ip-at-all';

        $this->assertSame('172.68.1.1', Helper::getIp());
    }

    // ---------------------------------------------------------- declared proxy

    public function testDeclaredProxyIsBelieved()
    {
        $this->setTrustedProxies('127.0.0.1');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    public function testDeclaredProxyAcceptsCidrRanges()
    {
        $this->setTrustedProxies('10.0.0.0/8');

        $_SERVER['REMOTE_ADDR'] = '10.4.5.6';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    /**
     * (int) on the suffix made each of these /0, so one typo trusted every IPv4 client.
     * An IPv4 value in the header is then skipped as "one of ours" too, which is why the
     * claimed address here is IPv6: that is the one a client could pick freely, a new one
     * per request to step around the attempt limit.
     */
    public function testAMalformedCidrSuffixTrustsNobody()
    {
        foreach (['10.0.0.1/foo', '10.0.0.1/', '10.0.0.1/-1', '10.0.0.1/8a'] as $entry) {
            $this->setTrustedProxies($entry);

            $_SERVER['REMOTE_ADDR'] = '198.51.100.4';
            $_SERVER['HTTP_X_FORWARDED_FOR'] = '2001:db8::9';

            $this->assertSame('198.51.100.4', Helper::getIp(), $entry);
        }
    }

    public function testHeaderFromAnUndeclaredAddressIsStillIgnored()
    {
        $this->setTrustedProxies('10.0.0.0/8');

        $_SERVER['REMOTE_ADDR'] = '198.51.100.4';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';

        $this->assertSame('198.51.100.4', Helper::getIp());
    }

    /**
     * A client can prepend entries to X-Forwarded-For before it ever reaches the proxy,
     * so the leftmost value is attacker controlled. Walking in from the right past our
     * own proxies lands on the first hop we did not add ourselves.
     */
    public function testSpoofedEntriesPrependedToTheChainAreSkipped()
    {
        $this->setTrustedProxies('127.0.0.1, 10.0.0.0/8');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 203.0.113.9, 10.0.0.7';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    public function testChainOfOnlyTrustedProxiesFallsBackToTheConnection()
    {
        $this->setTrustedProxies('127.0.0.1, 10.0.0.0/8');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.7, 10.0.0.8';

        $this->assertSame('127.0.0.1', Helper::getIp());
    }

    public function testACustomProxyHeaderCanBeNamed()
    {
        $this->setTrustedProxies('127.0.0.1', 'X-Real-IP');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_REAL_IP'] = '203.0.113.9';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    public function testHeaderNameIsAcceptedInEitherForm()
    {
        $this->setTrustedProxies('127.0.0.1', 'HTTP_X_REAL_IP');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_REAL_IP'] = '203.0.113.9';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    /**
     * Cloudflare in front of a local proxy: REMOTE_ADDR is the local hop, so the CF
     * range check cannot pass and the declared proxy has to carry it.
     */
    public function testCloudflareBehindALocalProxyStillResolvesTheVisitor()
    {
        $this->setTrustedProxies('127.0.0.1', 'CF-Connecting-IP');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';

        $this->assertSame('203.0.113.9', Helper::getIp());
    }

    // ----------------------------------------------------------------- general

    public function testPortsAreStripped()
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.4:54321';
        $this->assertSame('198.51.100.4', Helper::getIp());

        Helper::resetStatics();
        $_SERVER['REMOTE_ADDR'] = '[2001:db8::1]:54321';
        $this->assertSame('2001:db8::1', Helper::getIp());
    }

    public function testCliRequestsWithoutAConnectionFallBackToLocalhost()
    {
        unset($_SERVER['REMOTE_ADDR']);

        $this->assertSame('127.0.0.1', Helper::getIp());
    }

    public function testTheUserIpFilterStillWins()
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.4';

        $filter = function () {
            return '203.0.113.77';
        };

        add_filter('fluent_auth/user_ip', $filter);
        Helper::resetStatics();
        $result = Helper::getIp();
        remove_filter('fluent_auth/user_ip', $filter);

        $this->assertSame('203.0.113.77', $result);
    }

    public function testAnonymisationIsAppliedOnEveryCallNotJustTheFirst()
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.4';

        $this->assertSame('198.51.100.4', Helper::getIp());
        // Used to return the raw address here because the memo short circuited first.
        $this->assertSame('198.51.100.0', Helper::getIp(true));
    }
}
