<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IpRules;

class IpRulesTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        delete_option(IpRules::OPTION);

        // A public address, so the proxy guard does not kick in unless a test asks for it.
        $_SERVER['REMOTE_ADDR'] = '198.51.100.20';

        $settings = get_option('__fls_auth_settings', []);
        $settings['trusted_proxies'] = '';
        $settings['proxy_ip_header'] = '';
        update_option('__fls_auth_settings', $settings);

        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR']);

        parent::tearDown();
    }

    /**
     * @param array $rules
     * @return array|\WP_Error
     */
    private function save($rules)
    {
        $result = IpRules::save($rules + ['allow' => [], 'block' => []]);

        Helper::resetStatics();

        return $result;
    }

    /* ------------------------------------------------------------------ storing */

    public function testStoresBothListsAndReportsTheCurrentAddress()
    {
        $result = $this->save([
            'allow' => ['203.0.113.0/24'],
            'block' => ['45.148.10.72']
        ]);

        $this->assertIsArray($result);
        $this->assertEquals(['203.0.113.0/24'], $result['rules']['allow']);
        $this->assertEquals(['45.148.10.72'], $result['rules']['block']);
        $this->assertEquals('198.51.100.20', $result['current_ip']);
    }

    /**
     * A text box, so the server takes the text. Splitting it in the browser and posting an
     * array would only mean trusting that the browser split it the same way.
     */
    public function testTakesAListTypedOneAddressToALine()
    {
        $result = $this->save(['allow' => "203.0.113.0/24\n198.51.100.20\n\n"]);

        $this->assertEquals(['203.0.113.0/24', '198.51.100.20'], $result['rules']['allow']);
    }

    /**
     * The screen cannot flag the line covering its reader the way a table of rows could, so
     * the one thing it needs that answer for - the restriction warning - is answered here,
     * where CIDR matching already exists rather than a second time in JavaScript.
     */
    public function testSaysWhetherTheAllowListCoversWhoeverIsReading()
    {
        $this->assertFalse($this->save(['allow' => ['203.0.113.4']])['current_ip_listed']);
        $this->assertTrue($this->save(['allow' => ['198.51.100.0/24']])['current_ip_listed']);
    }

    /**
     * These lists used to be rows carrying a label and an expiry date. An install that has
     * not saved since must keep being enforced; its first save rewrites the shape.
     */
    public function testReadsTheShapeTheListsUsedToHave()
    {
        update_option(IpRules::OPTION, [
            'allow' => [['ip' => '198.51.100.20', 'label' => 'Office', 'expires_at' => '']],
            'block' => [['ip' => '45.148.10.72', 'label' => 'Brute force', 'expires_at' => '']]
        ]);

        $this->assertEquals(['198.51.100.20'], IpRules::get()['allow']);
        $this->assertTrue(IpRules::isAllowed('198.51.100.20'));
        $this->assertTrue(IpRules::isBlocked('45.148.10.72'));
    }

    /* --------------------------------------------------------------- allow list */

    public function testAnAllowedAddressSkipsTheAttemptLimit()
    {
        $this->save(['allow' => ['198.51.100.20']]);

        $this->assertTrue(IpRules::isAllowed('198.51.100.20'));
        $this->assertFalse(IpRules::isAllowed('198.51.100.21'));
    }

    public function testAllowListUnderstandsRanges()
    {
        $this->save(['allow' => ['203.0.113.0/24']]);

        $this->assertTrue(IpRules::isAllowed('203.0.113.1'));
        $this->assertTrue(IpRules::isAllowed('203.0.113.255'));
        $this->assertFalse(IpRules::isAllowed('203.0.114.1'));
    }

    /**
     * Behind an undeclared proxy every visitor arrives as the same address, so honouring
     * the allow list would exempt everyone who can reach the site.
     */
    public function testAllowListDoesNotApplyWhileAddressesAreAmbiguous()
    {
        $this->save(['allow' => ['198.51.100.20']]);

        $this->assertTrue(IpRules::isAllowed('198.51.100.20'));

        // A request relayed from inside the network, with no proxy declared.
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.20';
        Helper::resetStatics();

        $this->assertFalse(IpRules::isAllowed('198.51.100.20'));
    }

    public function testDeclaringTheProxyBringsTheAllowListBack()
    {
        $this->save(['allow' => ['198.51.100.20']]);

        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.20';

        $settings = get_option('__fls_auth_settings');
        $settings['trusted_proxies'] = '10.0.0.0/8';
        $settings['proxy_ip_header'] = 'HTTP_X_FORWARDED_FOR';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->assertTrue(IpRules::isAllowed('198.51.100.20'));
    }

    /* --------------------------------------------------------------- block list */

    public function testABlockedAddressIsBlocked()
    {
        $this->save(['block' => ['45.148.10.0/24']]);

        $this->assertTrue(IpRules::isBlocked('45.148.10.72'));
        $this->assertFalse(IpRules::isBlocked('45.148.11.72'));
    }

    /**
     * The block list is not hedged the way the allow list is: refusing a shared address is
     * a visible inconvenience, not a silent hole, so ambiguity does not switch it off.
     */
    public function testBlockListStillAppliesWhileAddressesAreAmbiguous()
    {
        $this->save(['block' => ['45.148.10.72']]);

        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        Helper::resetStatics();

        $this->assertTrue(IpRules::isBlocked('45.148.10.72'));
    }

    public function testBlockAppendsWithoutDisturbingTheAllowList()
    {
        $this->save(['allow' => ['203.0.113.0/24']]);

        $result = IpRules::add('block', '45.148.10.72');

        $this->assertIsArray($result);
        $this->assertEquals(['203.0.113.0/24'], $result['rules']['allow']);
        $this->assertEquals(['45.148.10.72'], $result['rules']['block']);
    }

    /* -------------------------------------------------------------- validation */

    public function testRejectsThingsThatAreNotAddresses()
    {
        // Not '': an empty line is what the end of a text box looks like, and is dropped.
        foreach (['not-an-ip', '999.1.1.1', '203.0.113.0/', '203.0.113.0/abc'] as $value) {
            $this->assertWpErrorWithCode(
                $this->save(['allow' => [$value]]),
                'invalid_ip',
                $value
            );
        }
    }

    /**
     * A /0 on the allow list would switch the attempt limit off for the whole internet.
     */
    public function testRejectsAnAllowRangeThatCoversTooMuch()
    {
        foreach (['0.0.0.0/0', '10.0.0.0/8', '0.0.0.0/1'] as $range) {
            $result = $this->save(['allow' => [$range]]);

            $this->assertWPError($result, $range);
            $this->assertContains($result->get_error_code(), ['range_too_broad', 'invalid_ip'], $range);
        }

        // A /24 office and a /16 data centre are the point of the feature.
        $this->assertIsArray($this->save(['allow' => ['203.0.113.0/24']]));
        $this->assertIsArray($this->save(['allow' => ['203.0.0.0/16']]));
    }

    public function testABroadRangeIsStillAllowedOnTheBlockList()
    {
        $this->assertIsArray($this->save(['block' => ['10.0.0.0/8']]));
        $this->assertWpErrorWithCode($this->save(['block' => ['0.0.0.0/0']]), 'invalid_ip');
    }

    /**
     * The one mistake that locks an administrator out of their own site.
     */
    public function testRefusesToBlockYourOwnAddress()
    {
        $error = $this->save(['block' => ['198.51.100.20']]);

        $this->assertWpErrorWithCode($error, 'self_block');
        $this->assertEmpty(get_option(IpRules::OPTION));

        // And by range, not just exactly.
        $this->assertWpErrorWithCode($this->save(['block' => ['198.51.100.0/24']]), 'self_block');
    }

    /**
     * The same line twice is a slip in a text box, not a decision - and the box is redrawn
     * from what was stored, so collapsing them shows rather than hides.
     */
    public function testCollapsesTheSameAddressTypedTwice()
    {
        $result = $this->save(['allow' => ['203.0.113.4', ' 203.0.113.4 ']]);

        $this->assertEquals(['203.0.113.4'], $result['rules']['allow']);
    }

    public function testRejectsAListLongerThanItWillWalkOnEveryLogin()
    {
        $entries = [];

        for ($i = 0; $i < IpRules::MAX_ENTRIES + 1; $i++) {
            $entries[] = '203.0.113.' . ($i % 255);
        }

        $this->assertWpErrorWithCode($this->save(['block' => $entries]), 'too_many');
    }

    /**
     * A rejected save must leave what was already stored untouched.
     */
    public function testARejectedSaveChangesNothing()
    {
        $this->save(['allow' => ['203.0.113.0/24']]);

        $this->assertWpErrorWithCode(
            $this->save([
                'allow' => ['203.0.113.0/24'],
                'block' => ['nonsense']
            ]),
            'invalid_ip'
        );

        $stored = get_option(IpRules::OPTION);

        $this->assertEquals(['203.0.113.0/24'], $stored['allow']);
        $this->assertEmpty($stored['block']);
    }

    public function testNormalisesARangeToItsCanonicalForm()
    {
        $result = $this->save(['allow' => ['  203.0.113.0/024  ']]);

        $this->assertEquals(['203.0.113.0/24'], $result['rules']['allow']);
    }

    public function testEmptyListsMeanNothingIsExemptOrBlocked()
    {
        $this->assertFalse(IpRules::isAllowed('198.51.100.20'));
        $this->assertFalse(IpRules::isBlocked('198.51.100.20'));
    }

    /* ----------------------------------------------- allow list wins over block */

    public function testAnAddressOnBothListsIsDroppedFromTheBlockList()
    {
        $result = $this->save([
            'allow' => ['203.0.113.0/24'],
            'block' => ['203.0.113.9', '45.148.10.72']
        ]);

        $this->assertIsArray($result);
        $this->assertEquals(['45.148.10.72'], $result['rules']['block']);
        $this->assertEquals(['203.0.113.9'], $result['dropped_blocks']);

        $this->assertFalse(IpRules::isBlocked('203.0.113.9'));
    }

    public function testABlockedRangeInsideAnAllowedRangeIsDroppedToo()
    {
        $result = $this->save([
            'allow' => ['203.0.0.0/16'],
            'block' => ['203.0.113.0/24']
        ]);

        $this->assertEmpty($result['rules']['block']);
        $this->assertEquals(['203.0.113.0/24'], $result['dropped_blocks']);
    }

    public function testAddingAnAddressAlreadyCoveredIsRefusedRatherThanDuplicated()
    {
        $this->save(['allow' => ['203.0.113.0/24']]);

        $this->assertWpErrorWithCode(IpRules::add('allow', '203.0.113.9'), 'already_listed');
        $this->assertWpErrorWithCode(IpRules::add('nowhere', '203.0.113.9'), 'unknown_list');
        $this->assertWpErrorWithCode(IpRules::add('block', ''), 'invalid_ip');
    }

    /**
     * Saving both lists at once resolves an overlap quietly, but a button that says "block
     * this address" has to either block it or say why not - never report success for an
     * entry that save() is about to drop straight back off again.
     */
    public function testBlockingAnAllowedAddressIsRefusedRatherThanSilentlyDropped()
    {
        $this->save(['allow' => ['203.0.113.0/24']]);

        $error = IpRules::add('block', '203.0.113.55');

        $this->assertWpErrorWithCode($error, 'allow_list_conflict');
        $this->assertEmpty(IpRules::get()['block']);
        $this->assertFalse(IpRules::isBlocked('203.0.113.55'));
    }

    public function testAddingKeepsTheRestOfTheConfiguration()
    {
        $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator']
        ]);

        $result = IpRules::add('block', '45.148.10.72');

        $this->assertIsArray($result);
        $this->assertEquals(['administrator'], $result['restricted_roles']);
        $this->assertEquals(['198.51.100.20'], $result['rules']['allow']);
        $this->assertEquals(['45.148.10.72'], $result['rules']['block']);
    }

    /* -------------------------------------------------------- restricted roles */

    /**
     * @param string $role
     * @return \WP_User
     */
    private function userWithRole($role)
    {
        return $this->factory->user->create_and_get(['role' => $role]);
    }

    public function testARestrictedRoleIsRefusedFromAnUnlistedAddress()
    {
        $admin = $this->userWithRole('administrator');

        $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator']
        ]);

        $this->assertFalse(IpRules::deniesSignIn($admin));

        $_SERVER['REMOTE_ADDR'] = '45.148.10.72';
        Helper::resetStatics();

        $this->assertTrue(IpRules::deniesSignIn($admin));
    }

    public function testRolesThatAreNotRestrictedAreUnaffected()
    {
        $subscriber = $this->userWithRole('subscriber');

        $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator']
        ]);

        $_SERVER['REMOTE_ADDR'] = '45.148.10.72';
        Helper::resetStatics();

        $this->assertFalse(IpRules::deniesSignIn($subscriber));
    }

    public function testTheRestrictionUsesTheSameAllowListRanges()
    {
        $admin = $this->userWithRole('administrator');

        $this->save([
            'allow'            => ['198.51.100.0/24'],
            'restricted_roles' => ['administrator']
        ]);

        $_SERVER['REMOTE_ADDR'] = '198.51.100.77';
        Helper::resetStatics();
        $this->assertFalse(IpRules::deniesSignIn($admin));

        $_SERVER['REMOTE_ADDR'] = '198.51.101.77';
        Helper::resetStatics();
        $this->assertTrue(IpRules::deniesSignIn($admin));
    }

    public function testNothingIsRestrictedByDefault()
    {
        $admin = $this->userWithRole('administrator');

        $this->assertEmpty(IpRules::getRestrictedRoles());
        $this->assertFalse(IpRules::deniesSignIn($admin));
    }

    /* --------------------------------------------- refusing to lock people out */

    public function testTurningItOnFromAnAddressThatIsNotListedIsRefused()
    {
        $error = $this->save([
            'allow'            => ['203.0.113.9'],
            'restricted_roles' => ['administrator']
        ]);

        $this->assertWpErrorWithCode($error, 'would_lock_you_out');
        $this->assertEmpty(IpRules::getRestrictedRoles());
    }

    public function testRestrictingWithAnEmptyAllowListIsRefused()
    {
        $this->assertWpErrorWithCode(
            $this->save(['restricted_roles' => ['administrator']]),
            'no_allowed_addresses'
        );
    }

    public function testRestrictingIsRefusedWhileAddressesAreAmbiguous()
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.20';
        Helper::resetStatics();

        $this->assertWpErrorWithCode(
            $this->save([
                'allow'            => ['10.0.0.5'],
                'restricted_roles' => ['administrator']
            ]),
            'addresses_ambiguous'
        );
    }

    public function testUnknownRolesAreDiscarded()
    {
        $result = $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator', 'not_a_role']
        ]);

        $this->assertEquals(['administrator'], $result['restricted_roles']);
    }

    /* ------------------------------------------- failing open rather than shut */

    /**
     * Each of these would otherwise lock out every restricted role with no way back in, so
     * the restriction stands down instead. Saving refuses to create them; they can only
     * arise afterwards, when something changes underneath.
     */
    public function testTheRestrictionStandsDownIfTheAllowListEmpties()
    {
        $admin = $this->userWithRole('administrator');

        $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator']
        ]);

        $stored = get_option(IpRules::OPTION);
        $stored['allow'] = [];
        update_option(IpRules::OPTION, $stored);

        $_SERVER['REMOTE_ADDR'] = '45.148.10.72';
        Helper::resetStatics();

        $this->assertFalse(IpRules::deniesSignIn($admin));
    }

    public function testTheRestrictionStandsDownWhileAddressesAreAmbiguous()
    {
        $admin = $this->userWithRole('administrator');

        $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator']
        ]);

        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        Helper::resetStatics();

        $this->assertFalse(IpRules::deniesSignIn($admin));
    }

    public function testTheRestrictionOnlyAppliesToRealUsers()
    {
        $this->save([
            'allow'            => ['198.51.100.20'],
            'restricted_roles' => ['administrator']
        ]);

        $_SERVER['REMOTE_ADDR'] = '45.148.10.72';
        Helper::resetStatics();

        $this->assertFalse(IpRules::deniesSignIn(null));
        $this->assertFalse(IpRules::deniesSignIn(new \WP_Error('incorrect_password')));
    }
}
