<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * A connection made against the alerts service that dash.fluentauth.com replaced.
 *
 * Both services kept their credentials in the same option under the same two keys, so an
 * update carries the old pair forward untouched and the site goes on calling itself connected
 * while nothing it sends can be accepted. Nothing else here finds that out reliably: the only
 * other route is being refused mid-report, and the scheduled report will not run at all unless
 * `auto_scan` is on - which on the old service was a separate switch, off by default.
 *
 * The test is a shape test, and these cases are about where it is allowed to conclude
 * anything at all. Getting it wrong in the other direction destroys a working credential that
 * can only be replaced by registering again by email.
 */
class LegacyConnectionTest extends BaseTestCase
{
    /**
     * The shape the relay actually mints - `mintApiId()` and `mintSiteKey()` in its
     * src/lib/keys.ts. Any pair the service has ever issued looks like this.
     */
    const CURRENT_ID = 'site_aB3xK9mQ2pL7vR4tY6nZ';

    const CURRENT_KEY = 'fask_7hJ2kL9mN4pQ8rS3tV6wX1yZ5aB0cD7eF4gH';

    /**
     * The shape the old service actually issued, which is a UUID for both halves.
     *
     * Not a guess. Checked against the whole of that service's `registrations` table (the
     * `fluent_auth_api_tokens` D1, 2,917 rows): every `api_id` and every `api_token` in it is
     * a 36-character UUID, and not one of them begins with either prefix the current relay
     * mints. So the shape test below is confirmed against the entire real population rather
     * than against a plausible-looking fixture - there is no old credential anywhere that it
     * reads as current.
     */
    const OLD_ID = '7f3a91c2-4b8e-4d1a-9c55-2e6b0f8a1d37';

    const OLD_KEY = 'c4d81f06-93ae-4b57-8e2a-1d7f60b9a534';

    private function connectedWith($apiId, $apiKey, $extra = [])
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), array_merge([
            'status'           => 'active',
            'api_id'           => $apiId,
            'api_key'          => $apiKey,
            'account_email_id' => 'owner@example.com',
            'auto_scan'        => 'yes'
        ], $extra)));
    }

    public function testACurrentCredentialIsLeftAlone()
    {
        $this->connectedWith(self::CURRENT_ID, self::CURRENT_KEY);

        $this->assertFalse(IntegrityHelper::maybeRetireLegacyConnection());

        $settings = IntegrityHelper::getSettings();

        $this->assertSame('active', $settings['status']);
        $this->assertSame(self::CURRENT_ID, $settings['api_id']);
        $this->assertSame(self::CURRENT_KEY, $settings['api_key']);
        $this->assertSame('', $settings['relay_rejection']);
    }

    public function testAPairFromTheOldServiceIsRetired()
    {
        $this->connectedWith(self::OLD_ID, self::OLD_KEY);

        $this->assertTrue(IntegrityHelper::maybeRetireLegacyConnection());

        $settings = IntegrityHelper::getSettings();

        $this->assertSame('unregistered', $settings['status']);
        $this->assertSame(IntegrityHelper::RELAY_LEGACY, $settings['relay_rejection']);
        $this->assertSame('', $settings['api_id']);
        $this->assertSame('', $settings['api_key']);
        $this->assertSame('no', $settings['auto_scan']);
    }

    /**
     * The id survives the credential, in the field nothing acts on. It is the only record of
     * what this site was connected as - the screen is what decides not to offer it to support.
     */
    public function testTheRetiredIdIsKept()
    {
        $this->connectedWith(self::OLD_ID, self::OLD_KEY);

        IntegrityHelper::maybeRetireLegacyConnection();

        $this->assertSame(
            self::OLD_ID,
            IntegrityHelper::getSettings()['relay_retired_api_id']
        );
    }

    /**
     * The case nothing else reaches. A site left at `pending` by the old service never posts a
     * report, so the refusal path cannot fire, and it would sit for ever on a screen asking
     * for an emailed key that can no longer be redeemed anywhere.
     */
    public function testASiteStillWaitingForItsOldKeyIsRetired()
    {
        $this->connectedWith(self::OLD_ID, '', [
            'status'    => 'pending',
            'auto_scan' => 'no'
        ]);

        $this->assertTrue(IntegrityHelper::maybeRetireLegacyConnection());
        $this->assertSame('unregistered', IntegrityHelper::getSettings()['status']);
    }

    /**
     * Registered against the current relay and not yet confirmed. There is no key to look at,
     * so the id has to be the whole answer - and it says this one is fine.
     */
    public function testASiteWaitingForACurrentKeyIsLeftAlone()
    {
        $this->connectedWith(self::CURRENT_ID, '', [
            'status'    => 'pending',
            'auto_scan' => 'no'
        ]);

        $this->assertFalse(IntegrityHelper::maybeRetireLegacyConnection());
        $this->assertSame('pending', IntegrityHelper::getSettings()['status']);
    }

    public function testASiteThatNeverConnectedIsLeftAlone()
    {
        $this->connectedWith('', '', ['status' => 'unregistered', 'auto_scan' => 'no']);

        $this->assertFalse(IntegrityHelper::maybeRetireLegacyConnection());
        $this->assertSame('', IntegrityHelper::getSettings()['relay_rejection']);
    }

    /**
     * Scanning without the service at all. There are no credentials, and a site that chose
     * this is not waiting to be told about a move it was never part of.
     */
    public function testASelfManagedSiteIsLeftAlone()
    {
        $this->connectedWith('', '', ['status' => 'self', 'auto_scan' => 'no']);

        $this->assertFalse(IntegrityHelper::maybeRetireLegacyConnection());
        $this->assertSame('self', IntegrityHelper::getSettings()['status']);
    }

    /**
     * The guard that keeps this from being a claim about somebody else's service.
     *
     * A self-hosted relay behind `fluent_auth/alerts_api_url` mints its own tokens in whatever
     * shape it likes. Reading ours into them would disconnect every such install on update
     * day, for a reason none of them could act on.
     */
    public function testAnInstallPointedAtItsOwnRelayIsNeverRetired()
    {
        $this->connectedWith(self::OLD_ID, self::OLD_KEY);

        $filter = function () {
            return 'https://relay.example.com/api/v1/';
        };

        add_filter('fluent_auth/alerts_api_url', $filter);

        try {
            $this->assertFalse(IntegrityHelper::maybeRetireLegacyConnection());
            $this->assertSame('active', IntegrityHelper::getSettings()['status']);
        } finally {
            remove_filter('fluent_auth/alerts_api_url', $filter);
        }
    }

    /**
     * Retiring twice must not be a second event. Once the credential is gone there is nothing
     * left to recognise, and a guard that fired again on every admin page load would write the
     * rejection over itself for ever.
     */
    public function testRetiringIsIdempotent()
    {
        $this->connectedWith(self::OLD_ID, self::OLD_KEY);

        $this->assertTrue(IntegrityHelper::maybeRetireLegacyConnection());

        $first = IntegrityHelper::getSettings()['relay_rejected_at'];

        $this->assertFalse(IntegrityHelper::maybeRetireLegacyConnection());
        $this->assertSame($first, IntegrityHelper::getSettings()['relay_rejected_at']);
    }

    /**
     * Reconnecting has to clear it, or the screen goes on explaining a move to a site that has
     * already come through it. `withRelayRejectionCleared()` is the one list every reconnect
     * path runs through, which is what makes this true for all of them at once.
     */
    public function testReconnectingClearsTheRetirement()
    {
        $this->connectedWith(self::OLD_ID, self::OLD_KEY);

        IntegrityHelper::maybeRetireLegacyConnection();

        $settings = IntegrityHelper::withRelayRejectionCleared(IntegrityHelper::getSettings());

        $this->assertSame('', $settings['relay_rejection']);
        $this->assertSame('', $settings['relay_retired_api_id']);
    }

    /**
     * The key is a secret, and a retired one is still a secret. Whatever else the screen is
     * told about this, it is not told that.
     */
    public function testTheRetiredKeyNeverReachesTheBrowser()
    {
        $this->connectedWith(self::OLD_ID, self::OLD_KEY);

        IntegrityHelper::maybeRetireLegacyConnection();

        $public = IntegrityHelper::getPublicSettings();

        $this->assertArrayNotHasKey('api_key', $public);
        $this->assertFalse($public['has_api_key']);
    }
}
