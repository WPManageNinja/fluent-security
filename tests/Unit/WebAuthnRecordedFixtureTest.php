<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\WebAuthn\Assertion;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\UserHandle;

/**
 * The same checklist, against bytes real authenticators actually produced.
 *
 * WebAuthnCeremonyTest proves the checks fire. It cannot prove they fire on the right
 * things, because the ceremonies it checks were built by this codebase from its own
 * reading of the specification - so a misreading would be present in both the encoder
 * and the decoder, and would cancel out.
 *
 * These fixtures come from devices instead. Capture them with
 * bin/passkey-fixture-capture.php and drop the JSON into tests/fixtures/webauthn/.
 * The test skips rather than fails when there are none, so the suite stays green on a
 * machine with no authenticator - but a passkey release should not ship without at
 * least one platform authenticator and one password manager recorded here.
 */
class WebAuthnRecordedFixtureTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        add_filter('fluent_auth/webauthn_rp_id', [$this, 'filterRpId']);
        add_filter('fluent_auth/webauthn_allowed_origins', [$this, 'filterOrigins']);
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/webauthn_rp_id');
        remove_all_filters('fluent_auth/webauthn_allowed_origins');
        remove_all_filters('fluent_auth/webauthn_user_verification');
        parent::tearDown();
    }

    /** @var array */
    private $current = [];

    public function filterRpId()
    {
        return isset($this->current['rpId']) ? $this->current['rpId'] : '';
    }

    public function filterOrigins()
    {
        return isset($this->current['origin']) ? [$this->current['origin']] : [];
    }

    /**
     * @dataProvider recordedFixtures
     * @param $fixture array
     * @param $name string
     */
    public function test_a_recorded_ceremony_verifies($fixture, $name)
    {
        $this->current = $fixture;

        if (isset($fixture['userVerification'])) {
            add_filter('fluent_auth/webauthn_user_verification', function () use ($fixture) {
                return $fixture['userVerification'];
            });
        }

        $registrationChallenge = Base64Url::decode($fixture['registration']['challenge']);

        $verified = Registration::verify($fixture['registration']['response'], $registrationChallenge);

        $this->assertNotEmpty($verified['public_key'], $name . ': no public key was recovered');
        $this->assertContains($verified['algorithm'], [-7, -257], $name . ': unexpected algorithm');

        if (empty($fixture['assertion'])) {
            return;
        }

        $user = get_user_by('ID', $this->factory->user->create());

        // Line the stored handle up with whatever the recorded device signed.
        if (!empty($fixture['userHandle'])) {
            update_user_meta($user->ID, UserHandle::META_KEY, $fixture['userHandle']);
        }

        $credential = (object)[
            'id'            => 1,
            'user_id'       => $user->ID,
            'credential_id' => $verified['credential_id'],
            'public_key'    => $verified['public_key'],
            'algorithm'     => $verified['algorithm'],
            'sign_count'    => 0,
            'transports'    => ''
        ];

        $challenge = Base64Url::decode($fixture['assertion']['challenge']);

        $signCount = Assertion::verify($fixture['assertion']['response'], $credential, $challenge, $user);

        $this->assertIsInt($signCount, $name . ': assertion did not verify');
    }

    /**
     * @return array
     */
    public function recordedFixtures()
    {
        $directory = dirname(__DIR__) . '/fixtures/webauthn';
        $files = glob($directory . '/*.json');

        if (!$files) {
            return [];
        }

        $cases = [];

        foreach ($files as $file) {
            $fixture = json_decode(file_get_contents($file), true);

            if (!is_array($fixture) || empty($fixture['registration'])) {
                continue;
            }

            $name = isset($fixture['label']) ? $fixture['label'] : basename($file);
            $cases[$name] = [$fixture, $name];
        }

        return $cases;
    }

    /**
     * Named so that a suite with no recordings says so, rather than quietly reporting
     * that the passkey code was tested against hardware when it was not.
     */
    public function test_at_least_one_authenticator_has_been_recorded()
    {
        if (!$this->recordedFixtures()) {
            $this->markTestSkipped(
                'No recorded authenticator fixtures. Capture one with bin/passkey-fixture-capture.php.'
            );
        }

        $this->assertNotEmpty($this->recordedFixtures());
    }
}
