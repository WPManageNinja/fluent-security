<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Optin;

/**
 * The mailing list signup.
 *
 * The rules worth holding are all about what happens when somebody says no, or when the
 * service says no: a list that records a subscriber it never delivered, or that keeps
 * asking after being told not to, is the kind of thing nobody notices until it is a
 * complaint. The optional half is here too - the environment details are the only part of
 * this that leaves a site without being asked for by name, so the test says what they are.
 */
class OptinTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        delete_option(Optin::OPTION);
        delete_option(Optin::DISMISSED_OPTION);
        delete_option('__fls_integrity_settings');
    }

    public function tearDown(): void
    {
        delete_option(Optin::OPTION);
        delete_option(Optin::DISMISSED_OPTION);
        delete_option('__fls_integrity_settings');

        parent::tearDown();
    }

    /**
     * Captures the request the signup makes instead of letting it out.
     *
     * @param int $status
     * @return array{handler: callable, sent: \ArrayObject}
     */
    private function serviceReturns($status = 200, $body = null)
    {
        $sent = new \ArrayObject();

        if ($body === null) {
            $body = ['status' => 'success', 'data' => ['optin_status' => 'pending']];
        }

        $handler = function ($preempt, $args, $url) use ($status, $body, $sent) {
            $sent['url'] = $url;
            $sent['body'] = json_decode($args['body'], true);

            return [
                'response' => ['code' => $status, 'message' => ''],
                'body'     => json_encode($body),
                'headers'  => []
            ];
        };

        add_filter('pre_http_request', $handler, 10, 3);

        return ['handler' => $handler, 'sent' => $sent];
    }

    public function test_a_fresh_site_is_asked()
    {
        $this->assertTrue(Optin::isRequired());
        $this->assertFalse(Optin::hasSubscribed());
    }

    public function test_subscribing_sends_the_address_and_stops_the_asking()
    {
        $service = $this->serviceReturns();

        $result = Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertIsArray($result);
        $this->assertTrue(Optin::hasSubscribed());
        $this->assertFalse(Optin::isRequired());

        $this->assertEquals('owner@example.com', $service['sent']['body']['email']);
        $this->assertEquals('Site Owner', $service['sent']['body']['full_name']);
        $this->assertEquals('fluentauth', $service['sent']['body']['source']);
    }

    public function test_an_invalid_address_is_never_sent_anywhere()
    {
        $reached = false;

        $handler = function () use (&$reached) {
            $reached = true;

            return ['response' => ['code' => 200, 'message' => ''], 'body' => '{}', 'headers' => []];
        };

        add_filter('pre_http_request', $handler);

        $result = Optin::subscribe('not-an-address', 'Site Owner');

        remove_filter('pre_http_request', $handler);

        $this->assertWpErrorWithCode($result, 'invalid_email');
        $this->assertFalse($reached, 'A rejected address must not leave the site.');
        $this->assertFalse(Optin::hasSubscribed());
    }

    /**
     * The one failure that cannot be found afterwards: recorded here, never received there,
     * and the site has stopped asking - so nobody is ever going to notice the gap.
     */
    public function test_a_rejected_signup_is_not_recorded_as_subscribed()
    {
        $service = $this->serviceReturns(500);

        $result = Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertWpErrorWithCode($result, 'optin_failed');
        $this->assertFalse(Optin::hasSubscribed());
        $this->assertTrue(Optin::isRequired(), 'A failed signup leaves the question open.');
    }

    public function test_a_transport_failure_is_reported_rather_than_swallowed()
    {
        $handler = function () {
            return new \WP_Error('http_request_failed', 'Connection refused');
        };

        add_filter('pre_http_request', $handler);

        $result = Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $handler);

        $this->assertWpErrorWithCode($result, 'optin_failed');
        $this->assertFalse(Optin::hasSubscribed());
    }

    public function test_the_environment_details_are_only_sent_when_asked_for()
    {
        $service = $this->serviceReturns();

        Optin::subscribe('owner@example.com', 'Site Owner', false);

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertEquals('no', $service['sent']['body']['share_essential']);
        $this->assertArrayNotHasKey('essentials', $service['sent']['body']);
        $this->assertEquals('yes', get_option(Optin::OPTION));
    }

    /**
     * The form lists these three by name. Anything added to the payload without being added
     * to that sentence is a promise broken on the screen, so the set is pinned here.
     */
    public function test_the_environment_details_are_exactly_what_the_form_lists()
    {
        $service = $this->serviceReturns();

        Optin::subscribe('owner@example.com', 'Site Owner', true);

        remove_filter('pre_http_request', $service['handler'], 10);

        $essentials = $service['sent']['body']['essentials'];

        $this->assertEquals('yes', $service['sent']['body']['share_essential']);
        $this->assertEquals(
            ['php_version', 'mysql_version', 'wp_version'],
            array_keys($essentials)
        );
        $this->assertEquals('shared', get_option(Optin::OPTION));
    }

    /**
     * No inventory of this site's plugins leaves, ticked or not.
     *
     * The checkbox offers to help us test releases against real setups, and three version
     * numbers is what that sentence covers. A list of installed plugins is a different thing
     * asked for under the same tick: not queryable on a contact record in any way that
     * decides something, readable by everyone a marketing system is readable by, and - posted
     * to an endpoint that needs no credentials - a catalogue of a site's attack surface. The
     * scanner collects that list, where the site connected for exactly that purpose.
     */
    public function test_no_inventory_of_the_installed_plugins_is_ever_sent()
    {
        /*
         * get_plugins() reads the plugins directory and caches the result under `plugins`.
         * Seeding that cache is the only way to put a known catalogue in front of it - it has
         * no filter of its own, and `all_plugins` belongs to the list table instead.
         */
        wp_cache_set('plugins', ['' => [
            'acme-widgets/acme-widgets.php' => ['Name' => 'Acme Widgets', 'Version' => '3.1.4']
        ]], 'plugins');

        update_option('active_plugins', ['acme-widgets/acme-widgets.php']);

        $service = $this->serviceReturns();

        Optin::subscribe('owner@example.com', 'Site Owner', true);

        remove_filter('pre_http_request', $service['handler'], 10);
        wp_cache_delete('plugins', 'plugins');

        $wire = json_encode($service['sent']['body']);

        $this->assertArrayNotHasKey('plugins', $service['sent']['body']['essentials']);
        $this->assertStringNotContainsString('Acme Widgets', $wire);
        $this->assertStringNotContainsString('3.1.4', $wire);
    }

    public function test_the_signup_goes_to_the_relay_and_not_to_the_crm()
    {
        $service = $this->serviceReturns();

        Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertStringContainsString('dash.fluentauth.com', (string)$service['sent']['url']);
        $this->assertStringContainsString('/optin', (string)$service['sent']['url']);
        $this->assertStringNotContainsString('fluentcrm', (string)$service['sent']['url']);
    }

    /**
     * One field, one name. Every other route this service has calls the site's address
     * `site_url`, and a second name for it across four endpoints is a mapping somebody has to
     * remember.
     */
    public function test_the_site_address_travels_under_the_name_the_relay_uses()
    {
        $service = $this->serviceReturns();

        Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertArrayHasKey('site_url', $service['sent']['body']);
        $this->assertArrayNotHasKey('optin_website', $service['sent']['body']);
    }

    /**
     * The message follows the contact's status, because the two outcomes need different
     * things said about them.
     *
     * @dataProvider contactStates
     */
    public function test_the_message_follows_the_contacts_status($sent, $expectedStatus, $mustSay, $mustNotSay)
    {
        $service = $this->serviceReturns(200, $sent);

        $result = Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $said = strtolower($result['message']);

        $this->assertEquals($expectedStatus, $result['optin_status']);
        $this->assertStringContainsString($mustSay, $said);
        $this->assertStringNotContainsString($mustNotSay, $said);
    }

    public function contactStates()
    {
        $ok = function ($status = null) {
            $body = ['status' => 'success'];

            if ($status !== null) {
                $body['data'] = ['optin_status' => $status];
            }

            return $body;
        };

        return [
            /* Already confirmed - pointing them at an inbox sends them after mail nobody sent. */
            'subscribed'         => [$ok('subscribed'), 'subscribed', 'you are subscribed', 'inbox'],
            'already_subscribed' => [$ok('already_subscribed'), 'already_subscribed', 'you are subscribed', 'inbox'],
            /* A fresh signup, with a confirmation genuinely on its way. */
            'pending'            => [$ok('pending'), 'pending', 'check your inbox', 'you are subscribed'],
            /* A relay too old to say. Pending is the ordinary outcome and the safe guess. */
            'not stated'         => [$ok(), 'pending', 'check your inbox', 'you are subscribed'],
        ];
    }

    /**
     * Said once, and then never again.
     *
     * Whether somebody goes on to click the link is between them and their inbox. The plugin
     * has no way to find out and deliberately does not ask - a site that kept showing the
     * card until an address was confirmed would be a security plugin nagging about a mailing
     * list, and an address typed wrongly is the reader's to fix, not this screen's.
     */
    public function test_an_unconfirmed_address_is_never_chased()
    {
        $service = $this->serviceReturns(200, ['status' => 'success', 'data' => ['optin_status' => 'pending']]);

        Optin::subscribe('typo@exmaple.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertTrue(Optin::hasSubscribed());
        $this->assertFalse(Optin::isRequired(), 'The card must not come back while an address sits unconfirmed.');

        /* Not even after the dismissal window it would otherwise have used. */
        update_option(Optin::DISMISSED_OPTION, time() - (365 * DAY_IN_SECONDS));

        $this->assertFalse(Optin::isRequired());
    }

    /**
     * The relay's refusals, asserted on the contract rather than the prose.
     *
     * These were captured off the running service rather than invented - a test written from
     * my own idea of somebody else's contract only ever proves my half consistent with
     * itself. But capturing the response is not the same as pinning it: `message` is display
     * text that gets reworded after a support ticket or corrected for a typo, and asserting
     * it verbatim would make their copy editor break this suite. `error_code` is the part
     * that is promised not to move, so that is what is asserted.
     *
     * Note what these refusals are *not*: unreachable. No unmodified install can provoke
     * them - `is_email()` runs first, `site_url()` is always http(s), and the source is a
     * constant - but the endpoint is public and unauthenticated, so anyone with curl is a
     * caller. They are load-bearing against exactly the traffic that is not this plugin.
     *
     * @dataProvider realRefusals
     */
    public function test_the_relays_real_refusals_are_understood($status, $body)
    {
        $service = $this->serviceReturns($status, $body);

        $result = Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        $this->assertWpErrorWithCode($result, 'optin_failed');
        $this->assertEquals($body['error_code'], $result->get_error_data()['relay_error_code']);
        $this->assertFalse(Optin::hasSubscribed(), 'A refused signup leaves the question open.');

        /* The sentence is shown, so it has to be usable - without being pinned word for word. */
        $said = $result->get_error_message();
        $this->assertNotEmpty(trim($said));
        $this->assertStringNotContainsString('%', $said, 'An unfilled placeholder reached the reader.');
        $this->assertStringNotContainsString('__', $said, 'A translation key reached the reader.');
    }

    public function realRefusals()
    {
        /* Verbatim from POST /api/v1/optin, dev and production alike. */
        return [
            'invalid_email'  => [422, ['status' => 'error', 'error_code' => 'invalid_email', 'message' => 'Please provide a valid email address.']],
            'invalid_site'   => [422, ['status' => 'error', 'error_code' => 'invalid_site', 'message' => 'Please provide the site URL as an http or https address.']],
            'invalid_source' => [422, ['status' => 'error', 'error_code' => 'invalid_source', 'message' => 'That opt-in source is not configured.']],
            'rejected'       => [422, ['status' => 'error', 'error_code' => 'rejected', 'message' => 'That mailbox does not exist.']],
            'crm_unavailable'=> [502, ['status' => 'error', 'error_code' => 'crm_unavailable', 'message' => 'The subscription service is unavailable.']],
            'rate_limited'   => [429, ['status' => 'error', 'error_code' => 'rate_limited', 'message' => 'Too many attempts. Please try again later.']],
        ];
    }

    /**
     * Two refusals that mean different things must not read the same.
     *
     * The one bug this catches that asserting each string separately would not: a copy edit
     * that collapses two causes into one sentence leaves the reader unable to tell a mistyped
     * address from a service outage, and every individual assertion still passes.
     */
    public function test_no_two_refusals_are_worded_identically()
    {
        $seen = [];

        foreach ($this->realRefusals() as $name => $case) {
            list($status, $body) = $case;

            $service = $this->serviceReturns($status, $body);
            $result = Optin::subscribe('owner@example.com', 'Site Owner');
            remove_filter('pre_http_request', $service['handler'], 10);

            $said = $result->get_error_message();

            $this->assertNotContains($said, $seen, 'Two different causes tell the reader the same thing.');
            $seen[] = $said;
        }
    }

    /* ------------------------------------------- sites that already gave us this */

    private function connectedAs($status, $email = 'owner@example.com')
    {
        $settings = \FluentAuth\App\Services\IntegrityChecker\IntegrityHelper::getSettings();
        $settings['status'] = $status;
        $settings['account_email_id'] = $email;
        \FluentAuth\App\Services\IntegrityChecker\IntegrityHelper::saveSettings($settings);
    }

    /**
     * Connecting for scan alerts posts a name and an address and confirms it by email. That is
     * a longer version of this same form, so asking again is asking somebody for something
     * they have already handed over.
     *
     * @dataProvider connectedStates
     */
    public function test_a_site_already_connected_for_alerts_is_not_asked($status)
    {
        $this->connectedAs($status);

        $this->assertFalse(Optin::isRequired(), $status . ' has already given us these details.');
    }

    public function connectedStates()
    {
        return [
            'awaiting its emailed key' => ['pending'],
            'connected'                => ['active'],
            'switched off on the dashboard, key still valid' => ['disabled'],
        ];
    }

    /**
     * Scanning with no service behind it sends nothing anywhere, so those details were never
     * given and the question is still open.
     */
    public function test_a_site_scanning_without_connecting_is_still_asked()
    {
        $this->connectedAs('self', '');

        $this->assertTrue(Optin::isRequired());
    }

    public function test_a_site_that_never_registered_is_still_asked()
    {
        $this->connectedAs('unregistered', '');

        $this->assertTrue(Optin::isRequired());
    }

    /**
     * A site connected by pasting an account-level key never sets `account_email_id`, so the
     * status has to be enough on its own.
     */
    public function test_the_status_alone_is_enough()
    {
        $this->connectedAs('active', '');

        $this->assertFalse(Optin::isRequired());
    }

    /**
     * And the reverse: an address on file means known, whatever the status says.
     */
    public function test_an_account_email_alone_is_enough()
    {
        $this->connectedAs('self', 'owner@example.com');

        $this->assertFalse(Optin::isRequired());
    }

    /**
     * Read live, not recorded. Connecting the scanner after the card has been sitting on the
     * dashboard for a week should stop it there and then.
     */
    public function test_connecting_later_stops_the_asking_from_that_moment()
    {
        $this->assertTrue(Optin::isRequired());

        $this->connectedAs('active');

        $this->assertFalse(Optin::isRequired());
    }

    /**
     * A revoked site is put back to `unregistered` with its account email cleared - the relay
     * holds nothing about it any more, so the question is open again.
     */
    public function test_a_site_the_relay_disowned_is_asked_again()
    {
        $this->connectedAs('active');
        $this->assertFalse(Optin::isRequired());

        \FluentAuth\App\Services\IntegrityChecker\IntegrityHelper::markRelayRejected(
            \FluentAuth\App\Services\IntegrityChecker\IntegrityHelper::RELAY_REVOKED
        );

        $this->assertTrue(Optin::isRequired());
    }

    public function test_declining_parks_the_question_for_a_week()
    {
        Optin::dismiss();

        $this->assertFalse(Optin::isRequired());
        $this->assertFalse(Optin::hasSubscribed(), 'Declining is not subscribing.');
    }

    public function test_the_question_comes_back_once_the_week_is_up()
    {
        update_option(Optin::DISMISSED_OPTION, time() - (Optin::DISMISS_DAYS * DAY_IN_SECONDS) - 60);

        $this->assertTrue(Optin::isRequired());
    }

    public function test_a_subscriber_is_never_asked_again_however_old_the_dismissal()
    {
        $service = $this->serviceReturns();

        Optin::subscribe('owner@example.com', 'Site Owner');

        remove_filter('pre_http_request', $service['handler'], 10);

        update_option(Optin::DISMISSED_OPTION, time() - (365 * DAY_IN_SECONDS));

        $this->assertFalse(Optin::isRequired());
    }

    public function test_a_site_can_switch_the_whole_thing_off()
    {
        $filter = function () {
            return false;
        };

        add_filter('fluent_auth/show_optin', $filter);

        $required = Optin::isRequired();

        remove_filter('fluent_auth/show_optin', $filter);

        $this->assertFalse($required);
    }
}
