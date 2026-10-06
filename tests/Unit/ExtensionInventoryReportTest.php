<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * The extension inventory that travels with a report.
 *
 * Two things have to hold: the list is only carried when the relay's copy is out of date, and
 * "the relay's copy" means one it actually accepted - not one that was merely posted.
 */
class ExtensionInventoryReportTest extends BaseTestCase
{
    private function inventory($version = '1.0.0', $untracked = 3)
    {
        return [
            'extensions' => [
                ['type' => 'plugin', 'slug' => 'fluent-smtp', 'file' => 'fluent-smtp/fluent-smtp.php', 'version' => $version, 'status' => 'active', 'update_source' => true],
                ['type' => 'theme', 'slug' => 'twentytwentyfour', 'version' => '1.2', 'status' => 'active', 'update_source' => true]
            ],
            'extensions_untracked' => $untracked
        ];
    }

    private function stubInventory($inventory)
    {
        add_filter('fluent_auth/pre_report_extension_inventory', function () use ($inventory) {
            return $inventory;
        });
    }

    public function testTheHashIgnoresOrder()
    {
        $a = $this->inventory();
        $b = $a;
        $b['extensions'] = array_reverse($b['extensions']);

        $this->assertEquals(IntegrityHelper::inventoryHash($a), IntegrityHelper::inventoryHash($b));
    }

    public function testTheHashNoticesAVersionChange()
    {
        $this->assertNotEquals(
            IntegrityHelper::inventoryHash($this->inventory('1.0.0')),
            IntegrityHelper::inventoryHash($this->inventory('1.0.1'))
        );
    }

    public function testTheHashNoticesAPluginBeingDeactivated()
    {
        $off = $this->inventory();
        $off['extensions'][0]['status'] = 'inactive';

        $this->assertNotEquals(IntegrityHelper::inventoryHash($this->inventory()), IntegrityHelper::inventoryHash($off));
    }

    public function testAnUnchangedInventoryIsNotCarried()
    {
        $inventory = $this->inventory();

        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'extensions_hash' => IntegrityHelper::inventoryHash($inventory)
        ]));

        $this->stubInventory($inventory);

        $payload = IntegrityHelper::withInventory(['site_url' => 'https://example.com']);

        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $this->assertArrayNotHasKey('extensions', $payload);
    }

    public function testAChangedInventoryIsCarried()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'extensions_hash' => IntegrityHelper::inventoryHash($this->inventory('0.9.0'))
        ]));

        $this->stubInventory($this->inventory('1.0.0'));

        $payload = IntegrityHelper::withInventory([]);

        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $this->assertArrayHasKey('extensions', $payload);
        $this->assertCount(2, $payload['extensions']);
        $this->assertSame(3, $payload['extensions_untracked']);
    }

    public function testASiteThatHasNeverSentOneCarriesIt()
    {
        $this->stubInventory($this->inventory());

        $payload = IntegrityHelper::withInventory([]);

        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $this->assertArrayHasKey('extensions', $payload);
    }

    /**
     * A licence lapsing changes nothing else about an extension - same slug, same version,
     * same status - so if it did not move the hash the relay would go on believing the plugin
     * is still being offered updates, and keep counting it as checked.
     */
    public function testALicenceLapsingIsACHange()
    {
        $live = $this->inventory();
        $lapsed = $live;
        $lapsed['extensions'][0]['update_source'] = false;

        $this->assertNotEquals(IntegrityHelper::inventoryHash($live), IntegrityHelper::inventoryHash($lapsed));
    }

    /**
     * A bespoke plugin appearing changes nothing in the named list - only the number - so the
     * number has to be part of what decides whether to resend.
     */
    public function testAChangeInTheUntrackedCountAloneIsCarried()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'extensions_hash' => IntegrityHelper::inventoryHash($this->inventory('1.0.0', 3))
        ]));

        $this->stubInventory($this->inventory('1.0.0', 4));

        $payload = IntegrityHelper::withInventory([]);

        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $this->assertArrayHasKey('extensions', $payload);
        $this->assertSame(4, $payload['extensions_untracked']);
    }

    /**
     * @dataProvider deliveryProvider
     */
    public function testTheHashIsOnlyRecordedWhenTheRelayTookIt($response, $shouldRecord)
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'active', 'api_id' => 'a', 'api_key' => 'b', 'auto_scan' => 'yes'
        ]));

        $this->stubInventory($this->inventory());

        $handler = function () use ($response) {
            return $response;
        };

        add_filter('pre_http_request', $handler);
        IntegrityHelper::sendStoredReport();
        remove_filter('pre_http_request', $handler);
        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $stored = IntegrityHelper::getSettings()['extensions_hash'];

        if ($shouldRecord) {
            $this->assertEquals(IntegrityHelper::inventoryHash($this->inventory()), $stored);
        } else {
            $this->assertSame('', $stored, 'A report the relay did not take must not mark the inventory as delivered.');
        }
    }

    public function deliveryProvider()
    {
        $body = function ($code, $data = null) {
            $payload = ['status' => $code < 300 ? 'success' : 'error'];

            if ($data !== null) {
                $payload['data'] = $data;
            }

            return ['response' => ['code' => $code, 'message' => ''], 'body' => json_encode($payload), 'headers' => []];
        };

        return [
            /*
             * A 2xx is not the answer on its own. The relay used to write the inventory after
             * its response had gone out, so a successful report said nothing about whether the
             * list survived - and because it is only re-sent when its hash changes, one dropped
             * write withheld a site's plugins until it next installed one. It now files the
             * rows first and says so.
             */
            'filed'                  => [$body(200, ['extensions_accepted' => true]), true],
            'accepted but not filed' => [$body(200, ['extensions_accepted' => false]), false],
            /* A relay too old to say. Its 2xx is all there is to go on, as before. */
            'relay cannot say'       => [$body(200), true],
            'rate limited'           => [$body(429), false],
            'relay down'             => [$body(500), false],
        ];
    }

    /**
     * The direction of the failure is the point: never "believe it is filed".
     *
     * A report the relay took but could not file must leave the hash where it was, so the very
     * next scan carries the whole inventory again. The opposite mistake is silent and lasts
     * until the site's plugins happen to change.
     */
    public function testAnInventoryTheRelayCouldNotFileIsSentAgainNextTime()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'active', 'api_id' => 'a', 'api_key' => 'b', 'auto_scan' => 'yes'
        ]));

        $this->stubInventory($this->inventory());

        $sent = [];
        $refuseToFile = function ($preempt, $args) use (&$sent) {
            $sent[] = json_decode($args['body'], true);

            return [
                'response' => ['code' => 200, 'message' => ''],
                'body'     => json_encode(['status' => 'success', 'data' => ['extensions_accepted' => false]]),
                'headers'  => []
            ];
        };

        add_filter('pre_http_request', $refuseToFile, 10, 2);
        IntegrityHelper::sendStoredReport();
        IntegrityHelper::sendStoredReport();
        remove_filter('pre_http_request', $refuseToFile, 10);
        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $this->assertCount(2, $sent);
        $this->assertArrayHasKey('extensions', $sent[0]);
        $this->assertArrayHasKey('extensions', $sent[1], 'An unfiled inventory must travel again.');
    }

    public function testATransportFailureDoesNotMarkItDelivered()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'active', 'api_id' => 'a', 'api_key' => 'b', 'auto_scan' => 'yes'
        ]));

        $this->stubInventory($this->inventory());

        $handler = function () {
            return new \WP_Error('http_request_failed', 'timed out');
        };

        add_filter('pre_http_request', $handler);
        IntegrityHelper::sendStoredReport();
        remove_filter('pre_http_request', $handler);
        remove_all_filters('fluent_auth/pre_report_extension_inventory');

        $this->assertSame('', IntegrityHelper::getSettings()['extensions_hash']);
    }
}
