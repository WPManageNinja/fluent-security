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
                ['type' => 'plugin', 'slug' => 'fluent-smtp', 'file' => 'fluent-smtp/fluent-smtp.php', 'version' => $version, 'status' => 'active'],
                ['type' => 'theme', 'slug' => 'twentytwentyfour', 'version' => '1.2', 'status' => 'active']
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
        $body = function ($code) {
            return ['response' => ['code' => $code, 'message' => ''], 'body' => json_encode(['status' => 'success']), 'headers' => []];
        };

        return [
            'accepted'    => [$body(200), true],
            'rate limited' => [$body(429), false],
            'relay down'  => [$body(500), false],
        ];
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
