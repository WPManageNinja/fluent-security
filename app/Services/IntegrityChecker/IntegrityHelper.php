<?php

namespace FluentAuth\App\Services\IntegrityChecker;


use FluentAuth\App\Helpers\Arr;

class IntegrityHelper
{
    public static function getSettings()
    {
        $defaults = [
            'status'           => 'unregistered',
            'api_id'           => '',
            'api_key'          => '',
            'last_checked'     => '',
            'account_email_id' => '',
            'is_ok'            => 'yes',
            'auto_scan'        => 'no',
            'scan_interval'    => 'daily',
            'last_report_sent' => ''
        ];

        $settings = get_option('__fls_integrity_settings', []);

        if (empty($settings)) {
            return $defaults;
        }

        $settings = wp_parse_args($settings, $defaults);

        return $settings;
    }

    public static function saveSettings($settings)
    {
        return update_option('__fls_integrity_settings', $settings, false);
    }

    public static function getIgnoreLists()
    {
        $ignoreLists = get_option('__fls_integrity_ignore_lists', []);

        $defaults = [
            'files'   => [],
            'folders' => []
        ];

        if (empty($ignoreLists)) {
            return $defaults;
        }

        return wp_parse_args($ignoreLists, $defaults);
    }

    public static function updateIgnoreLists($ignoreLists)
    {
        return update_option('__fls_integrity_ignore_lists', $ignoreLists, false);
    }

    public static function maybeSendScanReport()
    {
        $settings = self::getSettings();
        if ($settings['auto_scan'] != 'yes') {
            return;
        }

        $scanInterval = $settings['scan_interval'];

        if ($scanInterval == 'hourly') {
            $interval = 3600;
        } else {
            $interval = 84600; // 23.5 hours
        }

        if ($settings['last_report_sent'] && (time() - strtotime($settings['last_report_sent'])) < $interval) {
            return;
        }

        try {
            $checkerService = new CheckerService();
        } catch (\Exception $exception) {
            // error happended
            return false;
        }

        $modifiedFiles = $checkerService->getActiveModifiedFiles(false);
        $modifiedFolders = $checkerService->getActiveModifiedFolders();

        $settings['last_report_sent'] = date('Y-m-d H:i:s');
        $settings['last_checked'] = date('Y-m-d H:i:s');
        $settings['is_ok'] = (!$modifiedFolders && !$modifiedFiles) ? 'yes' : 'no';
        self::saveSettings($settings);

        if ($settings['is_ok'] === 'yes') {
            return false;
        }

        $payload = [
            'api_key'          => $settings['api_key'],
            'api_id'           => $settings['api_id'],
            'user_email'       => Arr::get($settings, 'account_email_id'),
            'site_url'         => str_replace(['https://', 'http://'], '', site_url()),
            'admin_url'        => admin_url('admin.php?page=fluent-auth#/'),
            'site_title'       => get_bloginfo('name'),
            'modified_files'   => $modifiedFiles,
            'modified_folders' => $modifiedFolders
        ];

        return Api::sendPostRequest('send-security-email/', $payload);
    }
}
