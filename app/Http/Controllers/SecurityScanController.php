<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\IntegrityChecker\Api;
use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

class SecurityScanController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        $settings = IntegrityHelper::getSettings();

        if ($settings['last_checked']) {
            $settings['last_checked_human'] = human_time_diff(strtotime($settings['last_checked']), current_time('timestamp'));
        }

        return [
            'settings' => $settings,
            'ignores'  => IntegrityHelper::getIgnoreLists(),
        ];
    }

    public static function registerSite(\WP_REST_Request $request)
    {
        if ($request->get_param('status') == 'self') {
            $defaults = [
                'status'           => 'self',
                'api_id'           => '',
                'api_key'          => '',
                'last_checked'     => '',
                'account_email_id' => '',
                'is_ok'            => 'yes',
                'auto_scan'        => 'no',
                'scan_interval'    => 'daily',
                'last_report_sent' => ''
            ];

            IntegrityHelper::saveSettings($defaults);

            return [
                'message' => __('Your settings has been saved successfully.', 'fluent-security'),
            ];

        }

        $info = $request->get_param('info');

        if (!is_array($info)) {
            $info = [];
        }

        // Validate the data
        $infoData = [
            'email'     => sanitize_email(Arr::get($info, 'email', '')),
            'full_name' => sanitize_text_field(Arr::get($info, 'full_name', '')),
            'api_id'    => sanitize_text_field(Arr::get($info, 'api_id', '')),
            'api_key'   => sanitize_text_field(Arr::get($info, 'api_key', ''))
        ];

        if (!is_email($infoData['email']) || empty($infoData['full_name'])) {
            return new \WP_Error('invalid_data', __('Please provide a valid email address and full name.', 'fluent-security'), ['status' => 400, 'data' => $infoData]);
        }

        $status = $request->get_param('status');

        $settings = IntegrityHelper::getSettings();
        $isConfirmed = false;
        if ($status == 'unregistered') {
            $apiId = Api::registerSite($infoData);
        } else {
            $infoData['api_id'] = $settings['api_id'];
            $apiId = Api::confirmSite($infoData);
            $isConfirmed = true;
        }

        if (is_wp_error($apiId)) {
            return $apiId;
        }

        if ($isConfirmed) {
            $settings['api_key'] = $infoData['api_key'];
            $settings['status'] = 'active';
        } else {
            $settings['api_id'] = $apiId;
            $settings['status'] = 'pending';
            $settings['account_email_id'] = $infoData['email'];
        }

        IntegrityHelper::saveSettings($settings);

        return [
            'message'  => 'Your site has been successfully registered. Please provide the API token.',
            'settings' => $settings
        ];

    }

    public static function scanSite(\WP_REST_Request $request)
    {
        $settings = IntegrityHelper::getSettings();
        $settings['last_checked'] = date('Y-m-d H:i:s');
        $settings['is_ok'] = 'yes';
        IntegrityHelper::saveSettings($settings);

        try {
            $checkerService = new CheckerService();
        } catch (\Exception $e) {
            return new \WP_Error('invalid_response', __('An error occurred while scanning the site. If you continously get this error, please reconnect the API.', 'fluent-security'), ['status' => 422, 'data' => $e->getMessage()]);
        }

        $scanResults = $checkerService->getScanResults(false);
        $activeChanges = $checkerService->getScanResults(true);

        $hasIssues = array_filter($activeChanges);
        $settings['last_checked'] = date('Y-m-d H:i:s');
        if ($hasIssues) {
            $settings['is_ok'] = 'no';
        }

        IntegrityHelper::saveSettings($settings);

        return [
            'scan_results'  => $scanResults,
            'activeChanges' => $activeChanges,
            'hasIssues'     => !!array_filter($scanResults),
            'willAlert'     => !!array_filter($activeChanges)
        ];
    }

    public static function toggleIgnore(\WP_REST_Request $request)
    {
        $willRemove = $request->get_param('will_remove') == 'yes';
        $file = $request->get_param('file');

        if (!is_string($file) || empty($file)) {
            return new \WP_Error('invalid_data', __('Please provide a valid file name.', 'fluent-security'), ['status' => 400, 'data' => $file]);
        }

        $isFolder = $request->get_param('is_folder') == 'yes';

        $settings = IntegrityHelper::getIgnoreLists();

        if ($isFolder) {
            $ignoreLists = $settings['folders'];
        } else {
            $ignoreLists = $settings['files'];
        }

        if ($willRemove) {
            $ignoreLists = array_diff($ignoreLists, [$file]);
        } else {
            $ignoreLists[] = $file;
        }

        if ($isFolder) {
            $settings['folders'] = array_values(array_unique($ignoreLists));
        } else {
            $settings['files'] = array_values(array_unique($ignoreLists));
        }

        IntegrityHelper::updateIgnoreLists($settings);

        return [
            'message' => __('Ignore status has been updated.', 'fluent-security'),
            'lists'   => $settings
        ];
    }

    public static function viewFileDiff(\WP_REST_Request $request)
    {
        $fileConfig = $request->get_param('viewing_file');

        if (!$fileConfig || empty($fileConfig['file']) || empty($fileConfig['status'])) {
            return new \WP_Error('invalid_data', __('Please provide a valid file name and status.', 'fluent-security'), ['status' => 400, 'data' => $fileConfig]);
        }

        $file = $fileConfig['file'];
        $status = $fileConfig['status'];
        $folder = $fileConfig['folder'];

        $validFolders = ['', 'wp-admin', 'wp-includes', WPINC];

        if (!in_array($folder, $validFolders)) {
            return new \WP_Error('invalid_data', __('Invalid folder name.', 'fluent-security'), ['status' => 400, 'data' => $fileConfig]);
        }

        $isInc = $folder == 'wp-includes';

        if ($folder == 'wp-includes') {
            $folder = WPINC;
        }

        if ($folder) {
            $filePath = ABSPATH . $folder . '/' . $file;
            if (realpath($filePath) != $filePath) {
                return new \WP_Error('invalid_data', __('This file could not be viewed for security reason.', 'fluent-security'), ['status' => 400, 'data' => $file]);
            }
        } else {
            $ignoredFiles = [
                '.git',
                '.gitignore',
                '.DS_Store',
                '.idea',
                'wp-admin',
                'wp-includes',
                'wp-config.php',
                'wp-config-sample.php',
                '.htaccess',
            ];

            $file = basename($file);

            if (in_array($file, $ignoredFiles)) {
                return new \WP_Error('invalid_data', __('This file could not be viewed.', 'fluent-security'), ['status' => 400, 'data' => $file]);
            }
            $filePath = ABSPATH . $file;
        }

        if (!file_exists($filePath)) {
            return new \WP_Error('invalid_data', __('This file could not be viewed.', 'fluent-security'), ['status' => 400, 'data' => $file]);
        }

        // check if the file size is greater than 2MB

        $maxFileSize = 2 * 1024 * 1024; // 2MB
        if (filesize($filePath) > $maxFileSize) {
            return new \WP_Error('invalid_data', __('This file is too large to be viewed.', 'fluent-security'), ['status' => 400, 'data' => $file]);
        }

        // check if the file is readable
        if (!is_readable($filePath)) {
            return new \WP_Error('invalid_data', __('This file is not readable.', 'fluent-security'), ['status' => 400, 'data' => $file]);
        }

        // get file content using WP File System API

        require_once(ABSPATH . 'wp-admin/includes/file.php');
        WP_Filesystem();
        global $wp_filesystem;
        $fileContent = $wp_filesystem->get_contents($filePath);

        $remoteContent = '';
        if ($status == 'modified') {
            $originalRelativePath = str_replace(ABSPATH, '', $filePath);
            if ($isInc) {
                $originalRelativePath = str_replace(WPINC, 'wp-includes', $originalRelativePath);
            }

            $remoteContent = Api::getFileContentFromGithub($originalRelativePath);

            if (is_wp_error($remoteContent)) {
                return new \WP_Error('invalid_data', __('Sorry, we could not compare the changes via Github API.', 'fluent-security'), ['status' => 400]);
            }
        }

        return [
            'filePath'            => str_replace(ABSPATH, '/', $filePath),
            'fileContent'         => $fileContent,
            'hasDiff'             => !!$remoteContent,
            'originalFileContent' => $remoteContent,
        ];

    }

    public static function updateScheduleScan(\WP_REST_Request $request)
    {
        $interval = $request->get_param('scan_interval');
        $enabled = $request->get_param('auto_scan') == 'yes';

        if (!is_string($interval) || empty($interval)) {
            return new \WP_Error('invalid_data', __('Please provide a valid interval.', 'fluent-security'), ['status' => 400, 'data' => $interval]);
        }

        $globalSettings = IntegrityHelper::getSettings();

        $globalSettings['auto_scan'] = $enabled ? 'yes' : 'no';
        $globalSettings['scan_interval'] = $interval == 'hourly' ? 'hourly' : 'daily';

        IntegrityHelper::saveSettings($globalSettings);

        return [
            'message'  => __('Schedule scan has been updated.', 'fluent-security'),
            'settings' => $globalSettings
        ];
    }

    public static function resetIgnores(\WP_REST_Request $request)
    {
        IntegrityHelper::updateIgnoreLists([
            'files'   => [],
            'folders' => []
        ]);

        return [
            'message' => __('Ignore lists have been reset successfully.', 'fluent-security')
        ];
    }

    public static function resetApi(\WP_REST_Request $request)
    {
        Api::disableApi();

        $settings = IntegrityHelper::getSettings();

        $settings['status'] = 'unregistered';
        $settings['api_id'] = '';
        $settings['api_key'] = '';
        $settings['auto_scan'] = 'no';
        $settings['scan_interval'] = 'daily';
        $settings['account_email_id'] = '';

        IntegrityHelper::saveSettings($settings);

        return [
            'message'  => __('API has been reset successfully.', 'fluent-security'),
            'settings' => $settings
        ];
    }
}
