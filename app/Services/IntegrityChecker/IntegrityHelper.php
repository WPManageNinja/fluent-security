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

    /*
     * What the last scan found in each plugin and theme, keyed by type and file.
     *
     * Core's findings are deliberately not kept - the screen re-scans on arrival and core is
     * one cheap request. Extensions are not cheap, so their results are stored: it is what
     * lets the aside say "44 of 47 verified" without walking wp-content again, and what lets
     * the scheduled scan work through a big site across several runs instead of trying to
     * finish inside one.
     */
    public static function getExtensionResults()
    {
        $results = get_option('__fls_integrity_extension_results', []);

        return is_array($results) ? $results : [];
    }

    public static function saveExtensionResults($results)
    {
        return update_option('__fls_integrity_extension_results', $results, false);
    }

    /*
     * File a single extension's result, replacing whatever was known about it before.
     *
     * The finding list is capped. A plugin whose folder has been emptied, or whose version
     * header no longer matches its contents, can report thousands of files at once, and none
     * of that belongs in an option row - past the cap the count is kept and the paths are not.
     */
    public static function storeExtensionResult($result)
    {
        $maxFiles = apply_filters('fluent_auth/integrity_max_extension_findings', 300);

        $files = isset($result['files']) && is_array($result['files']) ? $result['files'] : [];
        $result['total_files'] = count($files);
        $result['truncated'] = 0;

        if ($result['total_files'] > $maxFiles) {
            $result['files'] = array_slice($files, 0, $maxFiles, true);
            $result['truncated'] = $result['total_files'] - $maxFiles;
        }

        $results = self::getExtensionResults();
        $results[self::getResultKey($result)] = $result;

        self::saveExtensionResults($results);

        /*
         * Keep the site's stored verdict honest as the scan walks the list. A scan starts by
         * resetting it to yes (see SecurityScanController::scanSite), so this only ever has to
         * turn it off - and the dashboard widget, which reads the option directly, is then right
         * without waiting for the browser to finish the walk.
         */
        if (self::hasExtensionIssues()) {
            $settings = self::getSettings();

            if ($settings['is_ok'] !== 'no') {
                $settings['is_ok'] = 'no';
                self::saveSettings($settings);
            }
        }

        return $result;
    }

    public static function getResultKey($target)
    {
        return $target['type'] . ':' . $target['key'];
    }

    /*
     * Whether wp-content has anything outstanding: changed files, or a version the directory
     * never published. Both minus whatever has been accepted.
     *
     * The site's overall verdict is stored in one option field, and the interactive scan writes
     * it from the core check alone - core is one request, extensions are dozens, so there is no
     * single moment at which the whole picture is known. Reading it back through this is what
     * keeps the dashboard, the aside and the checklist from claiming "no changes" over a screen
     * full of red plugin rows.
     */
    public static function hasExtensionIssues()
    {
        return (bool)self::getActiveExtensionFindings() || (bool)self::getSuspiciousExtensions();
    }

    /*
     * Whether a whole extension has been marked as expected.
     *
     * A pre-release build is indistinguishable from a tampered one: both are a version the
     * directory does not publish. Somebody running a beta on purpose needs a way to say so, or
     * the site sits permanently red and the alert email cries wolf every night. Stored in the
     * same ignore list the rest of the screen uses - under `folders`, since what is being
     * accepted is a directory rather than a file.
     */
    public static function isExtensionIgnored($relPath)
    {
        $ignored = Arr::get(self::getIgnoreLists(), 'folders', []);

        return in_array('/' . trim($relPath, '/'), $ignored, true);
    }

    /*
     * Extensions the directory publishes, at a version it has never published.
     *
     * Reported as findings rather than as coverage gaps - see
     * ExtensionInventory::getReasonSeverity for why this is the alarming case.
     */
    public static function getSuspiciousExtensions()
    {
        $suspicious = [];

        foreach (self::getExtensionResults() as $result) {
            if (!empty($result['verifiable']) || empty($result['reason'])) {
                continue;
            }

            if (ExtensionInventory::getReasonSeverity($result['reason']) !== 'suspicious') {
                continue;
            }

            if (self::isExtensionIgnored(Arr::get($result, 'rel_path', ''))) {
                continue;
            }

            $suspicious[] = [
                'type'    => $result['type'],
                'name'    => $result['name'],
                'version' => $result['version'],
                'path'    => '/' . trim(Arr::get($result, 'rel_path', ''), '/'),
                'reason'  => ExtensionInventory::getReasonLabel($result['reason'])
            ];
        }

        return $suspicious;
    }

    /*
     * Extension findings the site has not already accepted, as flat root-relative paths.
     *
     * The ignore list is one list for the whole scan, holding core and extension paths alike,
     * so an extension finding has to be named the same way a core one is - relative to the
     * WordPress root, with the leading slash the browser stores.
     */
    public static function getActiveExtensionFindings()
    {
        $ignored = array_map(function ($file) {
            return ltrim($file, '/');
        }, Arr::get(self::getIgnoreLists(), 'files', []));

        $active = [];

        foreach (self::getExtensionResults() as $result) {
            if (empty($result['verifiable']) || empty($result['files'])) {
                continue;
            }

            /* An extension marked as expected is accepted whole, files and all. */
            if (self::isExtensionIgnored(Arr::get($result, 'rel_path', ''))) {
                continue;
            }

            foreach ($result['files'] as $file => $data) {
                $fullPath = trim($result['rel_path'], '/') . '/' . $file;

                if (in_array($fullPath, $ignored, true)) {
                    continue;
                }

                $data['extension'] = $result['name'];
                $data['extension_type'] = $result['type'];
                $active[$fullPath] = $data;
            }
        }

        return $active;
    }

    /*
     * How much of wp-content the last scan was actually able to vouch for.
     *
     * Counted against what is installed now, not against what happens to be in the stored
     * results. An interactive scan only asks the server about the extensions it can check, so
     * the premium and custom ones leave no result behind - and a summary built from results
     * alone would put the denominator at the number it managed to verify and report perfect
     * coverage. The blind spot has to be counted from the inventory to be counted at all.
     */
    public static function getExtensionSummary()
    {
        $results = self::getExtensionResults();

        $summary = [
            'total'        => 0,
            'verifiable'   => 0,
            'checked'      => 0,
            'unverifiable' => 0,
            /* Counted apart from the rest: these are findings, not missing coverage. */
            'suspicious'   => 0,
            'with_issues'  => 0,
            'files'        => 0
        ];

        foreach (ExtensionInventory::getTargets() as $target) {
            $summary['total']++;

            /*
             * Indexed directly, not through Arr::get(): a result key holds a plugin's own file
             * name, so it contains dots, and dot-notation lookup would read
             * "plugin:akismet/akismet.php" as a path into a nested array and find nothing.
             */
            $key = self::getResultKey($target);
            $result = isset($results[$key]) ? $results[$key] : null;

            /*
             * Unverifiable either because there is no official copy of it, or because the one
             * there should have been could not be had - an unpublished version, a failed
             * download. Both are "we could not check this", which is the number that matters.
             */
            if (empty($target['verifiable']) || ($result && empty($result['verifiable']))) {
                $summary['unverifiable']++;

                $reason = $result ? Arr::get($result, 'reason') : Arr::get($target, 'reason');

                if (ExtensionInventory::getReasonSeverity($reason) === 'suspicious'
                    && !self::isExtensionIgnored($target['rel_path'])) {
                    $summary['suspicious']++;
                }

                continue;
            }

            $summary['verifiable']++;

            if (!$result) {
                continue; // checkable, but this scan has not reached it yet
            }

            $summary['checked']++;

            $count = isset($result['total_files']) ? (int)$result['total_files'] : count(Arr::get($result, 'files', []));

            if ($count) {
                $summary['with_issues']++;
                $summary['files'] += $count;
            }
        }

        return $summary;
    }

    public static function getIgnoreLists()
    {
        $ignoreLists = get_option('__fls_integrity_ignore_lists', []);

        $defaults = [
            'files'     => [],
            'folders'   => [],
            /* path => hash, for the small directories watched by hash rather than by list. */
            'hashes'    => [],
            /* scope => unix time it was first recorded. See AcceptedFiles. */
            'baselined' => []
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

        /*
         * Then as much of wp-content as fits in the budget, picking up where the last run
         * stopped, so a site with sixty plugins gets covered across a few runs rather than
         * timing out on every one of them and reporting nothing.
         */
        self::scanExtensionBatch();

        /*
         * And the site's own snapshot, which covers exactly what the directory cannot - the
         * premium and custom extensions. Does nothing until somebody has taken one.
         */
        \FluentAuth\App\Services\Baseline\BaselineScanner::compare();

        $modifiedExtensionFiles = self::getActiveExtensionFindings();

        /*
         * An extension whose version the directory has never published is a finding in its own
         * right, even though it produced no file list - there was no official copy to diff
         * against, which is precisely what is alarming about it. Left out of this total it would
         * be the one thing the nightly email never mentioned.
         */
        $suspiciousExtensions = self::getSuspiciousExtensions();

        $settings['last_report_sent'] = date('Y-m-d H:i:s');
        $settings['last_checked'] = date('Y-m-d H:i:s');
        $settings['is_ok'] = (!$modifiedFolders && !$modifiedFiles && !$modifiedExtensionFiles && !$suspiciousExtensions)
            ? 'yes'
            : 'no';
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
            'modified_files'   => array_merge($modifiedFiles, $modifiedExtensionFiles),
            'modified_folders' => $modifiedFolders,
            /*
             * Sent as its own key rather than folded into modified_files: it is a different kind
             * of claim - "this whole extension is not the one WordPress.org published" - and the
             * report should be able to say so even if the email template only knows the two
             * older keys.
             */
            'unpublished_versions' => $suspiciousExtensions
        ];

        return Api::sendPostRequest('send-security-email/', $payload);
    }

    /*
     * Check as many plugins and themes as a cron run can afford.
     *
     * Least-recently-checked first, which needs no cursor of its own: the stored results carry
     * the timestamps, so adding or removing a plugin reorders the queue on its own instead of
     * invalidating a saved position. Anything never checked sorts to the front.
     */
    public static function scanExtensionBatch($budgetSeconds = null)
    {
        if ($budgetSeconds === null) {
            $budgetSeconds = apply_filters('fluent_auth/integrity_scan_budget', 20);
        }

        $targets = ExtensionInventory::getTargets();

        if (!$targets) {
            return 0;
        }

        $results = self::getExtensionResults();

        /*
         * Indexed directly rather than through Arr::get() - see getExtensionSummary(). Reading
         * these with dot notation silently returned "never checked" for every plugin, so every
         * run re-scanned the same handful and the queue never advanced.
         */
        $checkedAt = function ($target) use ($results) {
            $key = self::getResultKey($target);

            return isset($results[$key]['checked_at']) ? (string)$results[$key]['checked_at'] : '';
        };

        usort($targets, function ($a, $b) use ($checkedAt) {
            return strcmp($checkedAt($a), $checkedAt($b));
        });

        /* A stale entry for something no longer installed would keep counting forever. */
        self::forgetMissingExtensions($targets);

        $checker = new ExtensionChecker();
        $startedAt = time();
        $scanned = 0;

        foreach ($targets as $target) {
            self::storeExtensionResult($checker->scan($target));
            $scanned++;

            if ((time() - $startedAt) >= $budgetSeconds) {
                break;
            }
        }

        return $scanned;
    }

    protected static function forgetMissingExtensions($targets)
    {
        $installed = array_map([self::class, 'getResultKey'], $targets);
        $results = self::getExtensionResults();
        $kept = array_intersect_key($results, array_flip($installed));

        if (count($kept) !== count($results)) {
            self::saveExtensionResults($kept);
        }
    }
}
