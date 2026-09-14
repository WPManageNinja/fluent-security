<?php

namespace FluentAuth\App\Services\IntegrityChecker;


use FluentAuth\App\Helpers\Arr;

class IntegrityHelper
{
    /*
     * The two ways an owner can disown a site from the alerts dashboard, as this install
     * learns of them - which is only ever by being refused mid-report.
     *
     * Kept apart because the way back differs. A disabled site's key still works, so its owner
     * re-enabling it there is the whole fix. A deleted site's row is gone, and no credential
     * this install holds will ever work again.
     */
    const RELAY_DISABLED = 'disabled';

    const RELAY_REVOKED = 'revoked';

    /*
     * The schedules a site can be put on, and how long each waits, in seconds.
     *
     * Every one is shaved by half an hour. The cron driving this runs hourly and never exactly
     * on the hour, so an interval equal to a whole number of its own periods is a coin toss: a
     * tick arriving a second early fails the check and the next one is an hour later, which
     * turns "daily" into "every other day" and "hourly" into "every two hours". The daily value
     * has carried that shave since it was written; the rest have it for the same reason.
     *
     * One place, because the interval is decided in the cron, validated on save, and named on
     * two screens - and a list that lives in four ternaries grows a fifth.
     */
    const SCAN_INTERVALS = [
        'hourly'        => 3300,
        'six_hourly'    => 19800,
        'twelve_hourly' => 41400,
        'daily'         => 84600
    ];

    public static function getScanIntervals()
    {
        return self::SCAN_INTERVALS;
    }

    /*
     * The stored interval, or the default if it is one this version does not know - a value
     * written by a newer release, or by hand.
     */
    public static function normaliseScanInterval($interval)
    {
        return isset(self::SCAN_INTERVALS[$interval]) ? $interval : 'daily';
    }

    public static function getScanIntervalSeconds($interval)
    {
        return self::SCAN_INTERVALS[self::normaliseScanInterval($interval)];
    }

    public static function getSettings()
    {
        $defaults = [
            'status'              => 'unregistered',
            'api_id'              => '',
            'api_key'             => '',
            'last_checked'        => '',
            'account_email_id'    => '',
            'is_ok'               => 'yes',
            'auto_scan'           => 'no',
            'scan_interval'       => 'daily',
            'last_report_sent'    => '',
            /*
             * Why the relay stopped accepting this site's reports, if it has. Empty on a site
             * in good standing. See handleReportResponse().
             */
            'relay_rejection'     => '',
            'relay_rejected_at'   => '',
            'relay_auth_failures' => 0,
            /*
             * A hash of the extension inventory the relay has actually accepted, so the list is
             * only carried when it has changed. Empty means it has never taken one - which is
             * also the state a reconnection puts this back to, since a new row over there knows
             * nothing about this site.
             */
            'extensions_hash'     => ''
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
     * What the last scan made of core, kept so the screens that are not the scan screen can
     * say so without hashing wp-includes on every page load.
     *
     * Read by every screen that mentions core, the scan screen included. That screen re-runs
     * core when somebody asks it to, but it no longer scans on arrival, and a row that knows
     * what the last scan found should say so rather than ask to be run again - the findings
     * list and the recovery screen have always read it this way.
     *
     * Stored unfiltered and capped, like the extension results: the ignore list is applied
     * when read, so accepting a file later does not need a scan to take effect.
     */
    public static function getCoreResults()
    {
        $results = get_option('__fls_integrity_core_results', []);

        return is_array($results) ? $results : [];
    }

    /**
     * The last core scan, in the shape the scan screen draws.
     *
     * The same findings getCoreResults() holds, grouped by the folder the scanner looked in -
     * which is how a live scan hands them over, and so how the screen expects them. Stored
     * flat because everything else that reads them wants them flat; regrouped here rather
     * than stored twice.
     *
     * Null before the first scan, which is the one case the screen should word as never having
     * looked rather than as having found nothing.
     *
     * @return array|null
     */
    public static function getStoredCoreScanResults()
    {
        $results = self::getCoreResults();

        if (empty($results['checked_at'])) {
            return null;
        }

        return [
            'files'      => CheckerService::groupFiles((array)Arr::get($results, 'files', [])),
            'folders'    => array_values((array)Arr::get($results, 'folders', [])),
            'truncated'  => (int)Arr::get($results, 'truncated', 0),
            'checked_at' => $results['checked_at']
        ];
    }

    public static function storeCoreResult(CheckerService $checker)
    {
        $maxFiles = apply_filters('fluent_auth/integrity_max_extension_findings', 300);

        $files = $checker->getModifiedFiles();
        $total = count($files);

        $result = [
            'version'    => get_bloginfo('version'),
            'files'      => array_slice($files, 0, $maxFiles, true),
            'folders'    => array_values((array)$checker->getModifiedFolders()),
            'total'      => $total,
            'truncated'  => max(0, $total - $maxFiles),
            'checked_at' => current_time('mysql')
        ];

        update_option('__fls_integrity_core_results', $result, false);

        return $result;
    }

    /*
     * Core findings the site has not already accepted, as flat root-relative paths.
     *
     * The same shape getActiveExtensionFindings() returns, so a reader of either can treat
     * them alike. Nothing at all before the first scan - an empty list here means "nothing
     * found", and the caller has to check checked_at to tell that from "never looked".
     */
    public static function getActiveCoreFindings()
    {
        $results = self::getCoreResults();

        if (empty($results['checked_at'])) {
            return [];
        }

        $ignored = array_map(function ($file) {
            return ltrim($file, '/');
        }, Arr::get(self::getIgnoreLists(), 'files', []));

        $active = [];

        foreach ((array)Arr::get($results, 'files', []) as $file => $data) {
            if (in_array($file, $ignored, true)) {
                continue;
            }

            $active[$file] = $data;
        }

        return $active;
    }

    /*
     * What the last scan found in each plugin and theme, keyed by type and file.
     *
     * Core's findings are kept only in summary - see getCoreResults() - because the screen
     * re-scans on arrival and core is one cheap request. Extensions are not cheap, so their
     * results are stored in full: it is what lets the aside say "44 of 47 verified" without
     * walking wp-content again, and what lets the scheduled scan work through a big site
     * across several runs instead of trying to finish inside one.
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

        /*
         * Both halves of the condition the cron checks, repeated here rather than trusted to
         * the caller: this is what actually posts, and a site the relay has disowned must not
         * post from anywhere.
         */
        if ($settings['auto_scan'] != 'yes' || $settings['status'] != 'active') {
            return;
        }

        $interval = self::getScanIntervalSeconds($settings['scan_interval']);

        if ($settings['last_report_sent'] && (time() - strtotime($settings['last_report_sent'])) < $interval) {
            return;
        }

        try {
            $checkerService = new CheckerService();
        } catch (\Exception $exception) {
            // error happended
            return false;
        }

        self::storeCoreResult($checkerService);

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

        /*
         * A clean run is posted too, and deliberately.
         *
         * The relay records it without notifying anybody - an all-clear every night is how a
         * service teaches people to filter it - but the record is what keeps "last seen"
         * honest. Reporting only the bad runs made every healthy site look abandoned on the
         * dashboard, and it meant a site the owner had disconnected went on believing it was
         * connected until the day it happened to find something.
         */
        $payload = self::buildReportPayload(
            array_merge($modifiedFiles, $modifiedExtensionFiles),
            $modifiedFolders,
            $suspiciousExtensions
        );

        /*
         * The relay decides whether this is worth sending to anyone - see the fingerprint
         * check in its reports route. A site that has been modified and left modified posts
         * the same findings on every run, and suppressing the repeat there rather than here
         * means the dashboard still records that the scan happened and still found them.
         */
        return self::postReport(self::withInventory($payload));
    }

    /*
     * The wire shape of a report, built in one place so the scheduled send and the reconnect
     * probe cannot drift apart in what they claim about this site.
     */
    public static function buildReportPayload($modifiedFiles, $modifiedFolders, $suspiciousExtensions)
    {
        $settings = self::getSettings();

        return [
            'api_key'          => $settings['api_key'],
            'api_id'           => $settings['api_id'],
            'user_email'       => Arr::get($settings, 'account_email_id'),
            'site_url'         => site_url(),
            'admin_url'        => admin_url('admin.php?page=fluent-auth#/'),
            'site_title'       => get_bloginfo('name'),
            'modified_files'   => $modifiedFiles,
            /*
             * Re-indexed on the way out. The relay reads this key only when it is a JSON array,
             * and a list with a hole in it encodes as an object - which costs the whole section
             * of the alert without costing the count in its subject line.
             */
            'modified_folders' => array_values((array)$modifiedFolders),
            /*
             * Sent as its own key rather than folded into modified_files: it is a different kind
             * of claim - "this whole extension is not the one WordPress.org published" - and the
             * report should be able to say so even if the email template only knows the two
             * older keys.
             *
             * Re-indexed for the same reason the folders are, though nothing filters this list
             * today: the cost of being wrong is a whole finding type that encodes as an object
             * and is read as no findings at all, and one array_values is cheaper than relying on
             * everyone who edits getSuspiciousExtensions() knowing that.
             */
            'unpublished_versions' => array_values((array)$suspiciousExtensions)
        ];
    }

    /*
     * Send a report and act on what comes back.
     *
     * The one place a report is posted, so the standing of this site and the relay's record of
     * what is installed are updated on the same answer rather than in two places that can
     * disagree about whether the request succeeded.
     */
    protected static function postReport($payload)
    {
        $response = Api::sendPostRequest('reports', $payload);

        self::handleReportResponse($response);

        $code = is_wp_error($response) ? 0 : (int)wp_remote_retrieve_response_code($response);

        /*
         * The inventory counts as delivered only when the relay took it. Marking it sent on the
         * way out would mean one failed request silently withholds the list until something else
         * about the site changes - which, for a list that changes when a plugin is updated,
         * could be months.
         */
        if ($code >= 200 && $code < 300 && isset($payload['extensions'])) {
            $settings = self::getSettings();
            $settings['extensions_hash'] = self::inventoryHash([
                'extensions'           => $payload['extensions'],
                'extensions_untracked' => Arr::get($payload, 'extensions_untracked', 0)
            ]);
            self::saveSettings($settings);
        }

        return $response;
    }

    /*
     * Add the extension inventory, but only when the relay's copy is out of date.
     *
     * The list is the same on almost every run - a site's plugins change when somebody updates
     * one - so sending it every time would be the same few kilobytes over and over. Comparing a
     * hash of what would be sent against what was last accepted costs one option read.
     */
    public static function withInventory($payload)
    {
        $inventory = ExtensionInventory::getReportInventory();

        /* Nothing trustworthy to say this run - see getReportInventory. */
        if (!is_array($inventory) || !Arr::get($inventory, 'extensions')) {
            return $payload;
        }

        if (self::inventoryHash($inventory) === (string)Arr::get(self::getSettings(), 'extensions_hash', '')) {
            return $payload;
        }

        /*
         * Both keys travel together. The count is part of what changed, so sending it without the
         * list it was counted alongside would leave the relay holding two halves of different
         * snapshots.
         */
        $payload['extensions'] = Arr::get($inventory, 'extensions', []);
        $payload['extensions_untracked'] = (int)Arr::get($inventory, 'extensions_untracked', 0);

        return $payload;
    }

    /*
     * Order-independent, so a plugin list that comes back from get_plugins() in a different
     * order is not mistaken for a site that has changed.
     */
    public static function inventoryHash($inventory)
    {
        /*
         * The count is hashed too. A bespoke plugin being added or removed changes nothing in the
         * named list, and without this the relay would never be told its number had moved.
         */
        $parts = ['untracked:' . (int)Arr::get((array)$inventory, 'extensions_untracked', 0)];

        foreach ((array)Arr::get((array)$inventory, 'extensions', []) as $item) {
            $parts[] = implode('|', [
                Arr::get($item, 'type', ''),
                Arr::get($item, 'slug', ''),
                Arr::get($item, 'file', ''),
                Arr::get($item, 'version', ''),
                Arr::get($item, 'status', ''),
                Arr::get($item, 'latest', ''),
                /*
                 * A licence lapsing or being renewed changes nothing else about an extension -
                 * same slug, same version, same status - so without this the relay would go on
                 * believing something is still being offered updates when it is not.
                 */
                Arr::get($item, 'update_source') ? '1' : '0'
            ]);
        }

        sort($parts);

        return md5(implode("\n", $parts));
    }

    /*
     * Report the scan that has just finished, if this site reports at all.
     *
     * A scan somebody ran from the screen used to tell the relay nothing: only the scheduled
     * path posted, so "I scanned, and the dashboard still says it is waiting for a first scan"
     * was the accurate description of a working system. A scan is a scan whoever asked for it.
     *
     * Guarded on both halves of the cron's own condition, so there is one rule for whether a
     * site reports rather than two that can disagree - a site with the schedule switched off
     * has said it does not want its results sent anywhere.
     */
    public static function reportScanIfConnected()
    {
        $settings = self::getSettings();

        if ($settings['auto_scan'] != 'yes' || $settings['status'] != 'active') {
            return null;
        }

        $response = self::sendStoredReport();

        /*
         * Counts against the interval, so a scan run by hand a minute before the cron comes
         * round does not become two reports of the same findings.
         */
        $settings = self::getSettings();
        $settings['last_report_sent'] = date('Y-m-d H:i:s');
        self::saveSettings($settings);

        return $response;
    }

    /*
     * A report built from what the last scan already found, sent now.
     *
     * The scheduled path re-scans first, which means fetching core checksums and walking
     * wp-content - seconds of work that a request holding a browser open cannot afford. This
     * says exactly the same thing about the site using the stored results, which is all the
     * reconnect probe needs: the answer it is waiting for is the relay's, not the scanner's.
     */
    public static function sendStoredReport()
    {
        $folders = array_values(array_diff(
            (array)Arr::get(self::getCoreResults(), 'folders', []),
            (array)Arr::get(self::getIgnoreLists(), 'folders', [])
        ));

        $payload = self::buildReportPayload(
            array_merge(self::getActiveCoreFindings(), self::getActiveExtensionFindings()),
            $folders,
            self::getSuspiciousExtensions()
        );

        return self::postReport(self::withInventory($payload));
    }

    /*
     * What the relay made of the report, as far as this site's standing is concerned.
     *
     * Only two answers mean anything here. A 403 says the owner disabled this site on the
     * dashboard; a 401 says the credentials no longer name a site it knows. Everything else -
     * a timeout, a 429, a 500 - is this run's problem and not this site's, and reporting
     * carries on unchanged.
     *
     * Returns the rejection it recorded, or null if there was nothing to record.
     */
    public static function handleReportResponse($response)
    {
        if (is_wp_error($response)) {
            /* The network, not the relay. Nothing has been said about this site at all. */
            return null;
        }

        $code = (int)wp_remote_retrieve_response_code($response);

        if ($code >= 200 && $code < 300) {
            self::clearRelayRejection();

            return null;
        }

        if ($code !== 401 && $code !== 403) {
            return null;
        }

        if ($code === 403) {
            return self::markRelayRejected(self::RELAY_DISABLED);
        }

        /*
         * A 401 is the one ambiguous answer: a site deleted from the dashboard and a stored key
         * that has been corrupted look identical from here. So it costs one more report before
         * the credentials are thrown away - but only one, because the alternative is an install
         * that re-posts a key nothing will ever accept until somebody notices.
         */
        $settings = self::getSettings();
        $strikes = (int)Arr::get($settings, 'relay_auth_failures', 0) + 1;

        if ($strikes < 2) {
            $settings['relay_auth_failures'] = $strikes;
            self::saveSettings($settings);

            return null;
        }

        return self::markRelayRejected(self::RELAY_REVOKED);
    }

    /*
     * Stop reporting, and leave the screen able to say why.
     *
     * Reporting stops by way of `status`, which the cron already guards on - so there is no
     * second switch that can disagree with this one about whether the site is connected.
     */
    public static function markRelayRejected($reason)
    {
        $settings = self::getSettings();

        $settings['relay_rejection'] = $reason;
        $settings['relay_rejected_at'] = date('Y-m-d H:i:s');
        $settings['relay_auth_failures'] = 0;

        if ($reason === self::RELAY_REVOKED) {
            /*
             * Nothing survives: the relay has no row for these credentials, so keeping them
             * would only let the screen offer a reconnect that cannot work. Back to the state
             * a never-registered site is in, which is the one the screen knows how to offer
             * registration from.
             */
            $settings['status'] = 'unregistered';
            $settings['api_id'] = '';
            $settings['api_key'] = '';
            $settings['account_email_id'] = '';
            $settings['auto_scan'] = 'no';
        } else {
            /*
             * Disabled, not deleted - the key is still good. The schedule is left switched on
             * so that resuming is one click here and not a re-run of the whole setup.
             */
            $settings['status'] = 'disabled';
        }

        self::saveSettings($settings);

        return $reason;
    }

    public static function clearRelayRejection()
    {
        $settings = self::getSettings();

        if (empty($settings['relay_rejection']) && empty($settings['relay_auth_failures'])) {
            return false;
        }

        $settings['relay_rejection'] = '';
        $settings['relay_rejected_at'] = '';
        $settings['relay_auth_failures'] = 0;

        return self::saveSettings($settings);
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
