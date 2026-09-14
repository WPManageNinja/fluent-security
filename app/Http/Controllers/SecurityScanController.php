<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Files\MuPluginsCheck;
use FluentAuth\App\Services\IntegrityChecker\Api;
use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\ExtensionChecker;
use FluentAuth\App\Services\IntegrityChecker\ExtensionInventory;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;
use FluentAuth\App\Services\Recovery\FileRecovery;
use FluentAuth\App\Services\Recovery\RecoveryService;

class SecurityScanController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        $settings = IntegrityHelper::getSettings();

        if ($settings['last_checked']) {
            $settings['last_checked_human'] = human_time_diff(strtotime($settings['last_checked']), current_time('timestamp'));
        }

        /*
         * The stored verdict is written by the core check, which knows nothing about wp-content.
         * ORed with what is known about the extensions so this screen cannot report "no changes"
         * with changed plugins listed below it.
         */
        if ($settings['is_ok'] !== 'no' && IntegrityHelper::hasExtensionIssues()) {
            $settings['is_ok'] = 'no';
        }

        return [
            'settings' => $settings,
            'ignores'  => IntegrityHelper::getIgnoreLists(),
            /*
             * What the last scan found, so arriving on the screen shows the standing picture
             * instead of a blank slate. Core and wp-content alike: both are kept, and a row
             * that has an answer from the last scan should give it rather than ask to be run
             * again to say something it already knows.
             */
            'core_results' => IntegrityHelper::getStoredCoreScanResults(),
            'extension_results' => array_values(array_map(function ($result) {
                if (!empty($result['reason'])) {
                    $result['reason_label'] = ExtensionInventory::getReasonLabel($result['reason']);
                    $result['severity'] = ExtensionInventory::getReasonSeverity($result['reason']);
                }

                $result['ignored'] = IntegrityHelper::isExtensionIgnored(Arr::get($result, 'rel_path', ''));

                return $result;
            }, IntegrityHelper::getExtensionResults())),
            'extension_summary' => IntegrityHelper::getExtensionSummary()
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

        /*
         * The dashboard path. Somebody who already has an alerts account creates a key there
         * and pastes it here, which skips the emailed-key handshake entirely: the key proves
         * who they are, and what comes back is this site's own credential.
         *
         * Automatic scanning goes on with it. Connecting a site to an alert relay and leaving
         * the schedule off would mean nothing is ever sent - it is the only reason to paste a
         * key at all.
         */
        if ($request->get_param('status') == 'connect') {
            $apiKey = sanitize_text_field($request->get_param('api_key'));

            if (!$apiKey) {
                return new \WP_Error('invalid_data', __('Please provide your API key.', 'fluent-security'), ['status' => 400]);
            }

            $connection = Api::connectSite($apiKey);

            if (is_wp_error($connection)) {
                return $connection;
            }

            $settings = IntegrityHelper::getSettings();

            $settings['api_id'] = $connection['api_id'];
            $settings['api_key'] = $connection['api_key'];
            $settings['status'] = 'active';
            $settings['auto_scan'] = 'yes';
            /* Stated rather than inherited, so both ways in land on the same schedule. */
            $settings['scan_interval'] = 'daily';
            $settings['relay_rejection'] = '';
            $settings['relay_rejected_at'] = '';
            $settings['relay_auth_failures'] = 0;
            /* See the note on the other connection path: a new row reports from scratch. */
            $settings['last_report_sent'] = '';

            IntegrityHelper::saveSettings($settings);

            return [
                'message'  => __('This site is connected. Daily scans will now be reported to your alert channels.', 'fluent-security'),
                'settings' => $settings
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

            /*
             * Scheduling goes on with the key, daily.
             *
             * Connecting a site to an alert relay and leaving the schedule off means nothing is
             * ever sent, which is the only reason to connect one. It used to be a second step on
             * the screen behind this, easy to miss and invisible when missed: the site looked
             * connected, the dashboard listed it, and no report ever arrived.
             */
            $settings['auto_scan'] = 'yes';
            $settings['scan_interval'] = 'daily';

            /*
             * Cleared in case this key is replacing one the relay had stopped accepting - the
             * site has just proved otherwise.
             */
            $settings['relay_rejection'] = '';
            $settings['relay_rejected_at'] = '';
            $settings['relay_auth_failures'] = 0;

            /*
             * A connection is a different site as far as the relay is concerned - a new row,
             * with nothing reported to it yet - so the old connection's timestamp must not gate
             * the first report. Left in place it silences a freshly connected site for most of a
             * day and leaves the dashboard saying it is awaiting its first scan.
             */
            $settings['last_report_sent'] = '';
        } else {
            $settings['api_id'] = $apiId;
            $settings['status'] = 'pending';
            $settings['account_email_id'] = $infoData['email'];
        }

        IntegrityHelper::saveSettings($settings);

        return [
            'message'  => $isConfirmed
                ? __('This site is connected. Daily scans will now be reported to your alert channels.', 'fluent-security')
                : __('Your site has been successfully registered. Please provide the API token.', 'fluent-security'),
            'settings' => $settings
        ];

    }

    public static function scanSite(\WP_REST_Request $request)
    {
        $settings = IntegrityHelper::getSettings();
        $settings['last_checked'] = current_time('mysql');
        $settings['is_ok'] = 'yes';
        IntegrityHelper::saveSettings($settings);

        try {
            $checkerService = new CheckerService();
        } catch (\Exception $e) {
            return new \WP_Error('invalid_response', __('An error occurred while scanning the site. If you continously get this error, please reconnect the API.', 'fluent-security'), ['status' => 422, 'data' => $e->getMessage()]);
        }

        /* Kept for the screens that do not re-scan - see IntegrityHelper::getCoreResults(). */
        IntegrityHelper::storeCoreResult($checkerService);

        $scanResults = $checkerService->getScanResults(false);
        $activeChanges = $checkerService->getScanResults(true);

        $hasIssues = array_filter($activeChanges);
        $settings['last_checked'] = current_time('mysql');
        if ($hasIssues) {
            $settings['is_ok'] = 'no';
        }

        IntegrityHelper::saveSettings($settings);

        /*
         * Tell the relay what this scan found. Does nothing on a site that is not connected or
         * has the schedule off; see IntegrityHelper::reportScanIfConnected.
         */
        IntegrityHelper::reportScanIfConnected();

        return [
            'scan_results'  => $scanResults,
            'activeChanges' => $activeChanges,
            'hasIssues'     => !!array_filter($scanResults),
            'willAlert'     => !!array_filter($activeChanges)
        ];
    }

    /*
     * The work list for the plugin and theme phases of a scan.
     *
     * Handed to the browser so it can walk the list one item at a time - see ExtensionChecker
     * for why a single request cannot do all of it - and so the progress it shows is the real
     * count rather than a guess.
     */
    public static function getScanTargets(\WP_REST_Request $request)
    {
        $targets = ExtensionInventory::getTargets();
        $results = IntegrityHelper::getExtensionResults();

        $plugins = [];
        $themes = [];

        foreach ($targets as $target) {
            /*
             * Asked before applyKnownFailure(), which marks a version the directory never
             * published unverifiable - and that is precisely the case a reinstall answers, by
             * installing the current release instead. The recovery screen asks the same
             * question of the same unmodified target, so the two screens offer the button in
             * the same places.
             */
            $blocked = FileRecovery::extensionBlockedReason($target);

            $target = self::applyKnownFailure($target, $results);

            $item = [
                'type'       => $target['type'],
                'key'        => $target['key'],
                'slug'       => $target['slug'],
                'name'       => $target['name'],
                'version'    => $target['version'],
                'rel_path'   => $target['rel_path'],
                'verifiable' => (bool)$target['verifiable'],
                'reason'     => $target['reason'],
                'reason_label' => $target['reason'] ? ExtensionInventory::getReasonLabel($target['reason']) : '',
                /*
                 * Which kind of "could not verify" this is. Only the benign kind belongs in the
                 * premium list; a version the directory does not publish stays with the plugins.
                 */
                'severity'   => $target['reason'] ? ExtensionInventory::getReasonSeverity($target['reason']) : '',
                'ignored'    => IntegrityHelper::isExtensionIgnored($target['rel_path']),
                /* Whether the row may offer to put the official copy back, and why not. */
                'reinstallable' => !$blocked,
                'blocked'       => $blocked
            ];

            if ($target['type'] === 'theme') {
                $themes[] = $item;
            } else {
                $plugins[] = $item;
            }
        }

        return [
            'plugins' => $plugins,
            'themes'  => $themes,
            'counts'  => [
                'plugins'            => count($plugins),
                'themes'            => count($themes),
                'verifiable_plugins' => count(array_filter($plugins, function ($p) { return $p['verifiable']; })),
                'verifiable_themes'  => count(array_filter($themes, function ($t) { return $t['verifiable']; }))
            ]
        ];
    }

    /*
     * Carry forward a failure the last scan already established about this exact version.
     *
     * The inventory can only tell that a plugin comes from the .org directory; whether the
     * directory actually publishes the version installed here is something only an attempt can
     * find out. Without remembering that attempt the work list calls such a plugin checkable,
     * the aside counts it as unverified, and the two disagree about the same plugin.
     *
     * Only failures that are a property of the version are carried - a version that is not
     * published will not become published. A download that failed is not one of those: the
     * network being down once is no reason to stop trying.
     */
    protected static function applyKnownFailure($target, $results)
    {
        if (empty($target['verifiable'])) {
            return $target;
        }

        $key = $target['type'] . ':' . $target['key'];
        $result = isset($results[$key]) ? $results[$key] : null;

        if (!$result || !empty($result['verifiable'])) {
            return $target;
        }

        /* A different version now installed deserves its own attempt. */
        if (Arr::get($result, 'version') !== $target['version']) {
            return $target;
        }

        if (!in_array(Arr::get($result, 'reason'), ['version_not_published', 'no_manifest'], true)) {
            return $target;
        }

        $target['verifiable'] = false;
        $target['reason'] = $result['reason'];

        return $target;
    }

    /*
     * Check one plugin or theme. Called once per item while a scan is running.
     */
    public static function scanExtension(\WP_REST_Request $request)
    {
        $type = $request->get_param('type') === 'theme' ? 'theme' : 'plugin';
        $key = $request->get_param('key');

        if (!is_string($key) || empty($key)) {
            return new \WP_Error('invalid_data', __('Please provide the plugin or theme to check.', 'fluent-security'), ['status' => 400]);
        }

        /*
         * The target is taken from the inventory rather than from the request. What gets
         * hashed is a filesystem path and what gets fetched is a wordpress.org slug, and
         * neither should be something the browser can name.
         */
        $target = null;
        foreach (ExtensionInventory::getTargets() as $candidate) {
            if ($candidate['type'] === $type && $candidate['key'] === $key) {
                $target = $candidate;
                break;
            }
        }

        if (!$target) {
            return new \WP_Error('invalid_data', __('That plugin or theme is not installed on this site.', 'fluent-security'), ['status' => 404]);
        }

        $checker = new ExtensionChecker();
        $result = IntegrityHelper::storeExtensionResult($checker->scan($target));

        if (!empty($result['reason'])) {
            $result['reason_label'] = ExtensionInventory::getReasonLabel($result['reason']);
            $result['severity'] = ExtensionInventory::getReasonSeverity($result['reason']);
        }

        $result['ignored'] = IntegrityHelper::isExtensionIgnored($target['rel_path']);

        return [
            'result' => $result
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

        /* A file inside a plugin or theme is found a different way - see below. */
        if (Arr::get($fileConfig, 'scope') === 'extension') {
            return self::viewExtensionFileDiff($fileConfig);
        }

        if (Arr::get($fileConfig, 'scope') === 'mu-plugin') {
            return self::viewMuPluginFile($fileConfig);
        }

        $resolved = self::resolveCoreFile($fileConfig);

        if (is_wp_error($resolved)) {
            return $resolved;
        }

        $fileContent = self::readFileContents($resolved['path']);

        $remoteContent = '';

        if ($fileConfig['status'] == 'modified') {
            $remoteContent = Api::getFileContentFromGithub($resolved['remote_path']);

            if (is_wp_error($remoteContent)) {
                return new \WP_Error('invalid_data', __('Sorry, we could not compare the changes via Github API.', 'fluent-security'), ['status' => 400]);
            }
        }

        return [
            'filePath'            => str_replace(ABSPATH, '/', $resolved['path']),
            'fileContent'         => $fileContent,
            'hasDiff'             => !!$remoteContent,
            'originalFileContent' => $remoteContent,
        ];

    }

    /**
     * What is in the must-use plugins directory, and how it stands against the record.
     *
     * A listing rather than a verdict. These files run on every request and cannot be
     * deactivated from the plugins screen, so they are worth showing - but most sites have
     * them because their host put them there, and the check that watches them deliberately
     * says nothing on the first run. This is the other half of that: what it will not accuse
     * anybody of, it will at least let them read.
     *
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function getMuPlugins(\WP_REST_Request $request)
    {
        return self::muPluginsPayload();
    }

    /**
     * Record what is in mu-plugins right now, and start watching from here.
     *
     * The check itself records this folder silently on its first run, because a plugin that
     * opened by accusing somebody of their host's own files would be wrong on most sites. That
     * leaves one thing unsaid, and this is it: the day this plugin was installed is taken on
     * trust, so a site already broken into records the backdoor as normal. The button exists
     * so somebody who has now read these files can say so and have the record start from a
     * state they have actually looked at.
     *
     * Whole-folder rather than per file, like accepting is - the reader is answering one
     * question, and asking it once per file would be asking them to do the sorting.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function baselineMuPlugins(\WP_REST_Request $request)
    {
        $paths = MuPluginsCheck::phpFiles();

        if (!$paths) {
            return new \WP_Error(
                'nothing_to_record',
                __('There are no must-use plugins on this site, so there is nothing to record.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $scope = self::muPluginsScope();
        $hashes = [];

        foreach ($paths as $path) {
            $hash = AcceptedFiles::hash($path);

            if ($hash) {
                $hashes[AcceptedFiles::toRelative($path)] = $hash;
            }
        }

        /*
         * Dropped first, so re-recording cannot leave the hash of a file that is no longer
         * there sitting in the list. A record that still vouches for a deleted path is one an
         * attacker can put a file back underneath.
         */
        AcceptedFiles::forgetMissing(array_keys($hashes), function ($path) use ($scope) {
            return strpos($path, $scope) === 0;
        });

        AcceptedFiles::baseline($scope, $hashes);

        return self::muPluginsPayload([
            'message' => sprintf(
                /* translators: %s: number of files */
                _n(
                    '%s file recorded. You will hear about it only if it changes.',
                    '%s files recorded. You will hear about them only if they change.',
                    count($hashes),
                    'fluent-security'
                ),
                number_format_i18n(count($hashes))
            )
        ]);
    }

    /**
     * @return string root-relative, leading slash
     */
    protected static function muPluginsScope()
    {
        return defined('WPMU_PLUGIN_DIR')
            ? AcceptedFiles::toRelative(WPMU_PLUGIN_DIR)
            : '/wp-content/mu-plugins';
    }

    /**
     * What is in mu-plugins and what the site has recorded about it.
     *
     * One method behind both the listing and the button, so the two can never disagree about
     * which files are there or when they were recorded.
     *
     * @param array $extra
     * @return array
     */
    protected static function muPluginsPayload($extra = [])
    {
        $scope = self::muPluginsScope();

        $baselinedAt = AcceptedFiles::baselinedAt($scope);

        $files = [];

        foreach (MuPluginsCheck::phpFiles() as $path) {
            $relative = AcceptedFiles::toRelative($path);
            $hash = AcceptedFiles::hash($path);

            /*
             * Three states, and the third is the one worth drawing. "Recorded" is every file
             * that was here when watching began or has been accepted since; "changed" and
             * "new" are the two shapes a thing worth asking about takes.
             *
             * Before there is a baseline there is nothing for a file to be new against, and
             * saying otherwise would put "new since we started watching" beside every file on
             * a site that has not started watching. This screen can be opened before the one
             * that records the baseline, so that is not a hypothetical.
             */
            $status = 'recorded';

            if ($baselinedAt && $hash) {
                if (AcceptedFiles::hasChanged($relative, $hash)) {
                    $status = 'changed';
                } elseif (!AcceptedFiles::isAccepted($relative, $hash)) {
                    $status = 'new';
                }
            }

            $files[] = [
                'name'     => str_replace(trailingslashit(WPMU_PLUGIN_DIR), '', $path),
                'path'     => $relative,
                'size'     => (int)@filesize($path),
                'modified' => (int)@filemtime($path),
                'status'   => $status
            ];
        }

        return array_merge($extra, [
            'files'        => $files,
            'directory'    => $scope,
            'baselined_at' => $baselinedAt,
            'baselined_human' => $baselinedAt
                ? human_time_diff($baselinedAt, current_time('timestamp'))
                : '',
            /* How many of them are waiting to be looked at, so the button can say so. */
            'unrecorded'   => count(array_filter($files, function ($file) {
                return $file['status'] !== 'recorded';
            }))
        ]);
    }

    /**
     * One must-use plugin, as it stands.
     *
     * There is nothing to compare it against - no official copy of a file the host or a
     * developer wrote - so this only ever returns the source. Which is the point: nobody can
     * tell a legitimate mu-plugin from a planted one without reading it, so the least this
     * screen can do is not make them go and find it over SFTP.
     *
     * Resolved through realpath() against the directory itself rather than by trusting the
     * name, so a path the browser sent cannot walk out of the folder it is supposed to name.
     *
     * @param array $fileConfig
     * @return array|\WP_Error
     */
    protected static function viewMuPluginFile($fileConfig)
    {
        if (!defined('WPMU_PLUGIN_DIR')) {
            return new \WP_Error(
                'invalid_data',
                __('This site has no must-use plugins directory.', 'fluent-security'),
                ['status' => 400]
            );
        }

        $expectedDir = realpath(WPMU_PLUGIN_DIR);
        $realPath = realpath(trailingslashit(WPMU_PLUGIN_DIR) . ltrim($fileConfig['file'], '/'));

        if (!$expectedDir || !$realPath || strpos($realPath, $expectedDir . DIRECTORY_SEPARATOR) !== 0) {
            return new \WP_Error(
                'invalid_data',
                __('This file could not be viewed for security reason.', 'fluent-security'),
                ['status' => 400]
            );
        }

        if (!is_file($realPath) || strtolower(pathinfo($realPath, PATHINFO_EXTENSION)) !== 'php') {
            return new \WP_Error(
                'invalid_data',
                __('This file could not be viewed.', 'fluent-security'),
                ['status' => 400]
            );
        }

        $viewable = self::assertViewableFile($realPath, basename($realPath));

        if (is_wp_error($viewable)) {
            return $viewable;
        }

        return [
            'filePath'            => str_replace(ABSPATH, '/', $realPath),
            'fileContent'         => self::readFileContents($realPath),
            'hasDiff'             => false,
            'originalFileContent' => ''
        ];
    }

    /**
     * Where a core file the browser has named actually is, if it is anywhere allowed.
     *
     * Its own method because two things now act on the answer - the viewer and the restore -
     * and they must not be able to disagree about it. A restore that resolved paths through
     * its own copy of these rules would be one refactor away from writing somewhere the
     * viewer would never have read from.
     *
     * @param array $fileConfig
     * @param bool $forViewing whether the answer is going on the page - see assertAllowedFile()
     * @return array|\WP_Error
     */
    protected static function resolveCoreFile($fileConfig, $forViewing = true)
    {
        $file = $fileConfig['file'];
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
            // Allow nested paths for wp-admin/wp-includes, realpath() ensures containment
            $filePath = ABSPATH . $folder . '/' . $file;
            $expectedDir = realpath(ABSPATH . $folder);
        } else {
            // Root folder: strip directory components to prevent traversal
            $file = basename($file);
            $filePath = ABSPATH . $file;
            $expectedDir = realpath(ABSPATH);
        }

        $realPath = realpath($filePath);

        if (!$realPath || !$expectedDir || strpos($realPath, $expectedDir . DIRECTORY_SEPARATOR) !== 0) {
            return new \WP_Error('invalid_data', __('This file could not be viewed for security reason.', 'fluent-security'), ['status' => 400, 'data' => $file]);
        }

        $allowed = $forViewing
            ? self::assertViewableFile($realPath, $file)
            : self::assertAllowedFile($realPath, $file);

        if (is_wp_error($allowed)) {
            return $allowed;
        }

        $remotePath = str_replace(ABSPATH, '', $realPath);

        if ($isInc) {
            $remotePath = str_replace(WPINC, 'wp-includes', $remotePath);
        }

        return [
            'path'        => $realPath,
            'remote_path' => $remotePath,
            'display'     => str_replace(ABSPATH, '/', $realPath)
        ];
    }

    /*
     * One file inside a plugin or theme, against the copy wordpress.org published.
     *
     * The plugin or theme is looked up in the inventory by the key the browser sends, and the
     * directory to read from comes from that lookup - never from the request. So the only
     * thing the caller controls is a path *within* an installed extension, and realpath()
     * containment settles whether it really is within one.
     */
    protected static function viewExtensionFileDiff($fileConfig)
    {
        $resolved = self::resolveExtensionFile($fileConfig);

        if (is_wp_error($resolved)) {
            return $resolved;
        }

        $target = $resolved['target'];
        $remoteContent = '';

        if (Arr::get($fileConfig, 'status') === 'modified') {
            $remoteContent = Api::getExtensionFileContent(
                $target['type'],
                $target['slug'],
                $target['version'],
                $resolved['file']
            );

            if (is_wp_error($remoteContent)) {
                return new \WP_Error('invalid_data', __('Sorry, we could not fetch the original file from WordPress.org.', 'fluent-security'), ['status' => 400]);
            }
        }

        return [
            'filePath'            => $resolved['display'],
            'fileContent'         => self::readFileContents($resolved['path']),
            'hasDiff'             => !!$remoteContent,
            'originalFileContent' => $remoteContent
        ];
    }

    /**
     * Where a file inside an installed plugin or theme is, if it is inside one.
     *
     * The directory comes from the inventory rather than from the request, so the caller only
     * ever controls a path *within* an installed extension - and realpath() containment
     * settles whether it really is within one. Shared with the restore for the same reason
     * resolveCoreFile() is.
     *
     * @param array $fileConfig
     * @param bool $forViewing whether the answer is going on the page - see assertAllowedFile()
     * @return array|\WP_Error
     */
    protected static function resolveExtensionFile($fileConfig, $forViewing = true)
    {
        $type = Arr::get($fileConfig, 'type') === 'theme' ? 'theme' : 'plugin';
        $key = Arr::get($fileConfig, 'key');
        $file = Arr::get($fileConfig, 'file');

        if (!is_string($key) || !$key) {
            return new \WP_Error('invalid_data', __('Please provide the plugin or theme to view.', 'fluent-security'), ['status' => 400]);
        }

        $target = null;
        foreach (ExtensionInventory::getTargets() as $candidate) {
            if ($candidate['type'] === $type && $candidate['key'] === $key) {
                $target = $candidate;
                break;
            }
        }

        if (!$target) {
            return new \WP_Error('invalid_data', __('That plugin or theme is not installed on this site.', 'fluent-security'), ['status' => 404]);
        }

        /* A single-file plugin *is* the file, so there is no path to append. */
        if (!empty($target['single_file'])) {
            $filePath = $target['path'];
            $expectedDir = realpath(dirname($target['path']));
        } else {
            $filePath = rtrim($target['path'], '/') . '/' . $file;
            $expectedDir = realpath($target['path']);
        }

        $realPath = realpath($filePath);

        if (!$realPath || !$expectedDir || strpos($realPath, $expectedDir . DIRECTORY_SEPARATOR) !== 0) {
            return new \WP_Error('invalid_data', __('This file could not be viewed for security reason.', 'fluent-security'), ['status' => 400]);
        }

        $allowed = $forViewing
            ? self::assertViewableFile($realPath, $file)
            : self::assertAllowedFile($realPath, $file);

        if (is_wp_error($allowed)) {
            return $allowed;
        }

        return [
            'path'    => $realPath,
            'file'    => $file,
            'target'  => $target,
            'display' => '/' . trim($target['rel_path'], '/') . '/' . $file
        ];
    }

    /**
     * Put one file back to what WordPress.org published.
     *
     * One file, and only ever one that was modified. A file the scan calls "new" has no
     * original to be put back to - restoring it would mean deleting it, which is a different
     * decision with a different consequence, and it is not going to be made by a button
     * labelled the same as this one.
     *
     * The official copy is fetched before anything is touched, and the result is verified by
     * reading the file back afterwards. A write that the filesystem accepted and did not
     * perform, or performed partially, must not report success - this is somebody repairing a
     * compromised site, and "restored" has to mean it.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function restoreFile(\WP_REST_Request $request)
    {
        $fileConfig = $request->get_param('viewing_file');

        if (!$fileConfig || empty($fileConfig['file']) || empty($fileConfig['status'])) {
            return new \WP_Error('invalid_data', __('Please provide a valid file name and status.', 'fluent-security'), ['status' => 400]);
        }

        if (Arr::get($fileConfig, 'status') !== 'modified') {
            return new \WP_Error(
                'not_restorable',
                __('This file is not part of the official release, so there is no original to put back. Look at it and decide whether it belongs there.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $isExtension = Arr::get($fileConfig, 'scope') === 'extension';

        $resolved = $isExtension
            ? self::resolveExtensionFile($fileConfig)
            : self::resolveCoreFile($fileConfig);

        if (is_wp_error($resolved)) {
            return $resolved;
        }

        if ($isExtension) {
            $target = $resolved['target'];
            $original = Api::getExtensionFileContent(
                $target['type'],
                $target['slug'],
                $target['version'],
                $resolved['file']
            );
        } else {
            $original = Api::getFileContentFromGithub($resolved['remote_path']);
        }

        if (is_wp_error($original) || !is_string($original)) {
            return new \WP_Error(
                'no_original',
                __('The official copy of this file could not be fetched, so nothing has been changed.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (!is_writable($resolved['path'])) {
            return new \WP_Error(
                'not_writable',
                __('This file cannot be written to from here. Your host or your file permissions will need to allow it.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $written = @file_put_contents($resolved['path'], $original);

        clearstatcache(true, $resolved['path']);

        /*
         * Verified by reading it back rather than trusting the return value: a short write is
         * reported as a byte count, not as a failure, and a file left half replaced is worse
         * than one left alone.
         */
        if ($written === false || md5_file($resolved['path']) !== md5($original)) {
            return new \WP_Error(
                'restore_failed',
                __('The file could not be replaced properly. Check it before relying on this site.', 'fluent-security'),
                ['status' => 500]
            );
        }

        return [
            'message' => sprintf(
                /* translators: %s: a file path */
                __('%s has been put back to the official version.', 'fluent-security'),
                $resolved['display']
            ),
            'path'    => $resolved['display']
        ];
    }

    /**
     * Delete one file that should not be there.
     *
     * Permanent, and the screen says so before it runs. Nothing is kept: the alternative was a
     * quarantine copy under wp-content/uploads, and a copy of a webshell inside the webroot is
     * a liability of its own - `.htaccess` denies nothing on nginx, so the thing just taken off
     * the server would still be readable over HTTP. A file the site's owner wants back comes
     * back from their backup, which is the one copy that is not sitting where the attacker can
     * reach it.
     *
     * So the guards do the work instead, and there are three.
     *
     * Only ever a file the last scan called "new". A modified file has an official copy to be
     * put back to, and that is what the restore is for; a file that is missing is not there to
     * delete. "New" is the only finding whose answer is that the file should not exist.
     *
     * The browser's word for that is not taken. The finding is looked up in the stored results
     * of the last scan and has to say "new" there too, so a stale row, a mistyped path or a
     * request built by hand cannot talk this into deleting a file that belongs to WordPress.
     * The ignore list is not consulted: ignoring a finding is a decision to stop being told
     * about it, not a decision about what may be done to the file.
     *
     * And the path is resolved the way the viewer resolves it, so the names this refuses to
     * show are also the names it refuses to delete - wp-config.php above all.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function deleteFile(\WP_REST_Request $request)
    {
        $fileConfig = $request->get_param('viewing_file');

        if (!$fileConfig || empty($fileConfig['file']) || empty($fileConfig['status'])) {
            return new \WP_Error('invalid_data', __('Please provide a valid file name and status.', 'fluent-security'), ['status' => 400]);
        }

        if (Arr::get($fileConfig, 'status') !== 'new') {
            return new \WP_Error(
                'not_removable',
                __('Only a file that is not part of the official release can be deleted. This one has an official copy, so put it back instead.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $isExtension = Arr::get($fileConfig, 'scope') === 'extension';

        $resolved = $isExtension
            ? self::resolveExtensionFile($fileConfig, false)
            : self::resolveCoreFile($fileConfig, false);

        if (is_wp_error($resolved)) {
            return $resolved;
        }

        $label = ltrim($isExtension ? $resolved['display'] : str_replace(ABSPATH, '/', $resolved['path']), '/');

        $confirmed = $isExtension
            ? self::isExtensionFindingNew($resolved)
            : self::isCoreFindingNew($label);

        if (!$confirmed) {
            return new \WP_Error(
                'not_a_finding',
                __('The last scan does not list this file as one that is not part of the official release. Run the scan again, then look at it there.', 'fluent-security'),
                ['status' => 409]
            );
        }

        /* WordPress's own, so a host that filters file deletion still gets its say. */
        wp_delete_file($resolved['path']);

        clearstatcache(true, $resolved['path']);

        /*
         * Checked by looking, not by trusting a return value - wp_delete_file() has none to
         * trust. Somebody is clearing up after a break-in and "deleted" has to mean it.
         */
        if (file_exists($resolved['path'])) {
            return new \WP_Error(
                'delete_failed',
                __('This file could not be deleted. Your host or your file permissions will need to allow it, and nothing has been changed.', 'fluent-security'),
                ['status' => 422]
            );
        }

        RecoveryService::log(
            'delete_file',
            sprintf(
                /* translators: %s: a file path */
                __('Permanently deleted %s from the monitoring screen.', 'fluent-security'),
                '/' . $label
            )
        );

        return [
            'message' => sprintf(
                /* translators: %s: a file path */
                __('%s has been deleted from the server.', 'fluent-security'),
                '/' . $label
            ),
            'path'    => '/' . $label
        ];
    }

    /**
     * Whether the last core scan listed this exact path as not part of the release.
     *
     * Read from the stored results rather than from getActiveCoreFindings(), which drops
     * whatever is on the ignore list - see the note in deleteFile() about why that list has
     * no say here.
     *
     * @param string $label root-relative path, no leading slash
     * @return bool
     */
    protected static function isCoreFindingNew($label)
    {
        $files = (array)Arr::get(IntegrityHelper::getCoreResults(), 'files', []);

        /*
         * Indexed directly rather than through Arr::get(), which reads a dot in a key as a
         * step down into the array - and every one of these keys is a file name.
         */
        return isset($files[$label]['status']) && $files[$label]['status'] === 'new';
    }

    /**
     * The same question for a file inside a plugin or theme.
     *
     * @param array $resolved the answer from resolveExtensionFile()
     * @return bool
     */
    protected static function isExtensionFindingNew($resolved)
    {
        $key = IntegrityHelper::getResultKey($resolved['target']);
        $results = IntegrityHelper::getExtensionResults();
        $files = isset($results[$key]['files']) ? (array)$results[$key]['files'] : [];
        $file = $resolved['file'];

        /* Indexed directly, for the reason given in isCoreFindingNew(). */
        return isset($files[$file]['status']) && $files[$file]['status'] === 'new';
    }

    /*
     * Whether a file is one this screen will ever put on the page.
     *
     * Shared by the core and extension viewers so a rule added for one applies to both. Path
     * containment is not checked here - each caller knows the directory a file is supposed to
     * be under, and has already established it.
     */
    protected static function assertViewableFile($filePath, $displayName)
    {
        $allowed = self::assertAllowedFile($filePath, $displayName);

        if (is_wp_error($allowed)) {
            return $allowed;
        }

        $maxFileSize = 2 * 1024 * 1024; // 2MB
        if (filesize($filePath) > $maxFileSize) {
            return new \WP_Error('invalid_data', __('This file is too large to be viewed.', 'fluent-security'), ['status' => 400, 'data' => $displayName]);
        }

        if (!is_readable($filePath)) {
            return new \WP_Error('invalid_data', __('This file is not readable.', 'fluent-security'), ['status' => 400, 'data' => $displayName]);
        }

        return true;
    }

    /*
     * Whether this screen may act on the file at all - read it, put it back, or move it out
     * of the way.
     *
     * Split out from assertViewableFile() when removal arrived, because the two halves are
     * asked for different reasons. These rules are about which files this screen is allowed
     * to touch: a file whose name says it holds credentials is not one of them, whatever is
     * being done to it, so wp-config.php cannot be removed any more than it can be read. The
     * rules left with the viewer are about whether a file can usefully be put on a page - a
     * five megabyte payload is unreadable but perfectly removable, and refusing to move it
     * because it would not fit in a textarea would be a strange thing to tell somebody.
     */
    protected static function assertAllowedFile($filePath, $displayName)
    {
        $sensitivePatterns = [
            'wp-config',
            '.htaccess',
            '.env',
            'debug.log',
            'error_log',
            'php_errorlog',
            '.user.ini',
            '.php.ini',
            'php.ini',
            '.ftpconfig',
            '.ssh',
        ];

        $backupExtensions = ['.bak', '.back', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.copy', '~'];

        $fileLower = strtolower($displayName);

        foreach ($sensitivePatterns as $pattern) {
            if (strpos($fileLower, $pattern) !== false) {
                return new \WP_Error('invalid_data', __('This file could not be viewed.', 'fluent-security'), ['status' => 400, 'data' => $displayName]);
            }
        }

        foreach ($backupExtensions as $ext) {
            if (substr($fileLower, -strlen($ext)) === $ext) {
                return new \WP_Error('invalid_data', __('This file could not be viewed.', 'fluent-security'), ['status' => 400, 'data' => $displayName]);
            }
        }

        if (!file_exists($filePath)) {
            return new \WP_Error('invalid_data', __('This file could not be viewed.', 'fluent-security'), ['status' => 400, 'data' => $displayName]);
        }

        return true;
    }

    protected static function readFileContents($filePath)
    {
        require_once(ABSPATH . 'wp-admin/includes/file.php');
        WP_Filesystem();
        global $wp_filesystem;

        return $wp_filesystem->get_contents($filePath);
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
        $settings['relay_rejection'] = '';
        $settings['relay_rejected_at'] = '';
        $settings['relay_auth_failures'] = 0;

        IntegrityHelper::saveSettings($settings);

        return [
            'message'  => __('API has been reset successfully.', 'fluent-security'),
            'settings' => $settings
        ];
    }

    /*
     * Start reporting again after the owner re-enabled this site on the alerts dashboard.
     *
     * Verified rather than assumed. The stored key is still the right one - a disabled site
     * keeps its row - so a report is the probe: if the site is live again the relay takes it,
     * and if it is still disabled the same 403 puts the screen straight back where it was
     * instead of leaving it claiming a connection that does not work.
     *
     * Built from the last scan's findings rather than a fresh scan. Re-scanning would mean
     * fetching core checksums and walking wp-content while the browser waits, to learn
     * something this request is not asking about.
     */
    public static function resumeReporting(\WP_REST_Request $request)
    {
        $settings = IntegrityHelper::getSettings();

        if ($settings['relay_rejection'] !== IntegrityHelper::RELAY_DISABLED) {
            return new \WP_Error('invalid_state', __('This site is not waiting to be reconnected.', 'fluent-security'), ['status' => 400]);
        }

        /*
         * Put back in good standing first, so the probe below is sent as a connected site
         * would send it - and so a relay that refuses it again writes the rejection over
         * this, rather than this being written over the rejection.
         */
        $settings['status'] = 'active';
        $settings['auto_scan'] = 'yes';
        $settings['relay_rejection'] = '';
        $settings['relay_rejected_at'] = '';
        $settings['relay_auth_failures'] = 0;

        IntegrityHelper::saveSettings($settings);

        $response = IntegrityHelper::sendStoredReport();

        $settings = IntegrityHelper::getSettings();

        if ($settings['relay_rejection'] === IntegrityHelper::RELAY_DISABLED) {
            return new \WP_Error('still_disabled', __('This site is still disabled on your alerts dashboard. Re-enable it there, then try again.', 'fluent-security'), ['status' => 409, 'data' => ['settings' => $settings]]);
        }

        /*
         * The relay was unreachable, or answered with something that says nothing about this
         * site - a timeout, a 429, a 500. Reporting is switched back on and the schedule will
         * settle it, but saying "your dashboard is receiving this site again" on the strength
         * of a request that failed would be a claim nothing here can make.
         */
        $code = is_wp_error($response) ? 0 : (int)wp_remote_retrieve_response_code($response);

        if ($code < 200 || $code >= 300) {
            return new \WP_Error('probe_failed', __('Reporting has been switched back on, but your alerts dashboard could not be reached to confirm it. The next scheduled scan will try again.', 'fluent-security'), ['status' => 502, 'data' => ['settings' => $settings]]);
        }

        return [
            'message'  => __('Reporting has resumed. Your alerts dashboard is receiving this site again.', 'fluent-security'),
            'settings' => $settings
        ];
    }
}
