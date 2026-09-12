<?php

namespace FluentAuth\App\Services\Recovery;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\Checks\Files\MuPluginsCheck;
use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\ExtensionChecker;
use FluentAuth\App\Services\IntegrityChecker\ExtensionInventory;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * Putting files back after somebody has been in.
 *
 * The scan can say which files differ from what WordPress.org published. This is the half
 * that does something about it, and it does the coarse thing on purpose: WordPress is
 * reinstalled whole, a plugin is reinstalled whole. The one-file restore on the scan screen
 * is for somebody who has read a diff and wants to put back exactly that; somebody who has
 * just been hacked wants every file in wp-includes to be the official one, and does not want
 * to press a button forty times to get there.
 *
 * Nothing here writes a file of its own. WordPress's own upgrader does the copying, the same
 * code path as the Updates screen's "Re-install" button and the plugin uploader's "Replace
 * current with uploaded", so the filesystem handling, the maintenance mode and the cache
 * clearing are the ones every site already relies on.
 *
 * And nothing is deleted. A reinstall removes whatever was in the folder that the official
 * copy does not contain - which is the point, a dropped webshell is exactly that - but it is
 * also how a file somebody put there on purpose disappears. So the extras are moved to a
 * quarantine folder first, renamed so they cannot run, and listed in the log. Deleting the
 * quarantine is a decision for later, made by a person who is no longer frightened.
 */
class FileRecovery
{
    const QUARANTINE_DIR = 'fluent-auth-quarantine';

    const QUARANTINE_SUFFIX = '.quarantined';

    /**
     * What the recovery screen's file step shows.
     *
     * Read from the last scan rather than by scanning - see IntegrityHelper::getCoreResults().
     * The screen says when that was, and the reinstall actions re-check for themselves before
     * touching anything.
     *
     * @return array
     */
    public static function summary()
    {
        $core = IntegrityHelper::getCoreResults();
        $settings = IntegrityHelper::getSettings();

        $checkedAt = !empty($core['checked_at']) ? $core['checked_at'] : Arr::get($settings, 'last_checked', '');

        return [
            'scanned'      => !empty($checkedAt),
            'checked_at'   => $checkedAt,
            'checked_human' => $checkedAt
                ? human_time_diff(strtotime($checkedAt), current_time('timestamp'))
                : '',
            'core'         => self::coreSummary(),
            'extensions'   => self::extensionSummaries(),
            'unverifiable' => self::unverifiable(),
            'quarantine'   => self::quarantineSummary()
        ];
    }

    /**
     * @return array
     */
    protected static function coreSummary()
    {
        global $wp_version;

        $results = IntegrityHelper::getCoreResults();
        $active = IntegrityHelper::getActiveCoreFindings();

        $counts = ['modified' => 0, 'new' => 0, 'deleted' => 0];
        $removable = 0;
        $sample = [];

        foreach ($active as $file => $data) {
            $status = Arr::get($data, 'status', 'modified');

            if (isset($counts[$status])) {
                $counts[$status]++;
            }

            if ($status === 'new' && self::isInsideCoreDirectory($file)) {
                $removable++;
            }

            if (count($sample) < 20) {
                $sample[] = ['path' => $file, 'status' => $status];
            }
        }

        $truncated = (int)Arr::get($results, 'truncated', 0);
        $offer = static::coreOffer(false);

        return [
            'version'   => $wp_version,
            'checked'   => !empty($results['checked_at']),
            'files'     => count($active) + $truncated,
            'modified'  => $counts['modified'],
            'new'       => $counts['new'],
            'deleted'   => $counts['deleted'],
            /* Extras inside wp-admin or wp-includes: the ones a reinstall will quarantine. */
            'removable' => $removable,
            /*
             * What a reinstall would actually change. An extra file at the root - a favicon,
             * a verification page, a stray script - is left where it is, so a site whose only
             * findings are those has nothing for the button to do, and is told so instead.
             */
            'fixable'   => $counts['modified'] + $counts['deleted'] + $removable + $truncated,
            'truncated' => $truncated,
            'folders'   => array_values((array)Arr::get($results, 'folders', [])),
            'sample'    => $sample,
            /*
             * Whether "reinstall" is on offer at all, from the update check WordPress has
             * already made. Not forced here: a page load must not wait on api.wordpress.org,
             * and the action re-asks before it does anything.
             */
            'reinstallable' => (bool)$offer,
            'blocked'       => $offer ? '' : self::coreBlockedReason(),
            'update_url'    => admin_url('update-core.php')
        ];
    }

    /**
     * One row per plugin or theme the last scan had something to say about.
     *
     * @return array
     */
    protected static function extensionSummaries()
    {
        $ignored = array_map(function ($file) {
            return ltrim($file, '/');
        }, Arr::get(IntegrityHelper::getIgnoreLists(), 'files', []));

        $targets = [];
        foreach (ExtensionInventory::getTargets() as $target) {
            $targets[IntegrityHelper::getResultKey($target)] = $target;
        }

        $rows = [];

        foreach (IntegrityHelper::getExtensionResults() as $key => $result) {
            /* Something no longer installed has nothing to reinstall. */
            if (!isset($targets[$key])) {
                continue;
            }

            $target = $targets[$key];
            $relPath = Arr::get($result, 'rel_path', '');

            if (IntegrityHelper::isExtensionIgnored($relPath)) {
                continue;
            }

            $suspicious = empty($result['verifiable'])
                && !empty($result['reason'])
                && ExtensionInventory::getReasonSeverity($result['reason']) === 'suspicious';

            $counts = ['modified' => 0, 'new' => 0, 'deleted' => 0];
            $files = 0;

            if (!empty($result['verifiable'])) {
                foreach ((array)Arr::get($result, 'files', []) as $file => $data) {
                    if (in_array(trim($relPath, '/') . '/' . $file, $ignored, true)) {
                        continue;
                    }

                    $files++;
                    $status = Arr::get($data, 'status', 'modified');

                    if (isset($counts[$status])) {
                        $counts[$status]++;
                    }
                }

                $files += (int)Arr::get($result, 'truncated', 0);
            }

            if (!$files && !$suspicious) {
                continue;
            }

            $blocked = self::extensionBlockedReason($target);

            $rows[] = [
                'type'          => $target['type'],
                'key'           => $target['key'],
                'slug'          => $target['slug'],
                'name'          => $target['name'],
                'version'       => $target['version'],
                'rel_path'      => $relPath,
                'active'        => self::isExtensionActive($target),
                'files'         => $files,
                'modified'      => $counts['modified'],
                'new'           => $counts['new'],
                'deleted'       => $counts['deleted'],
                'truncated'     => (int)Arr::get($result, 'truncated', 0),
                'suspicious'    => $suspicious,
                'reason_label'  => $suspicious ? ExtensionInventory::getReasonLabel($result['reason']) : '',
                'reinstallable' => !$blocked,
                'blocked'       => $blocked
            ];
        }

        usort($rows, function ($a, $b) {
            if ($a['suspicious'] !== $b['suspicious']) {
                return $a['suspicious'] ? -1 : 1;
            }

            return strcasecmp($a['name'], $b['name']);
        });

        return $rows;
    }

    /**
     * The files no checksum covers, so nobody can put them back for you.
     *
     * Listed rather than left out. A page that says "every file matches WordPress.org" over
     * a wp-config.php with a second database user in it is telling the truth in a way that
     * misleads, and these four places are where a persistent way back in usually lives.
     *
     * @return array
     */
    protected static function unverifiable()
    {
        $items = [];

        $config = file_exists(ABSPATH . 'wp-config.php')
            ? ABSPATH . 'wp-config.php'
            : dirname(ABSPATH) . '/wp-config.php';

        if (file_exists($config)) {
            $items[] = [
                'key'      => 'wp-config',
                'label'    => 'wp-config.php',
                'detail'   => __('Holds your database password and salts. Read it for anything you did not put there.', 'fluent-security'),
                'modified' => self::modifiedHuman($config)
            ];
        }

        if (file_exists(ABSPATH . '.htaccess')) {
            $items[] = [
                'key'      => 'htaccess',
                'label'    => '.htaccess',
                'detail'   => __('Can redirect visitors or hand requests to another file. Read it for rules you do not recognise.', 'fluent-security'),
                'modified' => self::modifiedHuman(ABSPATH . '.htaccess')
            ];
        }

        $muPlugins = MuPluginsCheck::phpFiles();

        if ($muPlugins) {
            $latest = 0;
            foreach ($muPlugins as $path) {
                $latest = max($latest, (int)@filemtime($path));
            }

            $items[] = [
                'key'      => 'mu-plugins',
                'label'    => sprintf(
                    /* translators: %s: number of files */
                    _n('%s must-use plugin', '%s must-use plugins', count($muPlugins), 'fluent-security'),
                    number_format_i18n(count($muPlugins))
                ),
                'detail'   => __('Run on every request and cannot be deactivated. Listed under Monitoring, where each one can be read.', 'fluent-security'),
                'modified' => $latest
                    ? sprintf(
                        /* translators: %s: a length of time, for example "3 days" */
                        __('%s ago', 'fluent-security'),
                        human_time_diff($latest, current_time('timestamp'))
                    )
                    : '',
                'route'    => 'security_scans'
            ];
        }

        $dropIns = self::dropIns();

        if ($dropIns) {
            $latest = 0;
            foreach ($dropIns as $path) {
                $latest = max($latest, (int)@filemtime($path));
            }

            $items[] = [
                'key'      => 'drop-ins',
                'label'    => sprintf(
                    /* translators: %s: number of files */
                    _n('%s drop-in', '%s drop-ins', count($dropIns), 'fluent-security'),
                    number_format_i18n(count($dropIns))
                ),
                'detail'   => implode(', ', array_map('basename', $dropIns)),
                'modified' => $latest
                    ? sprintf(
                        /* translators: %s: a length of time, for example "3 days" */
                        __('%s ago', 'fluent-security'),
                        human_time_diff($latest, current_time('timestamp'))
                    )
                    : ''
            ];
        }

        return $items;
    }

    /**
     * Reinstall WordPress at the version already installed.
     *
     * The same thing the Updates screen's "Re-install" does, with one addition: a file inside
     * wp-admin or wp-includes that the official release does not contain is moved to
     * quarantine first. The reinstall alone would leave it there - the upgrader copies over
     * what it ships and removes only the files it knows old versions had - and a webshell in
     * wp-includes is the single most common thing a reinstall is being asked to get rid of.
     *
     * Only the current release can be reinstalled, because that is the only package the
     * update check offers. An older site is told to update instead, which replaces every
     * core file just as thoroughly - and is a decision that gets made on purpose, not as a
     * side effect of a button labelled something else.
     *
     * @return array|\WP_Error
     */
    public static function reinstallCore()
    {
        global $wp_version;

        $offer = static::coreOffer(true);

        if (!$offer) {
            return new \WP_Error(
                'not_available',
                self::coreBlockedReason(),
                ['status' => 422, 'url' => admin_url('update-core.php')]
            );
        }

        try {
            $checker = static::coreChecker();
        } catch (\Exception $exception) {
            return new \WP_Error(
                'checksums_unavailable',
                __('The official checksums for this version of WordPress could not be fetched, so nothing has been changed. Try again in a moment.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $extras = [];

        foreach ($checker->getActiveModifiedFiles(false) as $file => $data) {
            if (Arr::get($data, 'status') === 'new' && self::isInsideCoreDirectory($file)) {
                $extras[ABSPATH . $file] = $file;
            }
        }

        $quarantine = self::quarantine($extras, 'core');

        if (is_wp_error($quarantine)) {
            return $quarantine;
        }

        $offer->response = 'reinstall';

        $result = static::runCoreUpgrade($offer);

        if ($result === false) {
            return self::filesystemError($quarantine);
        }

        if (is_wp_error($result)) {
            return new \WP_Error(
                'reinstall_failed',
                sprintf(
                    /* translators: %s: the reason WordPress gave */
                    __('WordPress could not be reinstalled: %s', 'fluent-security'),
                    $result->get_error_message()
                ),
                ['status' => 500, 'quarantined' => $quarantine['moved']]
            );
        }

        /* Verified by looking again, not by trusting the upgrader's word for it. */
        $remaining = static::rescanCore();

        RecoveryService::log(
            'reinstall_core',
            sprintf(
                /* translators: 1: WordPress version, 2: number of files moved to quarantine, 3: number of files still differing */
                __('Reinstalled WordPress %1$s. %2$s unexpected files moved to quarantine, %3$s files still differ.', 'fluent-security'),
                $wp_version,
                number_format_i18n(count($quarantine['moved'])),
                number_format_i18n($remaining)
            )
        );

        return [
            'message'     => $remaining
                ? sprintf(
                    /* translators: 1: WordPress version, 2: number of files */
                    __('WordPress %1$s has been reinstalled. %2$s files still differ - see Monitoring.', 'fluent-security'),
                    $wp_version,
                    number_format_i18n($remaining)
                )
                : sprintf(
                    /* translators: %s: WordPress version */
                    __('WordPress %s has been reinstalled and every core file now matches the official release.', 'fluent-security'),
                    $wp_version
                ),
            'quarantined' => $quarantine['moved'],
            'failed'      => $quarantine['failed'],
            'remaining'   => $remaining,
            'files'       => self::summary()
        ];
    }

    /**
     * Reinstall one plugin or theme from WordPress.org.
     *
     * The target comes from the inventory, never from the request: what gets deleted is a
     * directory and what gets fetched is a slug, and neither is something the browser should
     * be able to name. The extension's folder is replaced whole, so its extras are moved to
     * quarantine first - see the class comment.
     *
     * Reinstalled at the version installed, so nothing changes but the files. The exception is
     * an extension on a version the directory never published: there is no official copy of
     * that version to install, so the current release is installed instead, and the message
     * says so.
     *
     * @param string $type plugin|theme
     * @param string $key  the plugin file or theme stylesheet
     * @return array|\WP_Error
     */
    public static function reinstallExtension($type, $key)
    {
        $type = $type === 'theme' ? 'theme' : 'plugin';
        $target = self::findTarget($type, $key);

        if (!$target) {
            return new \WP_Error(
                'not_installed',
                __('That plugin or theme is not installed on this site.', 'fluent-security'),
                ['status' => 404]
            );
        }

        $blocked = self::extensionBlockedReason($target);

        if ($blocked) {
            return new \WP_Error('not_reinstallable', $blocked, ['status' => 422]);
        }

        /* Checked again now rather than trusting a scan from last night. */
        $result = (new ExtensionChecker())->scan($target);

        $package = self::packageUrl($target, $result);

        if (is_wp_error($package)) {
            return $package;
        }

        $extras = [];

        if (!empty($result['verifiable'])) {
            foreach ((array)Arr::get($result, 'files', []) as $file => $data) {
                if (Arr::get($data, 'status') === 'new') {
                    $extras[rtrim($target['path'], '/') . '/' . $file] = trim($target['rel_path'], '/') . '/' . $file;
                }
            }
        }

        $quarantine = self::quarantine($extras, $type . '-' . $target['slug']);

        if (is_wp_error($quarantine)) {
            return $quarantine;
        }

        $installed = static::runExtensionInstall($type, $package['url']);

        if ($installed === false || $installed === null) {
            return self::filesystemError($quarantine);
        }

        if (is_wp_error($installed)) {
            return new \WP_Error(
                'reinstall_failed',
                sprintf(
                    /* translators: 1: plugin or theme name, 2: the reason WordPress gave */
                    __('%1$s could not be reinstalled: %2$s', 'fluent-security'),
                    $target['name'],
                    $installed->get_error_message()
                ),
                ['status' => 500, 'quarantined' => $quarantine['moved']]
            );
        }

        /*
         * Looked up afresh: the version header may have changed, and the upgrader has cleared
         * the plugin cache so the inventory reads the new files rather than the old list.
         */
        $fresh = self::findTarget($type, $key);
        $remaining = 0;

        if ($fresh) {
            $stored = IntegrityHelper::storeExtensionResult((new ExtensionChecker())->scan($fresh));
            $remaining = count((array)Arr::get($stored, 'files', [])) + (int)Arr::get($stored, 'truncated', 0);
        }

        RecoveryService::log(
            'reinstall_' . $type,
            sprintf(
                /* translators: 1: plugin or theme name, 2: version, 3: number of files moved to quarantine, 4: number of files still differing */
                __('Reinstalled %1$s %2$s from WordPress.org. %3$s unexpected files moved to quarantine, %4$s files still differ.', 'fluent-security'),
                $target['name'],
                $fresh ? $fresh['version'] : $target['version'],
                number_format_i18n(count($quarantine['moved'])),
                number_format_i18n($remaining)
            )
        );

        if ($package['latest']) {
            $message = sprintf(
                /* translators: 1: plugin or theme name, 2: the version now installed */
                __('%1$s has been replaced with the current WordPress.org release, %2$s.', 'fluent-security'),
                $target['name'],
                $fresh ? $fresh['version'] : ''
            );
        } elseif ($remaining) {
            $message = sprintf(
                /* translators: 1: plugin or theme name, 2: number of files */
                __('%1$s has been reinstalled, but %2$s files still differ - see Monitoring.', 'fluent-security'),
                $target['name'],
                number_format_i18n($remaining)
            );
        } else {
            $message = sprintf(
                /* translators: %s: plugin or theme name */
                __('%s has been reinstalled and every file now matches WordPress.org.', 'fluent-security'),
                $target['name']
            );
        }

        return [
            'message'     => $message,
            'quarantined' => $quarantine['moved'],
            'failed'      => $quarantine['failed'],
            'remaining'   => $remaining,
            'files'       => self::summary()
        ];
    }

    /**
     * Where the quarantine lives, root-relative for display.
     *
     * @return string
     */
    public static function quarantinePath()
    {
        $upload = wp_upload_dir(null, false);

        return trailingslashit($upload['basedir']) . self::QUARANTINE_DIR;
    }

    /* ------------------------------------------------------------------ internals */

    /**
     * The package WordPress should install for this target.
     *
     * @param array $target
     * @param array $result the live scan of it
     * @return array|\WP_Error ['url' => string, 'latest' => bool]
     */
    protected static function packageUrl($target, $result)
    {
        if (!empty($result['verifiable'])) {
            $url = $target['type'] === 'theme'
                ? 'https://downloads.wordpress.org/theme/' . $target['slug'] . '.' . $target['version'] . '.zip'
                : 'https://downloads.wordpress.org/plugin/' . $target['slug'] . '.' . $target['version'] . '.zip';

            return ['url' => $url, 'latest' => false];
        }

        $reason = Arr::get($result, 'reason', '');

        if (ExtensionInventory::getReasonSeverity($reason) !== 'suspicious') {
            return new \WP_Error(
                'not_checked',
                sprintf(
                    /* translators: 1: plugin or theme name, 2: why it could not be checked */
                    __('%1$s could not be checked against WordPress.org just now (%2$s), so nothing has been changed.', 'fluent-security'),
                    $target['name'],
                    ExtensionInventory::getReasonLabel($reason)
                ),
                ['status' => 422]
            );
        }

        $url = self::latestPackageUrl($target);

        if (!$url) {
            return new \WP_Error(
                'no_package',
                sprintf(
                    /* translators: %s: plugin or theme name */
                    __('WordPress.org did not offer a download for %s, so nothing has been changed.', 'fluent-security'),
                    $target['name']
                ),
                ['status' => 422]
            );
        }

        return ['url' => $url, 'latest' => true];
    }

    /**
     * @param array $target
     * @return string
     */
    protected static function latestPackageUrl($target)
    {
        if ($target['type'] === 'theme') {
            require_once ABSPATH . 'wp-admin/includes/theme.php';

            $info = themes_api('theme_information', ['slug' => $target['slug'], 'fields' => ['sections' => false]]);
        } else {
            require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

            $info = plugins_api('plugin_information', ['slug' => $target['slug'], 'fields' => ['sections' => false]]);
        }

        if (is_wp_error($info) || !is_object($info) || empty($info->download_link)) {
            return '';
        }

        return (string)$info->download_link;
    }

    /**
     * Why this extension cannot be reinstalled from here, or nothing if it can.
     *
     * Public because the monitoring screen offers the same reinstall beside the changed files
     * it found, and the two screens must agree about which extensions it is on offer for. Ask
     * it of the inventory's own view of a target, before anything downgrades `verifiable` on
     * the strength of a scan result: a version WordPress.org never published is unverifiable
     * and reinstallable at the same time, and that is the whole point of offering it.
     *
     * @param array $target
     * @return string
     */
    public static function extensionBlockedReason($target)
    {
        if (empty($target['verifiable'])) {
            if (Arr::get($target, 'reason') === 'no_version') {
                return __('This has no version number, so there is no way to know which official copy to install.', 'fluent-security');
            }

            return __('Not from the WordPress.org directory, so there is no official copy to install. Reinstall it from the vendor or from your own backup.', 'fluent-security');
        }

        if (!empty($target['single_file'])) {
            return __('A single-file plugin. Put the file back from Monitoring rather than reinstalling.', 'fluent-security');
        }

        if (basename(rtrim($target['path'], '/')) !== $target['slug']) {
            return sprintf(
                /* translators: 1: the folder it is in, 2: the folder WordPress.org would use */
                __('Installed in a folder called %1$s, but WordPress.org would install it as %2$s, so a reinstall would leave two copies. Reinstall it by hand.', 'fluent-security'),
                basename(rtrim($target['path'], '/')),
                $target['slug']
            );
        }

        return '';
    }

    /**
     * The update offer for the installed version, if there is one.
     *
     * @param bool $fresh ask api.wordpress.org now rather than reading the cached answer
     * @return object|null
     */
    protected static function coreOffer($fresh)
    {
        global $wp_version;

        require_once ABSPATH . 'wp-admin/includes/update.php';

        if ($fresh) {
            wp_version_check([], true);
        }

        $offer = find_core_update($wp_version, get_locale());

        /* Translations live in wp-content, so the en_US package is the same core files. */
        if (!$offer && get_locale() !== 'en_US') {
            $offer = find_core_update($wp_version, 'en_US');
        }

        if (!$offer || !isset($offer->response) || $offer->response !== 'latest') {
            return null;
        }

        return $offer;
    }

    /**
     * @return string
     */
    protected static function coreBlockedReason()
    {
        global $wp_version;

        return sprintf(
            /* translators: %s: WordPress version */
            __('This site is on WordPress %s, and only the current release can be reinstalled from here. Update WordPress first - that replaces every core file too - then come back.', 'fluent-security'),
            $wp_version
        );
    }

    /**
     * The core checker, which fetches the official checksums as it is built.
     *
     * Its own method so a test can hand back one that already knows the answer.
     *
     * @return CheckerService
     * @throws \Exception when the checksums cannot be fetched
     */
    protected static function coreChecker()
    {
        return new CheckerService();
    }

    /**
     * Run the core reinstall. Its own method so a test can stand in for it.
     *
     * @param object $offer
     * @return string|false|\WP_Error
     */
    protected static function runCoreUpgrade($offer)
    {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/update.php';

        if (function_exists('set_time_limit')) {
            @set_time_limit(300);
        }

        $upgrader = new \Core_Upgrader(new \Automatic_Upgrader_Skin());

        return $upgrader->upgrade($offer, ['allow_relaxed_file_ownership' => false]);
    }

    /**
     * Run a plugin or theme reinstall. Its own method so a test can hand it a local package.
     *
     * @param string $type
     * @param string $package
     * @return bool|null|\WP_Error
     */
    protected static function runExtensionInstall($type, $package)
    {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        require_once ABSPATH . 'wp-admin/includes/theme.php';

        if (function_exists('set_time_limit')) {
            @set_time_limit(300);
        }

        $skin = new \Automatic_Upgrader_Skin();
        $upgrader = $type === 'theme' ? new \Theme_Upgrader($skin) : new \Plugin_Upgrader($skin);

        return $upgrader->install($package, [
            'overwrite_package'  => true,
            'clear_update_cache' => true
        ]);
    }

    /**
     * @return int files still differing after the reinstall
     */
    protected static function rescanCore()
    {
        try {
            $checker = static::coreChecker();
        } catch (\Exception $exception) {
            return 0;
        }

        IntegrityHelper::storeCoreResult($checker);

        return count($checker->getActiveModifiedFiles(false));
    }

    /**
     * Move files out of the way, keeping them.
     *
     * Each is renamed with a suffix PHP will not execute and kept under its original relative
     * path, next to a manifest saying where it came from. The folder is under uploads because
     * that is the one place every host lets WordPress write, and it gets the same two guard
     * files WordPress puts elsewhere - a denying .htaccess and an empty index.php.
     *
     * Every file is attempted; the ones that could not be moved are reported rather than
     * stopping the rest. A reinstall that follows will remove them anyway, and the caller
     * says which were kept and which were not.
     *
     * @param array  $files absolute path => root-relative label
     * @param string $reason a short slug for the folder name
     * @return array|\WP_Error ['moved' => [], 'failed' => [], 'dir' => string]
     */
    protected static function quarantine(array $files, $reason)
    {
        $moved = [];
        $failed = [];

        if (!$files) {
            return ['moved' => $moved, 'failed' => $failed, 'dir' => ''];
        }

        $root = self::quarantinePath();

        if (!wp_mkdir_p($root)) {
            return new \WP_Error(
                'quarantine_failed',
                __('The quarantine folder could not be created under uploads, so nothing has been changed.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (!file_exists($root . '/.htaccess')) {
            @file_put_contents(
                $root . '/.htaccess',
                "# Files moved here by FluentAuth. Nothing in this folder is served.\n"
                . "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n"
            );
        }

        if (!file_exists($root . '/index.php')) {
            @file_put_contents($root . '/index.php', "<?php\n// Silence is golden.\n");
        }

        $dir = $root . '/' . gmdate('Ymd-His') . '-' . sanitize_file_name($reason);

        if (!wp_mkdir_p($dir)) {
            return new \WP_Error(
                'quarantine_failed',
                __('The quarantine folder could not be created under uploads, so nothing has been changed.', 'fluent-security'),
                ['status' => 422]
            );
        }

        foreach ($files as $source => $label) {
            $destination = $dir . '/' . ltrim($label, '/') . self::QUARANTINE_SUFFIX;

            if (!is_file($source) || !wp_mkdir_p(dirname($destination))) {
                $failed[] = $label;
                continue;
            }

            $ok = @rename($source, $destination);

            if (!$ok && @copy($source, $destination)) {
                $ok = @unlink($source);
            }

            clearstatcache(true, $source);

            if ($ok && !file_exists($source) && is_file($destination)) {
                $moved[] = $label;
            } else {
                $failed[] = $label;
            }
        }

        @file_put_contents($dir . '/manifest.json', wp_json_encode([
            'moved_at' => gmdate('c'),
            'by'       => wp_get_current_user()->user_login,
            'reason'   => $reason,
            'files'    => $moved,
            'failed'   => $failed
        ], JSON_PRETTY_PRINT));

        return ['moved' => $moved, 'failed' => $failed, 'dir' => $dir];
    }

    /**
     * @return array
     */
    protected static function quarantineSummary()
    {
        $root = self::quarantinePath();
        $count = 0;

        if (is_dir($root)) {
            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
                );

                foreach ($iterator as $file) {
                    if ($file->isFile() && substr($file->getFilename(), -strlen(self::QUARANTINE_SUFFIX)) === self::QUARANTINE_SUFFIX) {
                        $count++;
                    }
                }
            } catch (\Exception $exception) {
                $count = 0;
            }
        }

        return [
            'files' => $count,
            'path'  => '/' . ltrim(ExtensionInventory::toRelativePath($root), '/')
        ];
    }

    /**
     * The upgrader said it needed filesystem credentials it does not have.
     *
     * @param array $quarantine
     * @return \WP_Error
     */
    protected static function filesystemError($quarantine)
    {
        return new \WP_Error(
            'not_writable',
            __('WordPress cannot write to its own files from here - your host needs FTP details or direct file access to be set up. Nothing has been reinstalled.', 'fluent-security'),
            ['status' => 422, 'quarantined' => $quarantine['moved']]
        );
    }

    /**
     * @param string $type
     * @param string $key
     * @return array|null
     */
    protected static function findTarget($type, $key)
    {
        if (!is_string($key) || $key === '') {
            return null;
        }

        foreach (ExtensionInventory::getTargets() as $candidate) {
            if ($candidate['type'] === $type && $candidate['key'] === $key) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * @param array $target
     * @return bool
     */
    protected static function isExtensionActive($target)
    {
        if ($target['type'] === 'theme') {
            return in_array($target['key'], [get_stylesheet(), get_template()], true);
        }

        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        return is_plugin_active($target['key']);
    }

    /**
     * Whether a root-relative core path is under wp-admin or wp-includes - the two places
     * nothing legitimate is ever added to, as opposed to the root, where a favicon or a
     * verification file is ordinary.
     *
     * @param string $file
     * @return bool
     */
    protected static function isInsideCoreDirectory($file)
    {
        return strpos($file, 'wp-admin/') === 0 || strpos($file, 'wp-includes/') === 0;
    }

    /**
     * @return array absolute paths of the drop-ins present
     */
    protected static function dropIns()
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $present = [];

        foreach (array_keys(_get_dropins()) as $name) {
            $path = WP_CONTENT_DIR . '/' . $name;

            if (file_exists($path)) {
                $present[] = $path;
            }
        }

        return $present;
    }

    /**
     * @param string $path
     * @return string
     */
    protected static function modifiedHuman($path)
    {
        $time = (int)@filemtime($path);

        if (!$time) {
            return '';
        }

        return sprintf(
            /* translators: %s: a length of time, for example "3 days" */
            __('%s ago', 'fluent-security'),
            human_time_diff($time, current_time('timestamp'))
        );
    }
}
