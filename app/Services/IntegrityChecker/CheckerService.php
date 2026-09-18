<?php

namespace FluentAuth\App\Services\IntegrityChecker;


use FluentAuth\App\Helpers\Arr;

class CheckerService
{
    /* The only file whose hash differs between a translated package and the en_US one. */
    const LOCAL_PACKAGE_FILE = 'wp-includes/version.php';

    protected $remoteHashes = null;

    protected $localHashes = null;

    protected $hasIssues = null;

    protected $ignoreLists = null;

    protected $extraFolders = null;

    protected $modifiedFiles = null;

    /*
     * Files this scan is not in a position to judge, as file => true.
     *
     * Populated in getRemoteHashes(), and only ever with wp-includes/version.php - see
     * getCoreChecksums() for why that one file is never compared. Dropping a file from the
     * remote hashes is not enough to stop it being reported: a local file with no remote hash
     * is an unexpected file, which is how removing it turned a false "modified" into a false
     * "new". It has to be skipped on both sides of the comparison, which is what this is for.
     */
    protected $exemptFiles = [];

    public function __construct()
    {
        $this->getRemoteHashes();
        $this->getLocalHashes();
        $this->ignoreLists = IntegrityHelper::getIgnoreLists();
    }

    public function getScanResults($isActive = false)
    {
        if (!$isActive) {
            return [
                'files'   => $this->getGroupedModifiedItems(),
                'folders' => $this->getModifiedFolders()
            ];
        }

        return [
            'files'   => $this->getActiveModifiedFiles(false),
            'folders' => $this->getModifiedFolders(true)
        ];
    }

    public function getGroupedModifiedItems()
    {
        $modifiedItems = $this->getModifiedFiles();
        return self::groupFiles($modifiedItems);
    }

    public function getModifiedFiles()
    {
        if ($this->modifiedFiles !== null) {
            return $this->modifiedFiles;
        }

        $localHashes = $this->localHashes;
        $remoteHashes = $this->remoteHashes;

        $modifiedFiles = [];
        foreach ($localHashes as $file => $localHash) {
            if (isset($this->exemptFiles[$file])) {
                continue;
            }

            $remoteHash = isset($remoteHashes[$file]) ? $remoteHashes[$file] : null;
            if (!$remoteHash) {
                // the file is deleted
                $modifiedFiles[$file] = [
                    'status'      => 'new',
                    'modified_at' => gmdate('Y-m-d H:i:s', filemtime(ABSPATH . $file))
                ];
            } else if ($localHash !== $remoteHash) {
                // the file is modified
                $modifiedFiles[$file] = [
                    'status'      => 'modified',
                    'modified_at' => gmdate('Y-m-d H:i:s', filemtime(ABSPATH . $file))
                ];
            }
        }

        $deletedFiles = array_values(array_diff(array_keys($remoteHashes), array_keys($localHashes)));

        foreach ($deletedFiles as $file) {
            $modifiedFiles[$file] = [
                'status'      => 'deleted',
                'modified_at' => ''
            ];
        }

        $this->modifiedFiles = $modifiedFiles;

        return $this->modifiedFiles;
    }

    public function getActiveModifiedFiles($grouped = false)
    {
        $modifiedFiles = $this->getModifiedFiles();

        $ignoredFiles = Arr::get($this->ignoreLists, 'files', []);

        if (!$ignoredFiles) {
            return $modifiedFiles;
        }

        $ignoredFiles = array_map(function ($file) {
            return ltrim($file, '/');
        }, $ignoredFiles);

        $modifiedFiles = Arr::except($modifiedFiles, $ignoredFiles);

        if ($grouped) {
            return self::groupFiles($modifiedFiles);
        }

        return $modifiedFiles;
    }

    public function getModifiedFolders($isActive = false)
    {
        $folders = $this->extraFolders;

        if (!$isActive) {
            return $folders;
        }

        $ignoredFolders = Arr::get($this->ignoreLists, 'folders', []);

        if (!$ignoredFolders) {
            return $folders;
        }

        /*
         * Re-indexed: array_diff keeps the original keys, and a list with a hole in it is no
         * longer a JSON array once it reaches the relay - it arrives as an object, which the
         * report parser discards. Only ever visible on a site that has accepted a folder,
         * which is why it went unnoticed.
         */
        $folders = array_values(array_diff($folders, $ignoredFolders));

        return $folders;
    }

    public function getActiveModifiedFolders()
    {
        return $this->getModifiedFolders(true);
    }

    public function getRemoteHashes()
    {
        if ($this->remoteHashes !== null) {
            return $this->remoteHashes;
        }

        global $wp_version;

        $checksums = self::getCoreChecksums($wp_version, get_locale());

        $this->remoteHashes = $checksums['files'];
        $this->exemptFiles = $checksums['exempt'];

        return $this->remoteHashes;
    }

    /*
     * The official checksums for this exact WordPress build, ready to compare against.
     *
     * Deliberately not core's get_core_checksums(). Two things in that function fail the scan
     * on sites that are perfectly healthy:
     *
     *  - It caps the request at `wp_doing_cron() ? 30 : 3` seconds for a response that is over
     *    300KB. The daily scan runs under cron and gets 30 seconds; the Scan button is a REST
     *    request and gets 3, so a site on a slow link reports the scheduled scan working and
     *    the button failing. 30 either way here.
     *  - It asks for get_locale() and gives up when wordpress.org answers {"checksums":false},
     *    which is the answer for any locale whose package for that exact version has not been
     *    built. Translated builds trail a point release, so a site in a lagging locale loses
     *    core scanning for the window in between - at the time of writing, fr_FR, es_ES,
     *    ru_RU, it_IT, zh_CN, ar and hi_IN all had checksums for 7.1 but none for 7.1.1. For
     *    he_IL and hi_IN nothing is published for any recent version at all, so those sites
     *    could never scan.
     *
     * Hence the en_US fallback. It is exact rather than approximate: once the wp-content
     * entries and wp-config-sample.php are dropped - which this method does anyway, because
     * neither belongs to a core integrity check - a localized package differs from en_US in
     * exactly one file, wp-includes/version.php, which carries $wp_local_package. That file is
     * exempt on every path, not just the fallback - see the note at the unset() below.
     *
     * @param string $version
     * @param string $locale
     * @return array ['files' => file => md5, 'exempt' => file => true]
     * @throws ChecksumException when wordpress.org has nothing to offer for this build
     */
    public static function getCoreChecksums($version, $locale)
    {
        $cacheKey = 'fls_core_checksums_' . md5($version . '|' . $locale);

        $cached = get_transient($cacheKey);

        if (is_array($cached) && !empty($cached['files'])) {
            return $cached;
        }

        $checksums = self::requestChecksums($version, $locale);

        if (is_wp_error($checksums) && $checksums->get_error_code() === ChecksumException::UNPUBLISHED && $locale !== 'en_US') {
            $checksums = self::requestChecksums($version, 'en_US');
        }

        if (is_wp_error($checksums)) {
            throw self::checksumFailure($checksums, $version);
        }

        $result = [
            'files'  => self::pruneChecksums($checksums),
            'exempt' => [self::LOCAL_PACKAGE_FILE => true]
        ];

        /*
         * The one file whose hash legitimately varies, exempt whichever manifest was used.
         *
         * A translated build declares $wp_local_package in it, so it differs from en_US by
         * design - that is the case the fallback above creates, and it was the only one
         * exempted at first. The commoner divergence is the other way round and was still
         * being reported: a site installed from the en_US zip whose owner sets the site
         * language to French keeps its en_US core files, because WordPress downloads language
         * packs and not a new build. get_locale() then says fr_FR, wp.org publishes fr_FR
         * checksums, no fallback fires, and every scan reported wp-includes/version.php as
         * modified - a security product telling a small business its core had been altered,
         * once a night, until the next core update. Checked against 12 locales on WP 6.8.2:
         * after pruning, a localized package differs from en_US in this file and no other.
         *
         * Exempt rather than simply absent from the map: a file missing from the remote set
         * reads as "new" (see getModifiedFiles), so dropping it alone would swap one false
         * report for another. $exemptFiles skips it on the local side too.
         *
         * The cost is that this one file is not hash-checked. Accepted: an attacker who can
         * write it can write any other core file, and those are all still compared - so
         * choosing this one buys nothing, while the false report cost every localized site a
         * nightly alarm.
         */
        unset($result['files'][self::LOCAL_PACKAGE_FILE]);

        /*
         * Cached because the checksums for a released version never change, and three separate
         * callers - the Scan button, the daily run and a core reinstall - each pull the same
         * 300KB otherwise. A core update changes $wp_version, which changes the key, so a
         * stale set can never be compared against the wrong build.
         */
        set_transient($cacheKey, $result, 12 * HOUR_IN_SECONDS);

        return $result;
    }

    /*
     * One request to the checksum API. Returns the raw set, or a WP_Error whose code is one of
     * the two ChecksumException reasons.
     */
    protected static function requestChecksums($version, $locale)
    {
        $url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query([
                'version' => $version,
                'locale'  => $locale
            ], '', '&');

        $response = wp_remote_get($url, [
            'timeout' => 30,
            'headers' => ['Accept' => 'application/json']
        ]);

        if (is_wp_error($response)) {
            return new \WP_Error(ChecksumException::UNREACHABLE, $response->get_error_message());
        }

        $code = (int)wp_remote_retrieve_response_code($response);

        if ($code !== 200) {
            return new \WP_Error(ChecksumException::UNREACHABLE, sprintf('HTTP %d from api.wordpress.org', $code));
        }

        $body = json_decode(trim(wp_remote_retrieve_body($response)), true);

        /*
         * Not an error response: the API answers 200 with {"checksums":false} for a version and
         * locale it has never built, which is the unpublished case and the one worth retrying
         * against en_US.
         */
        if (!is_array($body) || empty($body['checksums']) || !is_array($body['checksums'])) {
            return new \WP_Error(ChecksumException::UNPUBLISHED, sprintf('No checksums published for %s (%s)', $version, $locale));
        }

        return $body['checksums'];
    }

    /*
     * Drop everything a core integrity check has no business comparing.
     *
     * wp-content is the site's own - plugins, themes and translations all live there and all
     * legitimately differ from the shipped package - and it is scanned separately against its
     * own sources. wp-config-sample.php is not installed as-is by anyone.
     */
    protected static function pruneChecksums($checksums)
    {
        foreach ($checksums as $file => $hash) {
            // if file has wp-content at the start, remove it
            if (strpos($file, 'wp-content/') === 0) {
                unset($checksums[$file]);
            }
        }

        unset($checksums['wp-config-sample.php']);

        return $checksums;
    }

    /*
     * The sentence the site owner sees. Neither reason involves the alert relay, so neither
     * mentions it - the previous message sent people to reconnect an API that this scan does
     * not use and that most sites running it have never set up.
     */
    protected static function checksumFailure($error, $version)
    {
        if ($error->get_error_code() === ChecksumException::UNPUBLISHED) {
            return new ChecksumException(
                ChecksumException::UNPUBLISHED,
                sprintf(
                    /* translators: %s: WordPress version number. */
                    __('WordPress.org has not published file checksums for WordPress %s, so there is nothing official to compare your core files against. This usually resolves within a few days of a release. If this site does not run a release built by WordPress.org, core files cannot be verified at all.', 'fluent-security'),
                    $version
                ),
                $error->get_error_message()
            );
        }

        return new ChecksumException(
            ChecksumException::UNREACHABLE,
            __('Could not reach api.wordpress.org to download the official WordPress checksums, so there was nothing to compare your core files against. This is usually a temporary network problem, or a firewall blocking outgoing requests from your server.', 'fluent-security'),
            $error->get_error_message()
        );
    }

    public function getLocalHashes()
    {
        if ($this->localHashes !== null) {
            return [
                'files'         => $this->localHashes,
                'extra_folders' => $this->extraFolders
            ];
        }

        $wpAdminFiles = $this->getHashesByFolder(ABSPATH . 'wp-admin', 'wp-admin');
        $wpIncludesFiles = $this->getHashesByFolder(ABSPATH . WPINC, 'wp-includes');
        $rootHashes = $this->getRootFolderHashes();
        $footFiles = $rootHashes['files'];

        $allFiles = array_merge($wpAdminFiles, $wpIncludesFiles, $footFiles);

        $this->localHashes = $allFiles;
        $this->extraFolders = $rootHashes['extra_folders'];

        return [
            'files'         => $this->localHashes,
            'extra_folders' => $this->extraFolders
        ];
    }

    /*
     * Static and public because the stored results are regrouped by the same rules when the
     * scan screen loads them back - see IntegrityHelper::getStoredCoreScanResults(). Two
     * copies of this would be two ways for a file to land in a group the screen never draws.
     */
    public static function groupFiles($files)
    {
        // let's grouped the files by folders
        $groupedFiles = [];

        foreach ($files as $file => $data) {
            /*
             * Grouped by the place the scanner looked - wp-admin, wp-includes, or the root -
             * which is the first segment of the path, not its parent directory. Using the
             * parent put wp-admin/includes/file.php in a group of its own called
             * "wp-admin/includes", and the screen only ever renders the three it knows, so
             * every finding in a nested directory was counted and then never shown.
             */
            $parts = explode('/', $file, 2);

            /*
             * Only the two folders that are walked as folders get a group of their own.
             * Anything else nested - an executable found under .well-known, say - belongs to
             * the root group with its path intact, because the screen renders these three
             * groups and no others: a fourth key is a finding that is counted and then never
             * drawn. Keeping the whole path as the label is also what makes the row's ignore
             * entry come out as /.well-known/... , the same shape every other accepted path
             * has.
             */
            if (count($parts) === 2 && in_array($parts[0], ['wp-admin', 'wp-includes', WPINC], true)) {
                $folder = $parts[0];
                $relativePath = $parts[1];
            } else {
                $folder = 'root';
                $relativePath = $file;
            }

            if (!isset($groupedFiles[$folder])) {
                $groupedFiles[$folder] = [];
            }
            $groupedFiles[$folder][$relativePath] = $data;
        }

        return $groupedFiles;
    }

    private function getHashesByFolder(string $directory, $replaceWith = '')
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                // Exclude certain system files or large files to improve performance
                $excludePatterns = [
                    '\.DS_Store$',
                    '\.log$',
                    '\.tmp$'
                ];

                $fullPath = $file->getPathname();

                /*
                 * The same logs the root drops, dropped here too. These patterns only ever
                 * matched an extension, so PHP's own `error_log` - which has none - was
                 * reported as a new file in wp-admin on every scan of every site whose
                 * host writes one. It is a log wherever it lands, and no version of it is
                 * interesting to a checksum.
                 *
                 * Only that half of the list travels: see RootExpectations for why a kept
                 * copy inside a core directory stays reported.
                 */
                if (RootExpectations::isSystemNoise($file->getFilename())) {
                    continue;
                }

                $relativePath = (string)str_replace(ABSPATH . $replaceWith, $replaceWith, $fullPath);

                $shouldExclude = array_reduce($excludePatterns, function ($carry, $pattern) use ($fullPath) {
                    return $carry || preg_match('/' . $pattern . '/i', $fullPath);
                }, false);

                if (!$shouldExclude) {
                    $files[$relativePath] = md5_file($file->getPathname());
                }
            }
        }

        return $files;
    }

    private function getRootFolderHashes()
    {
        $rootFolder = ABSPATH;

        // get the root files and folders
        $rootFiles = scandir($rootFolder);

        /*
         * The parts of the tree this scan is not responsible for. wp-admin and wp-includes
         * are walked separately and wp-content is another check's subject; the rest are
         * WordPress's own files, which the checksums either cover or deliberately do not.
         * Everything else a root may hold is RootExpectations' question, not this one's.
         */
        $ignores = array_unique([
            '.',
            '..',
            'wp-admin',
            'wp-includes',
            'wp-config.php',
            'wp-config-sample.php',
            WPINC,
            'wp-content',
            basename(WP_CONTENT_DIR)
        ]);

        $rootFiles = array_diff($rootFiles, $ignores);

        $files = [];
        $extraFolders = [];

        foreach ($rootFiles as $file) {
            $path = $rootFolder . '/' . $file;

            if (preg_match('/^(file-manager-|adminer-).*\.php$|\.conf$/i', $file)) {
                continue; // we are ignoring known useful files
            }

            /*
             * Tested before the file-or-directory question, because it always was: `.git`
             * and `.idea` are directories, and a rule that only reached files would start
             * announcing every checkout and every editor folder as an unknown directory.
             */
            if (RootExpectations::isNoise($file)) {
                continue;
            }

            if (is_dir($path)) {
                /*
                 * Expected, so the directory itself is not announced - but it is the one
                 * kind of directory this scan looks inside. See RootExpectations: silencing
                 * the row without walking the tree would leave the likeliest drop spots on
                 * the filesystem as the only places nothing is ever checked.
                 */
                if (RootExpectations::isExpectedDir($file)) {
                    $files = array_merge($files, RootExpectations::executablesIn($path, $file));
                    continue;
                }

                $xcloudDirs = ['before', 'after', 'server'];
                if (in_array($file, $xcloudDirs)) {
                    if ($this->isConfFolder($path)) {
                        continue;
                    }
                }

                $extraFolders[] = '/' . $file;
                continue;
            }

            if (is_file($path)) {
                $files[$file] = md5_file($path);
            }
        }


        return [
            'extra_folders' => $extraFolders,
            'files'         => $files,
        ];
    }

    private function isConfFolder($folderPath)
    {
        // Check if directory exists
        if (!is_dir($folderPath)) {
            return true;
        }

        // Get all files in directory
        $files = scandir($folderPath);

        // Remove . and .. from the list
        $files = array_diff($files, array('.', '..'));

        // If directory is empty, return true
        if (empty($files)) {
            return true;
        }

        // Check each file
        foreach ($files as $file) {
            $fullPath = $folderPath . DIRECTORY_SEPARATOR . $file;

            // If it's a directory, return false
            if (is_dir($fullPath)) {
                return false;
            }

            // If it's not a .conf file, return false
            if (!preg_match('/\.conf$/i', $file)) {
                return false;
            }
        }

        // If we made it through all checks, return true
        return true;
    }

}
