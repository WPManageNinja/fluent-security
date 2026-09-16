<?php

namespace FluentAuth\App\Services\IntegrityChecker;


use FluentAuth\App\Helpers\Arr;

class CheckerService
{
    protected $remoteHashes = null;

    protected $localHashes = null;

    protected $hasIssues = null;

    protected $ignoreLists = null;

    protected $extraFolders = null;

    protected $modifiedFiles = null;

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
        require_once ABSPATH . 'wp-admin/includes/update.php';
        $remoteHashes = get_core_checksums($wp_version, get_locale());
        if (!$remoteHashes) {
            throw new \Exception('Unable to get remote hashes');
        }

        foreach ($remoteHashes as $file => $hash) {
            // if file has wp-content at the start, remove it
            if (strpos($file, 'wp-content') === 0) {
                unset($remoteHashes[$file]);
            }
        }
        unset($remoteHashes['wp-config-sample.php']);

        $this->remoteHashes = $remoteHashes;

        return $this->remoteHashes;
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
