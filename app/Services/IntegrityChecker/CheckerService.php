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
        return $this->groupFiles($modifiedItems);
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
            return $this->groupFiles($modifiedFiles);
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

        $folders = array_diff($folders, $ignoredFolders);

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

    private function groupFiles($files)
    {
        // let's grouped the files by folders
        $groupedFiles = [];

        foreach ($files as $file => $data) {
            $folder = dirname($file);

            $relativePath = $file;
            if ($folder === '.') {
                $folder = 'root';
            } else {
                // Replace the first occurrence of the folder with an empty string
                $relativePath = preg_replace('/^' . preg_quote($folder, '/') . '\//', '', $file);
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

        $ignores = array_unique([
            '.',
            '..',
            '.git',
            '.gitignore',
            '.DS_Store',
            '.idea',
            'wp-admin',
            'wp-includes',
            'wp-config.php',
            'wp-config-sample.php',
            '.htaccess',
            '.env',
            WPINC,
            'wp-content',
            basename(WP_CONTENT_DIR)
        ]);

        $rootFiles = array_diff($rootFiles, $ignores);

        $backupExtensions = ['.bak', '.back', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.copy', '~'];

        $files = [];
        $extraFolders = [];
        foreach ($rootFiles as $file) {
            if (preg_match('/^(file-manager-|adminer-).*\.php$|\.conf$/i', $file)) {
                continue; // we are ignoring known useful files
            }

            $fileLower = strtolower($file);

            // Skip backup/temp files
            $isBackup = false;
            foreach ($backupExtensions as $ext) {
                if (substr($fileLower, -strlen($ext)) === $ext) {
                    $isBackup = true;
                    break;
                }
            }
            if ($isBackup) {
                continue;
            }

            if (is_file($rootFolder . '/' . $file)) {
                $files[$file] = md5_file($rootFolder . '/' . $file);
            } elseif (is_dir($rootFolder . '/' . $file)) {
                $xcloudDirs = ['before', 'after', 'server'];
                if (in_array($file, $xcloudDirs)) {
                    if ($this->isConfFolder($rootFolder . '/' . $file)) {
                        continue;
                    }
                }
                $extraFolders[] = '/' . $file;
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
