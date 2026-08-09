<?php

namespace FluentAuth\App\Services\Baseline;

use FluentAuth\App\Services\IntegrityChecker\ExtensionInventory;

/**
 * What a snapshot covers, and - just as deliberately - what it does not.
 *
 * Only the plugins and themes WordPress.org has no copy of. Everything else on the site is
 * already checked against something better than its own past: core and directory extensions
 * against the official release, mu-plugins and the drop-ins against the hashes the site
 * accepted for them. Snapshotting those as well would mean two answers about the same file,
 * and the weaker one would eventually contradict the stronger.
 *
 * Which makes this exactly the gap the Monitoring tab currently admits to - "14 items are not
 * from the WordPress.org directory, so there are no official checksums to compare them
 * against". Afterwards every file on the site is covered by one thing or the other.
 */
class BaselineTargets
{
    /**
     * Only files that can do something.
     *
     * The single most important line in this feature. Snapshotting a media library means a
     * bulk import reports two thousand changed files, and one event like that teaches
     * somebody to close the alert without reading it for ever afterwards. Nothing here can
     * execute except these, and it is execution that a break-in needs.
     *
     * @return array
     */
    public static function extensions()
    {
        return apply_filters('fluent_auth/baseline_extensions', ['php', 'js', 'htaccess', 'phtml']);
    }

    /**
     * @return array
     */
    public static function units()
    {
        $units = [];

        foreach (ExtensionInventory::getTargets() as $target) {
            /*
             * Verifiable ones are left alone: the directory's own checksums outrank anything
             * this site can remember about itself.
             */
            if (!empty($target['verifiable'])) {
                continue;
            }

            $units[] = [
                'scope'   => $target['type'] . ':' . $target['key'],
                'label'   => $target['name'],
                'type'    => $target['type'],
                'version' => isset($target['version']) ? $target['version'] : '',
                'path'    => $target['path'],
                'rel_path' => isset($target['rel_path']) ? $target['rel_path'] : ''
            ];
        }

        return $units;
    }

    /**
     * Hash everything in one unit that could run.
     *
     * @param string $path
     * @return array relative path => hash
     */
    public static function hash($path)
    {
        if (is_file($path)) {
            return [basename($path) => (string)@md5_file($path)];
        }

        if (!is_dir($path)) {
            return [];
        }

        $wanted = array_map('strtolower', self::extensions());
        $max = apply_filters('fluent_auth/baseline_max_files', 20000);

        $hashes = [];

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }

                $name = $file->getFilename();

                /* .htaccess has no extension as far as SplFileInfo is concerned. */
                $extension = strtolower($file->getExtension());

                if ($extension === '' && strpos($name, '.') === 0) {
                    $extension = strtolower(ltrim($name, '.'));
                }

                if (!in_array($extension, $wanted, true)) {
                    continue;
                }

                $relative = ltrim(str_replace(wp_normalize_path($path), '', wp_normalize_path($file->getPathname())), '/');

                $hashes[$relative] = (string)@md5_file($file->getPathname());

                if (count($hashes) >= $max) {
                    break;
                }
            }
        } catch (\Exception $exception) {
            return $hashes;
        }

        ksort($hashes);

        return $hashes;
    }
}
