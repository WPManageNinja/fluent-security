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
        $result = self::hashUnit($path);

        return $result['hashes'];
    }

    /**
     * The same walk, and what it could not reach.
     *
     * There is a ceiling on how many files one unit may contribute, so a single pathological
     * directory cannot make every scan on the site time out. The ceiling used to be a bare
     * `break`: the walk stopped, the rest of the unit went unwatched, and nothing anywhere
     * said so - the row reported itself covered exactly like a unit that really was.
     *
     * A monitor that quietly watches less than it claims to is worse than one that watches
     * nothing, because the reader has no way to know which they have. So the walk carries on
     * past the ceiling to count what it is skipping. Counting is a directory read that has
     * already been paid for; it is the hashing that costs, and that is what stops.
     *
     * The window is the sorted first N paths, not the first N the filesystem happened to hand
     * over. That is what makes a truncated unit comparable with itself at all: an arbitrary
     * subset shifts between runs, so the same unchanged site would report hundreds of files
     * added and hundreds removed every single scan. Sorted, the window is the same window next
     * time, and `boundary` is its last path - everything after it was never looked at, which is
     * what lets the comparison tell "not reached" apart from "deleted".
     *
     * @param string $path
     * @return array hashes, total, skipped, boundary (last path in the window, '' if complete)
     */
    public static function hashUnit($path)
    {
        if (is_file($path)) {
            return [
                'hashes'   => [basename($path) => (string)@md5_file($path)],
                'total'    => 1,
                'skipped'  => 0,
                'boundary' => ''
            ];
        }

        if (!is_dir($path)) {
            return ['hashes' => [], 'total' => 0, 'skipped' => 0, 'boundary' => ''];
        }

        $wanted = array_map('strtolower', self::extensions());
        $max = apply_filters('fluent_auth/baseline_max_files', 20000);

        $paths = [];

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

                /*
                 * Collected before anything is hashed. Names are cheap - it is the reading of
                 * file contents that costs, and none of that happens until the window is known.
                 */
                $paths[] = ltrim(str_replace(wp_normalize_path($path), '', wp_normalize_path($file->getPathname())), '/');
            }
        } catch (\Exception $exception) {
            /* Whatever was reached is still worth keeping; what was not is not guessed at. */
            $paths = [];
        }

        sort($paths, SORT_STRING);

        $total = count($paths);
        $window = $total > $max ? array_slice($paths, 0, $max) : $paths;

        $hashes = [];

        foreach ($window as $relative) {
            $hashes[$relative] = (string)@md5_file($path . '/' . $relative);
        }

        return [
            'hashes'   => $hashes,
            'total'    => $total,
            'skipped'  => max(0, $total - count($window)),
            'boundary' => $total > $max && $window ? end($window) : ''
        ];
    }
}
