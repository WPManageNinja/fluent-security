<?php

namespace FluentAuth\App\Services\IntegrityChecker;

/*
 * Checks one installed plugin or theme against its official copy on wordpress.org.
 *
 * One extension per call, deliberately. A real site has thirty or more plugins; checking them
 * all in a single request means dozens of HTTP round trips plus a hash of every file in
 * wp-content, which is how you get a scan that dies at max_execution_time and reports
 * nothing. The screen walks the list instead, and gets to show progress while it does.
 *
 * The two kinds are not verified the same way, because wordpress.org does not offer the same
 * thing for both:
 *
 *   Plugins have a real checksums API - one JSON document per released version, listing an
 *   md5 and a sha256 for every file. It is the direct counterpart of core's
 *   get_core_checksums(), and it is cheap.
 *
 *   Themes have no such API. None. The only official record of what a theme's files should
 *   contain is the theme's own zip, so that gets downloaded and hashed. It costs a few MB the
 *   first time a version is seen, which is why the result is cached - the contents of a
 *   released version never change, so a cached manifest can never go stale.
 */
class ExtensionChecker
{
    const PLUGIN_CHECKSUM_URL = 'https://downloads.wordpress.org/plugin-checksums/';

    const THEME_ZIP_URL = 'https://downloads.wordpress.org/theme/';

    /*
     * Files that are in the extension's directory but were never part of the download.
     *
     * Kept short on purpose. An unexpected file inside a plugin folder is the single most
     * telling sign of a compromise, so anything excluded here is a thing the scan will never
     * be able to tell you about. These are the ones that are noise on every site: operating
     * system leftovers, logs, and version control.
     */
    protected static function getIgnorePatterns()
    {
        return apply_filters('fluent_auth/integrity_extension_ignore_patterns', [
            '(^|/)\.DS_Store$',
            '(^|/)Thumbs\.db$',
            '(^|/)\.git(/|$)',
            '(^|/)\.svn(/|$)',
            '(^|/)node_modules/',
            '\.log$',
            '\.tmp$'
        ]);
    }

    /*
     * The verdict for one target.
     *
     * Returns the same three statuses core uses - new, modified, deleted - so the screen can
     * render an extension's findings with the component that already renders core's. An
     * extension that could not be checked says so with a reason rather than reporting clean,
     * because "we did not look" and "we looked and it was fine" are different answers.
     */
    public function scan(array $target)
    {
        $result = [
            'type'       => $target['type'],
            'key'        => $target['key'],
            'slug'       => $target['slug'],
            'name'       => $target['name'],
            'version'    => $target['version'],
            'rel_path'   => $target['rel_path'],
            'verifiable' => false,
            'reason'     => '',
            'files'      => [],
            'checked_at' => current_time('mysql')
        ];

        if (empty($target['verifiable'])) {
            $result['reason'] = !empty($target['reason']) ? $target['reason'] : 'not_on_wp_org';
            return $result;
        }

        if (!is_readable($target['path'])) {
            $result['reason'] = 'unreadable';
            return $result;
        }

        $manifest = $target['type'] === 'theme'
            ? $this->getThemeManifest($target)
            : $this->getPluginManifest($target);

        if (is_wp_error($manifest)) {
            $result['reason'] = $manifest->get_error_code();
            return $result;
        }

        $result['verifiable'] = true;
        $result['files'] = $this->compare($target, $manifest);

        return $result;
    }

    /*
     * The official hashes for a plugin version.
     *
     * Not cached. It is one request that answers in well under a second, and the document for
     * a large plugin runs to hundreds of kilobytes - keeping thirty of those in the options
     * table to save thirty fast requests is the wrong trade.
     */
    protected function getPluginManifest(array $target)
    {
        $url = self::PLUGIN_CHECKSUM_URL . $target['slug'] . '/' . $target['version'] . '.json';

        $response = wp_remote_get($url, [
            'timeout' => 20,
            'headers' => ['Accept' => 'application/json']
        ]);

        if (is_wp_error($response)) {
            return new \WP_Error('download_failed', $response->get_error_message());
        }

        $code = wp_remote_retrieve_response_code($response);

        /*
         * The directory keeps a document for every version it has ever published, so a 404
         * means this build is not one of them - a nightly, a hand-edited version header, or a
         * copy that never came from wordpress.org at all.
         */
        if ($code === 404) {
            return new \WP_Error('version_not_published', __('Version not published', 'fluent-security'));
        }

        if ($code !== 200) {
            return new \WP_Error('download_failed', __('Unexpected response', 'fluent-security'));
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        $files = isset($body['files']) && is_array($body['files']) ? $body['files'] : [];

        if (!$files) {
            return new \WP_Error('no_manifest', __('No checksums returned', 'fluent-security'));
        }

        /*
         * sha256 where it is offered, which is everywhere in practice. Each value can be a
         * list rather than one string: a file with more than one legitimate form - line
         * endings being the usual reason - has a hash for each, and any of them is a match.
         */
        $useSha = true;
        foreach ($files as $checksums) {
            if (empty($checksums['sha256'])) {
                $useSha = false;
                break;
            }
        }

        $algo = $useSha ? 'sha256' : 'md5';
        $hashes = [];

        foreach ($files as $file => $checksums) {
            $hashes[$file] = array_map('strval', (array)$checksums[$algo]);
        }

        return ['algo' => $algo, 'files' => $hashes];
    }

    /*
     * The official hashes for a theme version, worked out from the theme's own zip.
     *
     * Hashed straight out of the archive rather than extracted to disk: the entries are read
     * one at a time and hashed in memory, which needs no writable temp directory and leaves
     * nothing behind. The zip itself still has to be fetched, so the finished manifest is
     * cached - a released version's contents are fixed forever, so there is nothing to expire
     * except the cache entry's own housekeeping.
     */
    protected function getThemeManifest(array $target)
    {
        // v2: manifests cached before PHP inside node_modules was scanned left those files out.
        $cacheKey = 'fls_theme_hashes_v2_' . md5($target['slug'] . '|' . $target['version']);
        $cached = get_transient($cacheKey);

        if (is_array($cached) && !empty($cached['files'])) {
            return $cached;
        }

        if (!class_exists('ZipArchive')) {
            return new \WP_Error('download_failed', __('The ZipArchive extension is required to verify themes.', 'fluent-security'));
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';

        $url = self::THEME_ZIP_URL . $target['slug'] . '.' . $target['version'] . '.zip';
        $zipFile = download_url($url, 60);

        if (is_wp_error($zipFile)) {
            /*
             * download_url() reports the 404 as a plain HTTP failure, so the distinction
             * between "no such version" and "the network is down" is read back off the code.
             */
            $message = $zipFile->get_error_message();
            $code = strpos($message, '404') !== false ? 'version_not_published' : 'download_failed';

            return new \WP_Error($code, $message);
        }

        $zip = new \ZipArchive();

        if ($zip->open($zipFile) !== true) {
            @unlink($zipFile);
            return new \WP_Error('download_failed', __('The downloaded theme could not be read.', 'fluent-security'));
        }

        $hashes = [];
        $prefix = $target['slug'] . '/';

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);

            if ($name === false || substr($name, -1) === '/') {
                continue; // directory entry
            }

            /* Archives wrap everything in a folder named for the theme; findings should not. */
            $relative = strpos($name, $prefix) === 0 ? substr($name, strlen($prefix)) : $name;

            if ($this->isIgnoredPath($relative)) {
                continue;
            }

            $contents = $zip->getFromIndex($i);

            if ($contents === false) {
                continue;
            }

            $hashes[$relative] = [md5($contents)];
        }

        $zip->close();
        @unlink($zipFile);

        if (!$hashes) {
            return new \WP_Error('no_manifest', __('The official theme copy appears to be empty.', 'fluent-security'));
        }

        $manifest = ['algo' => 'md5', 'files' => $hashes];

        set_transient($cacheKey, $manifest, MONTH_IN_SECONDS);

        return $manifest;
    }

    /*
     * Local files against the manifest, in core's vocabulary: a file that is not in the
     * official copy is `new`, one whose hash differs is `modified`, one that is missing is
     * `deleted`.
     */
    protected function compare(array $target, array $manifest)
    {
        $local = $this->getLocalHashes($target, $manifest['algo']);
        $remote = $manifest['files'];

        $findings = [];

        foreach ($local as $file => $hash) {
            if (!isset($remote[$file])) {
                $findings[$file] = [
                    'status'      => 'new',
                    'modified_at' => $this->modifiedAt($target, $file)
                ];
            } elseif (!in_array($hash, $remote[$file], true)) {
                $findings[$file] = [
                    'status'      => 'modified',
                    'modified_at' => $this->modifiedAt($target, $file)
                ];
            }
        }

        foreach (array_keys($remote) as $file) {
            if (!isset($local[$file])) {
                $findings[$file] = [
                    'status'      => 'deleted',
                    'modified_at' => ''
                ];
            }
        }

        ksort($findings);

        return $findings;
    }

    protected function getLocalHashes(array $target, $algo)
    {
        /* A single-file plugin is its own whole extent - see ExtensionInventory. */
        if (!empty($target['single_file'])) {
            $name = basename($target['path']);

            return is_file($target['path'])
                ? [$name => hash_file($algo, $target['path'])]
                : [];
        }

        $base = wp_normalize_path(rtrim($target['path'], '/')) . '/';
        $hashes = [];

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($target['path'], \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );
        } catch (\Exception $e) {
            return [];
        }

        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $relative = str_replace($base, '', wp_normalize_path($file->getPathname()));

            if ($this->isIgnoredPath($relative)) {
                continue;
            }

            $hash = @hash_file($algo, $file->getPathname());

            if ($hash) {
                $hashes[$relative] = $hash;
            }
        }

        return $hashes;
    }

    protected function isIgnoredPath($relativePath)
    {
        /*
         * node_modules is build noise, but PHP dropped inside it runs like any other PHP.
         * PHP only: node-gyp alone ships hundreds of .py files, which would flood the scan.
         */
        if (preg_match('#(^|/)node_modules/#i', $relativePath) && preg_match('#\.(php\d?|phtml|pht)$#i', $relativePath)) {
            return false;
        }

        foreach (self::getIgnorePatterns() as $pattern) {
            if (preg_match('#' . $pattern . '#i', $relativePath)) {
                return true;
            }
        }

        return false;
    }

    protected function modifiedAt(array $target, $relativeFile)
    {
        $path = !empty($target['single_file'])
            ? $target['path']
            : rtrim($target['path'], '/') . '/' . $relativeFile;

        $time = @filemtime($path);

        return $time ? gmdate('Y-m-d H:i:s', $time) : '';
    }
}
