<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Services\Checks\AcceptedFiles;

/**
 * WordPress's drop-ins.
 *
 * A fixed set of filenames in wp-content that WordPress loads if they happen to exist -
 * object-cache.php, advanced-cache.php, db.php and the rest. Nothing installs them, nothing
 * lists them, and db.php in particular is loaded before almost anything else, which makes it
 * about the earliest place code can be made to run on a WordPress site.
 *
 * The names come from WordPress itself rather than from a list written here, so a drop-in
 * added in a future release is watched the day it exists.
 */
class DropInsCheck extends WatchedFilesCheck
{
    public function id()
    {
        return 'drop_ins';
    }

    protected function paths()
    {
        $found = [];

        foreach ($this->names() as $name) {
            $path = WP_CONTENT_DIR . '/' . $name;

            if (file_exists($path)) {
                $found[] = $path;
            }
        }

        return $found;
    }

    protected function scope()
    {
        return AcceptedFiles::toRelative(WP_CONTENT_DIR) . '/';
    }

    /**
     * The drop-ins sit loose in wp-content beside plugins, themes and mu-plugins, so the
     * subtree this check is named after is not the set it owns. Matching on the prefix would
     * have it forgetting the mu-plugins record every time it ran - and forgetting it in the
     * direction where a planted file comes back reading as expected.
     *
     * @param string $path
     * @return bool
     */
    protected function owns($path)
    {
        return dirname($path) === rtrim($this->scope(), '/')
            && in_array(basename($path), $this->names(), true);
    }

    /**
     * @return array the drop-in filenames WordPress itself recognises
     */
    protected function names()
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        return array_keys(_get_dropins());
    }

    protected function watchedTitle($count)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'The file that loads before the rest of your site has not changed',
                'The %s files that load before the rest of your site have not changed',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }

    protected function appearedTitle($count)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'A new file has started loading before the rest of your site',
                '%s new files have started loading before the rest of your site',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }

    protected function words()
    {
        return [
            'appeared_why'  => __('This file was not here last time we looked, and WordPress runs it automatically without listing it anywhere. Caching and database plugins add these legitimately, so check whether you just installed one.', 'fluent-security'),
            'alert_title'   => __('A file that loads before the rest of your site has changed', 'fluent-security'),
            'alert_why'     => __('One of these files has changed. If you did not update the plugin that added it, find out who did.', 'fluent-security'),
            'none_title'    => __('No extra files load before the rest of your site', 'fluent-security')
        ];
    }

    /**
     * Drop-ins are named things, and the name is what tells you what one is for. WordPress
     * describes each; the description is worth more to the reader than the path is.
     *
     * @param array $changed
     * @param array $appeared
     * @return array
     */
    protected function details($changed, $appeared)
    {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $dropins = _get_dropins();

        $describe = function ($path) use ($dropins) {
            $name = basename($path);
            $description = isset($dropins[$name][0]) ? $dropins[$name][0] : '';

            return $description ? $name . ' — ' . $description : $name;
        };

        $details = [];

        foreach ($changed as $path) {
            /* translators: %s: a drop-in file name and what it does */
            $details[] = sprintf(__('%s (changed)', 'fluent-security'), $describe($path));
        }

        foreach ($appeared as $path) {
            /* translators: %s: a drop-in file name and what it does */
            $details[] = sprintf(__('%s (new since we started watching)', 'fluent-security'), $describe($path));
        }

        return $details;
    }
}
