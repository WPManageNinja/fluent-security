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
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $found = [];

        foreach (array_keys(_get_dropins()) as $name) {
            $path = WP_CONTENT_DIR . '/' . $name;

            if (file_exists($path)) {
                $found[] = $path;
            }
        }

        return $found;
    }

    /*
     * The drop-ins sit loose in wp-content beside plugins and themes, so the scope has to be
     * the individual filenames - anything wider would have this check forgetting entries that
     * belong to the file scan.
     */
    protected function scope()
    {
        return AcceptedFiles::toRelative(WP_CONTENT_DIR) . '/';
    }

    protected function firstTitle($count)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'A file loads before the rest of your site',
                '%s files load before the rest of your site',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }

    protected function words()
    {
        return [
            'first_why'   => __('WordPress runs these automatically if they are present, and nothing lists them as installed. Caching and database plugins add them legitimately — have a look, and mark them as expected if you recognise them.', 'fluent-security'),
            'alert_title' => __('A file that loads before the rest of your site has changed', 'fluent-security'),
            'alert_why'   => __('One of these is no longer the file you marked as expected. They run earlier than plugins do, so a change here is worth accounting for.', 'fluent-security'),
            'none_title'  => __('Nothing unexpected loads ahead of your site', 'fluent-security')
        ];
    }

    /**
     * Drop-ins are named things, and the name is what tells you what one is for. WordPress
     * describes each; the description is worth more to the reader than the path is.
     *
     * @param array $changed
     * @param array $unaccounted
     * @return array
     */
    protected function details($changed, $unaccounted)
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
            $details[] = sprintf(__('%s (changed since you accepted it)', 'fluent-security'), $describe($path));
        }

        foreach ($unaccounted as $path) {
            $details[] = $describe($path);
        }

        return $details;
    }
}
