<?php

namespace FluentAuth\App\Services\Checks\Config;

use FluentAuth\App\Services\Checks\Finding;

/**
 * PHP errors printed into the page.
 *
 * A live site with this on hands visitors its file paths, and often fragments of queries and
 * data, in the middle of whatever page went wrong. It is the single most common way a site
 * tells a stranger how it is built.
 *
 * Only reported when debugging is actually on and display has not been turned off - a site
 * with WP_DEBUG off shows nothing regardless of the second constant.
 */
class DebugDisplayCheck extends ConfigConstantCheck
{
    public function id()
    {
        return 'debug_display';
    }

    protected function isSatisfied()
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return true;
        }

        return defined('WP_DEBUG_DISPLAY') && !WP_DEBUG_DISPLAY;
    }

    protected function words()
    {
        return [
            'title'    => __('Errors on your site are shown to visitors', 'fluent-security'),
            'why'      => __('When something goes wrong, the message printed on the page includes where your files live on the server, and sometimes what your site was doing at the time.', 'fluent-security'),
            'passed'   => __('Errors are not shown to visitors', 'fluent-security'),
            'snippet'  => "define( 'WP_DEBUG_DISPLAY', false );",
            'severity' => Finding::SEVERITY_FIX
        ];
    }
}
