<?php

namespace FluentAuth\App\Services\Checks\Files;

/**
 * The must-use plugins directory.
 *
 * Everything here runs on every request, cannot be deactivated from the plugins screen, and
 * in most installs is not listed anywhere a site owner would think to look. That combination
 * is why it is a favourite place to leave a way back in after a break-in, and why it is worth
 * a check of its own rather than a line in a file scan.
 *
 * It is also why most managed hosts put their own files here, which is the reason this check
 * says nothing on the first run - see WatchedFilesCheck. What is here can be read on the scan
 * screen, which lists the files and will show the source of any of them.
 */
class MuPluginsCheck extends WatchedFilesCheck
{
    public function id()
    {
        return 'mu_plugins';
    }

    protected function paths()
    {
        return self::phpFiles();
    }

    /**
     * The same list the check watches, for the screen that lists them.
     *
     * Public and static so the scan screen cannot end up with its own idea of what is in this
     * folder - a listing that disagreed with the check about which files exist would be two
     * answers to one question, and one of them would be wrong.
     *
     * @return array absolute paths
     */
    public static function phpFiles()
    {
        if (!defined('WPMU_PLUGIN_DIR')) {
            return [];
        }

        return (new self())->phpFilesIn(WPMU_PLUGIN_DIR);
    }

    protected function scope()
    {
        if (!defined('WPMU_PLUGIN_DIR')) {
            return '/wp-content/mu-plugins';
        }

        return \FluentAuth\App\Services\Checks\AcceptedFiles::toRelative(WPMU_PLUGIN_DIR);
    }

    protected function watchedTitle($count)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'The file that runs on every page has not changed',
                'The %s files that run on every page have not changed',
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
                'A new file has started running on every page of your site',
                '%s new files have started running on every page of your site',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }

    protected function words()
    {
        return [
            'appeared_why'  => __('This file was not here last time we looked, and files in this folder run automatically without appearing on your plugins screen. Ask your host or developer whether they added it before doing anything else.', 'fluent-security'),
            'alert_title'   => __('Something running on every page of your site has changed', 'fluent-security'),
            'alert_why'     => __('One of these files has changed. It cannot be switched off from the plugins screen, so find out who changed it.', 'fluent-security'),
            'none_title'    => __('No extra files run on every page of your site', 'fluent-security')
        ];
    }
}
