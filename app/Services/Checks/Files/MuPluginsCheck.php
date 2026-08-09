<?php

namespace FluentAuth\App\Services\Checks\Files;

/**
 * The must-use plugins directory.
 *
 * Everything here runs on every request, cannot be deactivated from the plugins screen, and
 * in most installs is not listed anywhere a site owner would think to look. That combination
 * is why it is a favourite place to leave a way back in after a break-in, and why it is worth
 * a check of its own rather than a line in a file scan.
 */
class MuPluginsCheck extends WatchedFilesCheck
{
    public function id()
    {
        return 'mu_plugins';
    }

    protected function paths()
    {
        if (!defined('WPMU_PLUGIN_DIR')) {
            return [];
        }

        return $this->phpFilesIn(WPMU_PLUGIN_DIR);
    }

    protected function scope()
    {
        if (!defined('WPMU_PLUGIN_DIR')) {
            return '/wp-content/mu-plugins';
        }

        return \FluentAuth\App\Services\Checks\AcceptedFiles::toRelative(WPMU_PLUGIN_DIR);
    }

    protected function firstTitle($count)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'A file runs on every page of your site',
                '%s files run on every page of your site',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }

    protected function words()
    {
        return [
            'first_why'   => __('They load automatically and cannot be switched off from the plugins screen. Some hosts and developers put files here on purpose — have a look, and mark them as expected if you recognise them.', 'fluent-security'),
            'alert_title' => __('Something running on every page of your site has changed', 'fluent-security'),
            'alert_why'   => __('A file you marked as expected is no longer the same file. Nothing here can be switched off from the plugins screen, so it is worth finding out who changed it.', 'fluent-security'),
            'none_title'  => __('Nothing unexpected loads on every page', 'fluent-security')
        ];
    }
}
