<?php

namespace FluentAuth\App\Services\Checks\Config;

use FluentAuth\App\Services\Checks\Finding;

/**
 * The theme and plugin editor in wp-admin.
 *
 * It turns access to the dashboard into the ability to run any code on the server, which is
 * the step between "somebody got an administrator password" and "somebody owns the machine".
 * Almost nobody edits their theme through it, and the sites that do have a developer who can
 * use SFTP instead.
 */
class FileEditorCheck extends ConfigConstantCheck
{
    public function id()
    {
        return 'file_editor';
    }

    protected function isSatisfied()
    {
        return defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
    }

    protected function words()
    {
        return [
            'title'    => __('Anyone who reaches your dashboard can edit your site\'s code', 'fluent-security'),
            'why'      => __('WordPress lets administrators edit theme and plugin files from the admin screens. That turns a stolen password into the ability to run anything on your server.', 'fluent-security'),
            'passed'   => __('Your site\'s code cannot be edited from the dashboard', 'fluent-security'),
            'snippet'  => "define( 'DISALLOW_FILE_EDIT', true );",
            'severity' => Finding::SEVERITY_LOOK
        ];
    }
}
