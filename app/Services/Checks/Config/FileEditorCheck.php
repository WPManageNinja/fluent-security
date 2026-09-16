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
 *
 * Advice rather than a finding, because nothing here is wrong with this site. The editor
 * being on is WordPress's default and costs nothing until somebody has already got in; what
 * this row offers is one less thing for them to reach when they do. Said in the same amber
 * as a changed mu-plugin, it would be teaching the reader that amber does not mean much.
 *
 * Worth being clear about what the line does not do, since it is easily mixed up with
 * DISALLOW_FILE_MODS: DISALLOW_FILE_EDIT removes the two editor screens and nothing else.
 * Updates, auto-updates and installs all carry on exactly as before.
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
            'title'    => __('Your dashboard can edit theme and plugin files', 'fluent-security'),
            'why'      => __('WordPress lets administrators edit theme and plugin code from the admin screens. Turning that off means a stolen administrator password cannot be used to run code on your server. It does not affect updates or installing plugins.', 'fluent-security'),
            'passed'   => __('Your site\'s code cannot be edited from the dashboard', 'fluent-security'),
            'snippet'  => "define( 'DISALLOW_FILE_EDIT', true );",
            'severity' => Finding::SEVERITY_ADVICE
        ];
    }
}
