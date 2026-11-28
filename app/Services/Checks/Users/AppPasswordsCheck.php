<?php

namespace FluentAuth\App\Services\Checks\Users;

use FluentAuth\App\Services\AppPasswords;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Application passwords nobody has used in a while. They sign in as their user without a
 * second factor, so one left behind by an old integration is a key nobody is watching.
 * Revoking happens on the Application Passwords screen; this only points there.
 */
class AppPasswordsCheck extends Check
{
    public function id()
    {
        return 'unused_app_passwords';
    }

    public function group()
    {
        return 'users';
    }

    public function run()
    {
        if (!current_user_can('list_users')) {
            return [];
        }

        $unused = AppPasswords::unused();

        // A list cut short at the cap cannot vouch for the passwords it did not read.
        if (!$unused && AppPasswords::isTruncated()) {
            return [];
        }

        if (!$unused) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Every application password is in use', 'fluent-security'),
                'scored' => false
            ])];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Application passwords nobody uses', 'fluent-security'),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        $details = [];
        foreach (array_slice($unused, 0, 10) as $row) {
            $details[] = sprintf(
                /* translators: 1: the application password's name, 2: the user's login name */
                __('"%1$s" of %2$s', 'fluent-security'),
                $row['name'],
                $row['user_login']
            );
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_LOOK,
            /* translators: 1: how many application passwords, 2: number of days */
            'title'    => sprintf(_n('%1$d application password nobody has used in %2$d days', '%1$d application passwords nobody has used in %2$d days', count($unused), 'fluent-security'), count($unused), AppPasswords::UNUSED_DAYS),
            'why'      => __('An application password signs in as its user without a second factor. One left behind by an old integration is a way in that nobody is watching.', 'fluent-security'),
            'details'  => $details,
            'action'   => 'navigate',
            'label'    => __('Review application passwords', 'fluent-security'),
            'route'    => 'settings_app_passwords',
            'dismiss'  => 'ignore',
            'scored'   => false
        ])];
    }

    public function accept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('That is not something this plugin knows how to check.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::add($this->id());

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    public function unaccept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('There is nothing to undo for this one.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::remove($this->id());

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }
}
