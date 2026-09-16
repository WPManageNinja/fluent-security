<?php

namespace FluentAuth\App\Services\Checks\Users;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * An administrator called "admin".
 *
 * Half of every login is the username, and this one is guessed first by every tool that
 * guesses. It does not make an account weaker on its own - what it does is take a password
 * that would need to be found alongside a username and leave only the password to find.
 *
 * Worth a look rather than fix-this: with a strong password and the login limits this plugin
 * already applies, it is a nuisance rather than a hole, and renaming an account somebody has
 * used for ten years is not a small ask.
 */
class AdminUsernameCheck extends Check
{
    public function id()
    {
        return 'admin_username';
    }

    public function group()
    {
        return 'users';
    }

    public function run()
    {
        $guessable = $this->guessableAdmins();

        if (!$guessable) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('No administrator has an easily guessed username', 'fluent-security'),
                'scored' => false
            ])];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('An administrator has an easily guessed username', 'fluent-security'),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_LOOK,
            'title'    => $this->title(count($guessable)),
            'why'      => __('The username is half of every login, and these are the ones guessed first. Whoever is trying only has the password left to find.', 'fluent-security'),
            'details'  => array_merge($guessable, [
                __('WordPress cannot rename an account. Create a new administrator, sign in as them, then delete the old one and assign its posts to the new account.', 'fluent-security')
            ]),
            'action'   => 'navigate',
            'label'    => __('Open users', 'fluent-security'),
            'url'      => admin_url('users.php?role=administrator'),
            'dismiss'  => 'ignore',
            'scored'   => false
        ])];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('That is not something this plugin knows how to check.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::add($this->id());

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('There is nothing to undo for this one.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::remove($this->id());

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }

    /**
     * @return array
     */
    protected function guessableAdmins()
    {
        $names = apply_filters('fluent_auth/guessable_usernames', ['admin', 'administrator', 'root', 'webmaster', 'test']);

        $found = [];

        foreach (get_users(['role' => 'administrator', 'number' => 100]) as $user) {
            if (in_array(strtolower($user->user_login), $names, true)) {
                $found[] = $user->user_login;
            }
        }

        return $found;
    }

    /**
     * @param int $count
     * @return string
     */
    protected function title($count)
    {
        return sprintf(
            /* translators: %s: number of accounts */
            _n(
                'An administrator account has a username people guess first',
                '%s administrator accounts have usernames people guess first',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }
}
