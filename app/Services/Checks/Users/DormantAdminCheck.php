<?php

namespace FluentAuth\App\Services\Checks\Users;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Administrator accounts nobody has used in a year.
 *
 * The developer who built the site, the agency that no longer has the contract, the colleague
 * who left. Each one is a full set of keys with nobody watching whether they still work, and
 * they are the accounts whose passwords are oldest and most likely to be in a breach dump.
 *
 * The whole check hangs on one guard. This site's login log goes back only as far as this
 * plugin does, so "nobody has signed in for a year" is only ever a claim about what was
 * watched - on a site that installed the plugin last month it would be a claim about every
 * account, including the one reading it. So nothing is said at all until the log itself is
 * older than the window. Being silent for a year is the correct behaviour; naming an
 * innocent colleague's account as abandoned is not.
 */
class DormantAdminCheck extends Check
{
    public function id()
    {
        return 'dormant_admins';
    }

    public function group()
    {
        return 'users';
    }

    /**
     * @return int
     */
    protected function windowDays()
    {
        return (int)apply_filters('fluent_auth/dormant_admin_days', 365);
    }

    public function run()
    {
        if (!$this->logIsOldEnough()) {
            return [];
        }

        $dormant = $this->dormantAdmins();

        if (!$dormant) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Every administrator account is in use', 'fluent-security'),
                'scored' => false
            ])];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Administrator accounts nobody uses', 'fluent-security'),
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
            'title'    => $this->title(count($dormant)),
            'why'      => __('An account nobody uses is one nobody would notice being used. These usually belong to a developer or a colleague who has moved on.', 'fluent-security'),
            'details'  => array_merge($dormant, [
                __('If somebody still needs access, leave it. If not, removing the account or dropping it to a lesser role costs nothing.', 'fluent-security')
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
     * Whether the log covers the whole window, so an absence of logins means something.
     *
     * @return bool
     */
    protected function logIsOldEnough()
    {
        $oldest = flsDb()->table('fls_auth_logs')
            ->select(['created_at'])
            ->orderBy('created_at', 'ASC')
            ->first();

        if (!$oldest || !$oldest->created_at) {
            return false;
        }

        $age = current_time('timestamp') - strtotime($oldest->created_at);

        return $age >= ($this->windowDays() * DAY_IN_SECONDS);
    }

    /**
     * @return array
     */
    protected function dormantAdmins()
    {
        $cutoff = gmdate('Y-m-d H:i:s', current_time('timestamp') - ($this->windowDays() * DAY_IN_SECONDS));

        $dormant = [];

        foreach (get_users(['role' => 'administrator', 'number' => 100]) as $user) {
            /*
             * The account itself has to predate the window too. Somebody added last week has
             * obviously not signed in for a year, and saying so would be nonsense.
             */
            if (!$user->user_registered || $user->user_registered > $cutoff) {
                continue;
            }

            $recent = flsDb()->table('fls_auth_logs')
                ->where('user_id', $user->ID)
                ->where('status', 'success')
                ->where('created_at', '>', $cutoff)
                ->first();

            if (!$recent) {
                $dormant[] = sprintf(
                    /* translators: 1: a username, 2: an email address */
                    __('%1$s (%2$s)', 'fluent-security'),
                    $user->user_login,
                    $user->user_email
                );
            }
        }

        return $dormant;
    }

    /**
     * @param int $count
     * @return string
     */
    protected function title($count)
    {
        return sprintf(
            /* translators: 1: number of accounts, 2: number of months */
            _n(
                'An administrator account has not been used in %2$s months',
                '%1$s administrator accounts have not been used in %2$s months',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count),
            number_format_i18n((int)round($this->windowDays() / 30))
        );
    }
}
