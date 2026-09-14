<?php

namespace FluentAuth\App\Services\Checks\Users;

use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Accounts the database has and the users screen does not.
 *
 * The oldest trick an attacker plays after getting in once is to arrange to still be in
 * tomorrow, and the cheapest way to do that is a second account. The account on its own
 * would be noticed - so the same code that creates it adds a line to `pre_user_query`, and
 * from then on WordPress's own user list quietly leaves that row out. The owner opens Users,
 * counts the accounts they know about, and is looking at a screen that has been told to lie
 * to them.
 *
 * Which is the whole reason this check can work at all. Hiding a user means filtering the
 * query, and the row itself stays exactly where it was: the attacker cannot delete it,
 * because they need it. So there are two answers to "how many accounts does this site have"
 * - count the table, and ask WordPress - and on an honest site they are the same number.
 *
 * That is the entire check, and keeping it that small is the point. It does not ask what the
 * hidden account can do, and it does not grade one hidden account above another. Any account
 * the screen will not show is the finding, whatever role it wears: a subscriber nobody can
 * see is still an account nobody reviews, and it is the usual shape of the thing anyway -
 * make the quiet account now, promote it later, because a new subscriber is not what anybody
 * is watching for. A check that sorted hidden accounts by privilege would be inventing a
 * distinction the evidence does not support, since the one thing we know for certain about a
 * hidden account is that somebody did not want it looked at.
 *
 * The raw queries are written to match what WP_User_Query builds for the same question - the
 * same members-of-this-site rule on multisite, nothing clever on single site. That is
 * deliberate and it is the property the check rests on: if the two sides are asking the same
 * question of the same table, a difference in the answers cannot be our query being
 * cleverer, and the only thing left it can be is a filter.
 *
 * The restraint this one needs: hiding a user is not by itself wrongdoing. Managed hosts
 * hide their own support account, and membership plugins hide customers from a list that is
 * meant to show staff. So the finding names the accounts and the file filtering the query -
 * which is what tells those two cases apart - and it can be dismissed. The dismissal is
 * keyed to the accounts it was given rather than to the check, so an account hidden next
 * month is a new finding rather than something already silenced.
 *
 * What it does not claim: a filter that only engages on the users screen itself - checking
 * `$pagenow` before it acts - is invisible from here, because this runs during a REST
 * request and that filter will honestly not apply. The passing sentence is worded as what
 * was actually compared for that reason.
 */
class HiddenUsersCheck extends Check
{
    public function id()
    {
        return 'hidden_users';
    }

    public function group()
    {
        return 'users';
    }

    /**
     * How many accounts this is willing to enumerate before it stops naming and starts
     * counting. Comparing every id on a site with a hundred thousand members is not work a
     * page load should be doing, and on a site that size the count alone is still the alarm.
     *
     * @return int
     */
    protected function nameLimit()
    {
        return (int)apply_filters('fluent_auth/hidden_users_name_limit', 5000);
    }

    public function run()
    {
        $hidden = $this->hidden();

        if (!$hidden['ids'] && !$hidden['unnamed']) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Your users list returns every account in the database', 'fluent-security'),
                'scored' => true
            ])];
        }

        if (Dismissals::has($this->dismissKey($hidden['ids']))) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Accounts are kept off your users list', 'fluent-security'),
                'why'    => __('You have said these ones are expected. If a different account is hidden later, this will speak up again.', 'fluent-security'),
                'scored' => false
            ])];
        }

        $accounts = $this->accounts($hidden['ids']);
        $total = count($hidden['ids']) + $hidden['unnamed'];

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $this->title($total),
            'why'      => __('Your database holds accounts that your users list will not show you. That is how access is kept after a break-in — the account stays, and the screen you would notice it on is filtered.', 'fluent-security'),
            'details'  => $this->details($accounts, $total),
            'action'   => 'navigate',
            'label'    => count($accounts) === 1 ? __('Open this account', 'fluent-security') : __('Open users', 'fluent-security'),
            'url'      => count($accounts) === 1
                ? admin_url('user-edit.php?user_id=' . (int)$accounts[0]->ID)
                : admin_url('users.php'),
            'dismiss'  => 'expected',
            'scored'   => true
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

        /*
         * Re-read rather than take the key from the request. What gets silenced is the set
         * of accounts that are hidden right now, which is the set the reader was looking at
         * when they pressed the button - and it means the endpoint cannot be handed a key
         * for accounts nobody has seen yet.
         */
        Dismissals::add($this->dismissKey($this->hidden()['ids']));

        return ['message' => __('Noted. These accounts will not be mentioned again.', 'fluent-security')];
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

        Dismissals::remove($this->dismissKey($this->hidden()['ids']));

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }

    /**
     * What the site has that it will not show.
     *
     * The count is what decides there is a finding. Working out which accounts they are is a
     * separate, more expensive question asked only once the answer is known to matter, and
     * one a large enough site is allowed to leave unanswered.
     *
     * @return array {
     *     @type int[] $ids      accounts we can name
     *     @type int   $unnamed  accounts missing from the count we could not name
     * }
     */
    protected function hidden()
    {
        $missing = max(0, $this->countInDatabase() - $this->countWordPressReturns());

        if (!$missing) {
            return ['ids' => [], 'unnamed' => 0];
        }

        $named = $this->hiddenMembers();

        if ($named === null) {
            return ['ids' => [], 'unnamed' => $missing];
        }

        return [
            'ids'     => $named,
            'unnamed' => max(0, $missing - count($named))
        ];
    }

    /**
     * Members of this site, counted from the table.
     *
     * On multisite that means the ones with a capabilities row for this blog, because that
     * is the rule WP_User_Query applies there and the comparison is only worth anything if
     * both sides are counting the same people.
     *
     * @return int
     */
    protected function countInDatabase()
    {
        global $wpdb;

        if (!is_multisite()) {
            return (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users}");
        }

        return (int)$wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(DISTINCT u.ID) FROM {$wpdb->users} u
                 INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
                 WHERE m.meta_key = %s",
                $this->capabilitiesKey()
            )
        );
    }

    /**
     * The same people, counted by asking WordPress.
     *
     * @return int
     */
    protected function countWordPressReturns()
    {
        $query = new \WP_User_Query([
            'fields'        => 'ID',
            'number'        => 1,
            'count_total'   => true,
            'cache_results' => false
        ]);

        return (int)$query->get_total();
    }

    /**
     * The ids behind the difference in the counts, when there are few enough to work out.
     *
     * @return int[]|null null when the site is too large to compare id by id
     */
    protected function hiddenMembers()
    {
        global $wpdb;

        $limit = $this->nameLimit();

        if (!is_multisite()) {
            $stored = $wpdb->get_col(
                $wpdb->prepare("SELECT ID FROM {$wpdb->users} LIMIT %d", $limit + 1)
            );
        } else {
            $stored = $wpdb->get_col(
                $wpdb->prepare(
                    "SELECT DISTINCT u.ID FROM {$wpdb->users} u
                     INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
                     WHERE m.meta_key = %s LIMIT %d",
                    $this->capabilitiesKey(),
                    $limit + 1
                )
            );
        }

        if (count($stored) > $limit) {
            return null;
        }

        $returned = get_users([
            'fields'        => 'ID',
            'number'        => $limit + 1,
            'cache_results' => false
        ]);

        return array_values(array_map('intval', array_diff(
            array_map('intval', $stored),
            array_map('intval', (array)$returned)
        )));
    }

    /**
     * @return string the capabilities meta key for this site, as WP_User_Query spells it
     */
    protected function capabilitiesKey()
    {
        global $wpdb;

        return $wpdb->get_blog_prefix() . 'capabilities';
    }

    /**
     * The accounts themselves, read straight from the table.
     *
     * Deliberately not get_users() - the point of this check is that get_users() is the thing
     * that has been got at. WP_User does its own direct lookup by id, but doing the read here
     * keeps the whole check on one side of the filter with nothing to think about.
     *
     * @param int[] $ids
     * @return array
     */
    protected function accounts($ids)
    {
        global $wpdb;

        if (!$ids) {
            return [];
        }

        $ids = array_slice(array_map('intval', $ids), 0, 25);

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value AS fls_caps
                 FROM {$wpdb->users} u
                 LEFT JOIN {$wpdb->usermeta} m ON m.user_id = u.ID AND m.meta_key = %s
                 WHERE u.ID IN (" . implode(',', $ids) . ")
                 ORDER BY u.ID ASC",
                $this->capabilitiesKey()
            )
        );

        return $rows ? $rows : [];
    }

    /**
     * The roles and capabilities on an account, as the table has them.
     *
     * Shown, not judged. Which role a hidden account holds is the first thing the reader will
     * want to know, and it is no part of deciding whether to tell them.
     *
     * @param object $account
     * @return string[]
     */
    protected function grantsOf($account)
    {
        $caps = maybe_unserialize($account->fls_caps);

        if (!is_array($caps)) {
            return [];
        }

        return array_keys(array_filter($caps));
    }

    /**
     * @param int $total every hidden account, named or only counted
     * @return string
     */
    protected function title($total)
    {
        return sprintf(
            /* translators: %s: number of accounts */
            _n(
                'Your database has an account that your users list does not show',
                'Your database has %s accounts that your users list does not show',
                $total,
                'fluent-security'
            ),
            number_format_i18n($total)
        );
    }

    /**
     * @param array $accounts the ones named, at most twenty-five of them
     * @param int $total every hidden account, named or only counted
     * @return array
     */
    protected function details($accounts, $total)
    {
        $details = [];

        foreach ($accounts as $account) {
            $grants = $this->grantsOf($account);

            $details[] = sprintf(
                /* translators: 1: username, 2: email address, 3: role and capability names, 4: user ID, 5: date the account was created */
                __('%1$s (%2$s) — %3$s, user ID %4$d, created %5$s', 'fluent-security'),
                $account->user_login,
                $account->user_email,
                $grants ? implode(', ', $grants) : __('no role on this site', 'fluent-security'),
                (int)$account->ID,
                $account->user_registered
            );
        }

        /*
         * One sentence covers both ways the list can fall short of the count - accounts the
         * site is too large to identify, and accounts held back so twenty-five rows of detail
         * do not become a wall. Neither is worth explaining to the reader, who needs to know
         * the number is bigger than the list and nothing else.
         */
        $remaining = max(0, $total - count($accounts));

        if ($remaining) {
            $details[] = sprintf(
                /* translators: %s: number of accounts */
                _n(
                    'One more hidden account is not listed here.',
                    '%s more hidden accounts are not listed here.',
                    $remaining,
                    'fluent-security'
                ),
                number_format_i18n($remaining)
            );
        }

        foreach ($this->filteringCode() as $file) {
            $details[] = sprintf(
                /* translators: %s: a file path */
                __('Filtering the user query: %s', 'fluent-security'),
                $file
            );
        }

        $details[] = __('Managed hosts and membership plugins do this on purpose — a support account, or customers kept out of a staff list. If one of the files above explains it, dismiss this.', 'fluent-security');
        $details[] = __('If nothing explains it, treat the site as broken into: the account is the way back in. Remove it, change every administrator password, and look at what else was added around the date it was created.', 'fluent-security');

        return $details;
    }

    /**
     * The files with code hooked into the user query.
     *
     * Only shown once something is actually missing, and it is the part of this finding a
     * developer can act on: it is the difference between knowing a user is hidden and knowing
     * what is hiding it.
     *
     * @return string[]
     */
    protected function filteringCode()
    {
        global $wp_filter;

        $files = [];

        foreach (['pre_user_query', 'users_pre_query', 'found_users_query'] as $hook) {
            if (empty($wp_filter[$hook])) {
                continue;
            }

            foreach ($wp_filter[$hook] as $callbacks) {
                foreach ((array)$callbacks as $callback) {
                    $file = isset($callback['function']) ? $this->fileOf($callback['function']) : '';

                    if ($file) {
                        $files[$file] = $file;
                    }
                }
            }
        }

        return array_values($files);
    }

    /**
     * @param mixed $callback
     * @return string
     */
    protected function fileOf($callback)
    {
        try {
            if (is_string($callback) && strpos($callback, '::') !== false) {
                $callback = explode('::', $callback);
            }

            if (is_array($callback) && count($callback) === 2) {
                $reflection = new \ReflectionMethod($callback[0], $callback[1]);
            } elseif (is_object($callback) && !$callback instanceof \Closure) {
                $reflection = new \ReflectionMethod($callback, '__invoke');
            } else {
                $reflection = new \ReflectionFunction($callback);
            }

            $file = $reflection->getFileName();
        } catch (\Throwable $exception) {
            /* A callback we cannot look at is not worth failing the whole finding over. */
            return '';
        }

        return $file ? AcceptedFiles::toRelative($file) : '';
    }

    /**
     * Keyed to the accounts, not to the check.
     *
     * Dismissing this says "these accounts are expected", which is a thing a reader can
     * reasonably know. "Whatever is hidden from now on is expected" is not, and it is what a
     * key of `hidden_users` would have meant the next time an account appeared.
     *
     * @param int[] $ids
     * @return string
     */
    protected function dismissKey($ids)
    {
        $ids = array_map('intval', $ids);
        sort($ids);

        return $this->id() . ':' . substr(md5(implode(',', $ids)), 0, 12);
    }
}
