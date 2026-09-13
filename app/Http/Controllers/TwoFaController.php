<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
use FluentAuth\App\Services\TwoFa\FactorMigration;
use FluentAuth\App\Services\TwoFa\FactorStore;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Who has a second factor, and the way back in when a device is lost.
 *
 * Without this the only way to answer either question is to open every user's profile
 * one at a time, which for the one case that matters - somebody locked out, on the
 * phone, right now - is not an answer at all.
 */
class TwoFaController
{
    const PER_PAGE = 20;

    public static function getUsers(\WP_REST_Request $request)
    {
        $page = max(1, (int)$request->get_param('page'));
        $search = sanitize_text_field((string)$request->get_param('search'));
        $filter = sanitize_text_field((string)$request->get_param('filter'));

        $page = self::queryPage($page, $search, $filter);

        $users = [];

        foreach ($page['ids'] as $userId) {
            $user = get_user_by('ID', $userId);

            if ($user) {
                $users[] = self::formatUser($user);
            }
        }

        return [
            'users' => [
                'data'         => $users,
                'total'        => $page['total'],
                'per_page'     => self::PER_PAGE,
                'current_page' => $page['page'],
                'last_page'    => (int)ceil($page['total'] / self::PER_PAGE)
            ],
            'summary' => self::getSummary(),
            /*
             * Reported with the rows rather than read from the settings the admin screen
             * was booted with: this list is where somebody lands after changing a policy,
             * and a stale answer here would have the screen describing the site as it was
             * when the tab was opened.
             */
            'methods' => self::getMethodStates()
        ];
    }

    /**
     * Turns off a user's authenticator app.
     *
     * This is the lost phone path, so it is the one action here that changes anything -
     * and it lowers the account's protection, which is why it re-checks the capability
     * to edit that specific user rather than trusting the endpoint's own permission.
     */
    public static function resetUser(\WP_REST_Request $request)
    {
        $userId = (int)$request->get_param('id');

        $user = $userId ? get_user_by('ID', $userId) : false;

        if (!$user) {
            return new \WP_Error('not_found', __('The user could not be found', 'fluent-security'), ['status' => 404]);
        }

        if (!current_user_can('edit_user', $userId)) {
            return new \WP_Error(
                'forbidden',
                __('You are not allowed to change this user', 'fluent-security'),
                ['status' => 403]
            );
        }

        if (!TotpTwoFaMethod::isEnrolled($user)) {
            return new \WP_Error(
                'not_enrolled',
                __('This user does not have an authenticator app set up', 'fluent-security'),
                ['status' => 422]
            );
        }

        TotpTwoFaMethod::disable($user);

        return [
            'user'    => self::formatUser($user),
            'summary' => self::getSummary(),
            /* translators: %s: the user's login name */
            'message' => sprintf(__('The authenticator app for %s has been turned off. They can set up a new one from their profile.', 'fluent-security'), $user->user_login)
        ];
    }

    /**
     * One page of the list, with its total.
     *
     * Written as a query rather than assembled from WP_User_Query, because enrollment
     * no longer lives in user meta and WP_User_Query cannot join a table it has never
     * heard of. What is below is what the meta clauses compiled to anyway - roles live
     * serialised inside one capabilities key, so matching a role has always been a LIKE
     * over that key - with the enrollment half now a join instead of a second one.
     *
     * Who belongs on this list at all: not every user on the site. A membership site
     * has thousands of subscribers who are offered nothing, and a page of "Not
     * available" repeated down every column buries the handful of rows worth reading.
     *
     * So: anybody whose role is offered a second factor, or - however the policy has
     * changed since - anybody who actually has one. That second half is not tidiness. A
     * user who enrolled while their role was allowed keeps a working factor when the
     * role is taken off the list, and this screen is the only place to turn it off; drop
     * them and the count above the table reports somebody the table cannot show.
     *
     * @param $page int
     * @param $search string
     * @param $filter string
     * @return array
     */
    private static function queryPage($page, $search, $filter)
    {
        global $wpdb;

        /*
         * Asked before the query rather than after it, because this join is exactly what
         * cannot see a legacy enrollment: a user still in user meta is absent from the
         * table, so the list would report them as never having set anything up and offer
         * to help them enrol again.
         */
        FactorMigration::ensureMigrated();

        $factors = FactorStore::table();
        $capsKey = $wpdb->get_blog_prefix() . 'capabilities';

        /*
         * Joined on the active rows only, so a half-finished setup does not read as an
         * enrollment - which is the distinction the old storage could not draw at all,
         * because a pending secret and a live one were the same serialised blob.
         */
        $join = FactorStore::hasTable()
            ? "LEFT JOIN {$factors} f ON f.user_id = u.ID AND f.status = 'active'
               AND f.type IN ('" . FactorStore::TYPE_TOTP . "', '" . FactorStore::TYPE_PASSKEY . "')"
            : '';

        $enrolledTest = FactorStore::hasTable() ? 'f.id IS NOT NULL' : '0 = 1';

        $conditions = [];
        $values = [];

        $scope = [$enrolledTest];

        foreach (self::getCoveredRoles() as $role) {
            $scope[] = 'caps.meta_value LIKE %s';
            $values[] = '%' . $wpdb->esc_like('"' . $role . '"') . '%';
        }

        $conditions[] = '(' . implode(' OR ', $scope) . ')';

        /*
         * Filtering belongs in the query rather than in a loop over the page, or
         * "show me who is enrolled" returns however many of the first twenty users
         * happen to be.
         */
        if ($filter === 'enrolled') {
            $conditions[] = $enrolledTest;
        } elseif ($filter === 'not_enrolled') {
            $conditions[] = FactorStore::hasTable() ? 'f.id IS NULL' : '1 = 1';
        }

        if ($search) {
            $like = '%' . $wpdb->esc_like($search) . '%';
            $conditions[] = '(u.user_login LIKE %s OR u.user_email LIKE %s OR u.display_name LIKE %s)';
            $values[] = $like;
            $values[] = $like;
            $values[] = $like;
        }

        $where = implode(' AND ', $conditions);

        $from = "FROM {$wpdb->users} u
            LEFT JOIN {$wpdb->usermeta} caps ON caps.user_id = u.ID AND caps.meta_key = %s
            {$join}
            WHERE {$where}";

        $capsValues = array_merge([$capsKey], $values);

        /*
         * Counted separately rather than with SQL_CALC_FOUND_ROWS, which MySQL has
         * deprecated and which behaves differently once a GROUP BY is involved.
         */
        $total = (int)$wpdb->get_var(
            $wpdb->prepare("SELECT COUNT(DISTINCT u.ID) {$from}", $capsValues)
        );

        $page = max(1, (int)$page);
        $offset = ($page - 1) * self::PER_PAGE;

        $ids = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT u.ID {$from} GROUP BY u.ID ORDER BY u.ID ASC LIMIT %d OFFSET %d",
                array_merge($capsValues, [self::PER_PAGE, $offset])
            )
        );

        return [
            'ids'   => array_map('intval', (array)$ids),
            'total' => $total,
            'page'  => $page
        ];
    }

    /**
     * The roles offered a second factor by one method or the other.
     *
     * @return array
     */
    private static function getCoveredRoles()
    {
        $roles = [];

        if (TotpTwoFaMethod::isEnabledForAnyRole()) {
            $roles = (array)Helper::getSetting('totp_2fa_roles');
        }

        if (PasskeyTwoFaMethod::isEnabledForAnyRole()) {
            $roles = array_merge($roles, (array)Helper::getSetting('passkey_2fa_roles'));
        }

        if (EmailTwoFaMethod::isEnabledForAnyRole()) {
            $roles = array_merge($roles, (array)Helper::getSetting('email2fa_roles'));
        }

        return array_values(array_unique(array_filter($roles)));
    }

    /**
     * Which second factors this site actually has in force.
     *
     * @return array
     */
    private static function getMethodStates()
    {
        return [
            'totp'    => TotpTwoFaMethod::isEnabledForAnyRole(),
            'email'   => EmailTwoFaMethod::isEnabledForAnyRole(),
            'passkey' => PasskeyTwoFaMethod::isEnabledForAnyRole()
        ];
    }

    /**
     * @param $user \WP_User
     * @return array
     */
    private static function formatUser($user)
    {
        $enrolled = TotpTwoFaMethod::isEnrolled($user);

        $emailRoles = Helper::getSetting('email2fa_roles');

        $emailApplies = Helper::getSetting('email2fa') === 'yes'
            && is_array($emailRoles)
            && (bool)array_intersect($emailRoles, array_values($user->roles));

        return [
            'id'              => (int)$user->ID,
            'user_login'      => $user->user_login,
            'display_name'    => $user->display_name,
            'user_email'      => $user->user_email,
            'roles'           => array_values($user->roles),
            'totp_enrolled'   => $enrolled,
            'passkey_count'   => PasskeyTwoFaMethod::isEnrolled($user) ? \FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore::countForUser($user) : 0,
            'totp_allowed'    => TotpTwoFaMethod::isAllowedForUser($user),
            'totp_required'   => TotpTwoFaMethod::isRequiredForUser($user),
            'activated_at'    => $enrolled ? TotpTwoFaMethod::getActivatedAt($user) : '',
            'recovery_codes'  => $enrolled ? TotpTwoFaMethod::getRemainingRecoveryCount($user) : 0,
            'recovery_total'  => TotpTwoFaMethod::RECOVERY_CODE_COUNT,
            'email_2fa'       => $emailApplies,
            'can_edit'        => current_user_can('edit_user', $user->ID)
        ];
    }

    /**
     * Counted with queries rather than by walking every user, so a site with a large
     * membership does not pay for this panel.
     *
     * @return array
     */
    private static function getSummary()
    {
        $enrolled = self::countEnrolledUsers();

        /*
         * Measured against the people who could have one, not against everybody with an
         * account. "3 of 4000" describes a membership list; "3 of 5" describes whether
         * the policy has landed, which is the only reason to put a number here.
         */
        $allowedRoles = TotpTwoFaMethod::isEnabledForAnyRole()
            ? (array)Helper::getSetting('totp_2fa_roles')
            : [];

        $eligible = 0;

        if ($allowedRoles) {
            $query = new \WP_User_Query([
                'number'    => 1,
                'fields'    => 'ID',
                'role__in'  => $allowedRoles
            ]);

            $eligible = (int)$query->get_total();
        }

        return [
            'enrolled' => $enrolled,
            'eligible' => $eligible
        ];
    }

    /**
     * How many people hold a device factor of any kind.
     *
     * Counted across passkeys and authenticator apps together, which the old count could
     * not do: it asked user meta, and a passkey has never been stored there. A site that
     * had rolled out passkeys was told nobody was enrolled.
     *
     * @return int
     */
    public static function countEnrolledUsers()
    {
        global $wpdb;

        FactorMigration::ensureMigrated();

        if (!FactorStore::hasTable()) {
            return 0;
        }

        $table = FactorStore::table();

        return (int)$wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(DISTINCT user_id) FROM {$table} WHERE `status` = %s AND `type` IN (%s, %s)",
                FactorStore::STATUS_ACTIVE,
                FactorStore::TYPE_TOTP,
                FactorStore::TYPE_PASSKEY
            )
        );
    }
}
