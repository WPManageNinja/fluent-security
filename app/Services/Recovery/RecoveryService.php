<?php

namespace FluentAuth\App\Services\Recovery;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\SiteActivityHandler;

/**
 * What to do once you think somebody has been in.
 *
 * The most dangerous surface this plugin has, and the design follows from that. Every action
 * here either evicts somebody or writes to people's inboxes, and it is reached by a person
 * who has just had a fright - so nothing is offered that cannot be explained in a sentence,
 * nothing is done that the reader was not told about, and everything that happens is written
 * to the auth log with the name of whoever did it.
 *
 * Two mechanisms are deliberately not the obvious ones.
 *
 * Signing everyone out destroys the session tokens rather than rotating the salts in
 * wp-config.php. Both evict every cookie on the site; only one of them involves this plugin
 * rewriting the single file a WordPress install cannot survive being wrong - and the salts
 * are not only used for cookies. Plenty of plugins derive an encryption key from them and
 * keep credentials under it: an SMTP password, a payment gateway's secret. Rotating the
 * salts turns all of those into ciphertext nobody holds the key for, silently, and the site
 * only finds out the next time it tries to send an email or take a payment. There is no
 * outcome the rotation buys here that is worth that, so the salts are left alone and the
 * screen says so.
 *
 * And the person running the recovery stays signed in. Turning them out along with everyone
 * else reads as thorough and helps nobody: an attacker holding an administrator account can
 * do this again whatever we revoke, and the one person who needs to keep working is the one
 * at the keyboard.
 */
class RecoveryService
{
    const QUEUE_OPTION = '__fls_recovery_reset_queue';

    const LOG_OPTION = '__fls_recovery_log';

    /**
     * How many reset emails one run will send.
     *
     * A site with four thousand users cannot be mailed inside one request, and a recovery that
     * dies half way through leaves nobody knowing who was told. So the list is worked through
     * in batches on the scheduler, and the screen reports how far it has got.
     */
    const BATCH = 50;

    /**
     * Sign everyone out and revoke every application password.
     *
     * Paired behind one button because they are the same job: both are ways of being signed
     * in to this site, and evicting one while leaving the other is not eviction.
     *
     * They are not equally easy to undo, though, and the screen no longer pretends otherwise.
     * A session comes back by signing in. An application password does not - it is deleted,
     * the plaintext existed once and was never stored, and whatever was using it (a phone, a
     * backup plugin, a script on another server) starts failing immediately with nobody
     * emailed about it. Somebody has to issue a new one and paste it wherever the old one
     * went. That is the sentence the confirmation has to earn, which is why it asks for the
     * words to be typed rather than for a second click.
     *
     * @param bool $rotateSalts also replace the keys in wp-config.php - opt-in, see SaltRotation
     * @return array
     */
    public static function secureNow($rotateSalts = false)
    {
        $currentUser = get_current_user_id();

        $sessions = self::countSessions();
        $passwords = self::revokeApplicationPasswords();

        \WP_Session_Tokens::destroy_all_for_all_users();

        /*
         * Last, because it is the only step that can fail on somebody else's terms - a file
         * that turned out not to be writable, a layout nothing recognises. Doing it after the
         * eviction means a refusal costs the key change and nothing else; doing it first would
         * mean a site signed out by a step that then did not happen.
         */
        $rotated = false;
        $saltsError = '';

        if ($rotateSalts) {
            $result = SaltRotation::rotate();

            if (is_wp_error($result)) {
                $saltsError = $result->get_error_message();
            } else {
                $rotated = true;
            }
        }

        /*
         * Re-issued straight away for the one person who has to keep working. Done after the
         * sweep rather than exempted from it, so their old session is discarded too - if the
         * cookie in this browser was the stolen one, it stops being valid here as well.
         *
         * Not when the keys have just been replaced, and not as an oversight. A cookie minted
         * in this request would be signed with the keys this PHP process loaded at boot, which
         * are now the old ones - it would be refused on the very next request, and the person
         * would be bounced to a login screen having been told they were still signed in. When
         * the keys move, everybody goes, including whoever asked for it. That is the feature.
         */
        if ($currentUser && !$rotated) {
            wp_set_auth_cookie($currentUser, false);
        }

        self::log(
            'secure_now',
            sprintf(
                /* translators: 1: number of sessions, 2: number of application passwords */
                __('Signed out %1$s sessions and revoked %2$s application passwords.', 'fluent-security'),
                number_format_i18n($sessions),
                number_format_i18n($passwords)
            )
        );

        return [
            'sessions'  => $sessions,
            'passwords' => $passwords,
            'salts_rotated' => $rotated,
            'salts_error'   => $saltsError,
            /*
             * Where to send the browser, because it is holding a cookie that stopped being
             * valid while this response was being written. Nothing else on the screen can be
             * loaded with it, so the screen redirects rather than trying.
             */
            'redirect_url'  => $rotated
                ? wp_login_url(admin_url('admin.php?page=fluent-auth#/security/recovery'))
                : '',
            /* The numbers, because "every application password" is the part somebody has to go and fix. */
            'message'   => self::secureNowMessage($sessions, $passwords, $rotated, $saltsError)
        ];
    }

    /**
     * One sentence for what just happened, which is three different sentences.
     *
     * Kept out of secureNow() because the interesting case is the partial one: the site was
     * signed out, the key change was refused, and the person is still signed in. Reporting
     * that as a success with a warning somewhere else is how somebody walks away believing
     * their keys were replaced.
     *
     * @param int $sessions
     * @param int $passwords
     * @param bool $rotated
     * @param string $saltsError
     * @return string
     */
    protected static function secureNowMessage($sessions, $passwords, $rotated, $saltsError)
    {
        $evicted = sprintf(
            /* translators: 1: number of sessions, 2: number of application passwords */
            __('Signed out %1$s sessions and permanently deleted %2$s application passwords.', 'fluent-security'),
            number_format_i18n($sessions),
            number_format_i18n($passwords)
        );

        if ($rotated) {
            return $evicted . ' ' . __('The eight security keys have been replaced, so you have been signed out here too. Sign in again to carry on.', 'fluent-security');
        }

        if ($saltsError) {
            /* translators: %s: why the keys could not be changed */
            return $evicted . ' ' . sprintf(__('The security keys were left alone: %s', 'fluent-security'), $saltsError);
        }

        return $evicted . ' ' . __('You are still signed in here.', 'fluent-security');
    }

    /**
     * What pressing the button would cost, counted before it is pressed.
     *
     * The confirmation is only worth typing out if it says something specific, and "every
     * application password will stop working" means nothing to somebody who does not know
     * whether this site has any. Two numbers turn it into a decision: nought here and the
     * step is merely disruptive; eleven across four people and somebody needs to warn four
     * people first.
     *
     * Counted from usermeta directly rather than through get_users(), because the answer is
     * a number rather than a list of users and a site with fifty thousand accounts should
     * not load them all to draw one sentence.
     *
     * @return array
     */
    public static function impact()
    {
        global $wpdb;

        $passwords = 0;
        $people = 0;

        if (class_exists('\WP_Application_Passwords')) {
            $rows = $wpdb->get_col(
                $wpdb->prepare(
                    "SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s",
                    \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS
                )
            );

            foreach ($rows as $row) {
                $items = maybe_unserialize($row);

                if (is_array($items) && $items) {
                    $passwords += count($items);
                    $people++;
                }
            }
        }

        return [
            'sessions'        => self::countSessions(),
            'passwords'       => $passwords,
            'password_people' => $people
        ];
    }

    /**
     * Who can change this site, and what is known about how they got there.
     *
     * The dates are the point. An administrator account created an hour before the file you
     * are worried about appeared is the single most useful thing this screen can show, and it
     * is not visible anywhere in WordPress without reading two screens side by side.
     *
     * @return array
     */
    public static function administrators()
    {
        $users = get_users([
            'role'    => 'administrator',
            'orderby' => 'registered',
            'order'   => 'DESC',
            'number'  => 100
        ]);

        $administrators = [];

        foreach ($users as $user) {
            $lastLogin = flsDb()->table('fls_auth_logs')
                ->where('user_id', $user->ID)
                ->where('status', 'success')
                ->orderBy('created_at', 'DESC')
                ->first();

            $registered = $user->user_registered;

            $administrators[] = [
                'id'           => $user->ID,
                'login'        => $user->user_login,
                'email'        => $user->user_email,
                'registered'   => $registered,
                'registered_human' => $registered
                    ? sprintf(
                        /* translators: %s: a length of time, for example "3 days" */
                        __('%s ago', 'fluent-security'),
                        human_time_diff(strtotime($registered), current_time('timestamp'))
                    )
                    : '',
                /*
                 * Flagged rather than sorted on. It is a fact worth having in front of you,
                 * not a verdict - people do add administrators in an ordinary week.
                 */
                'is_new'       => $registered && (current_time('timestamp') - strtotime($registered)) < WEEK_IN_SECONDS,
                /*
                 * The whole phrase, not a value for the screen to introduce. Two answers here
                 * do not share a sentence - "signed in 3 hours ago" and "we have no record of
                 * this account signing in" are different claims, and a template that prefixes
                 * both with "Last signed in" produces one of them wrong.
                 *
                 * And it is not "never". This site's log goes back only as far as the plugin
                 * does, and telling somebody an account has never been used when the truth is
                 * that nobody was watching is the sort of wrong that gets an innocent
                 * colleague's account deleted at midnight.
                 */
                'last_login'   => $lastLogin
                    ? sprintf(
                        /* translators: %s: a length of time, for example "3 days" */
                        __('Signed in %s ago', 'fluent-security'),
                        human_time_diff(strtotime($lastLogin->created_at), current_time('timestamp'))
                    )
                    : __('Not signed in since logging began', 'fluent-security'),
                'edit_url'     => get_edit_user_link($user->ID),
                'is_you'       => $user->ID === get_current_user_id()
            ];
        }

        return $administrators;
    }

    /**
     * Queue a password reset email for everyone in scope.
     *
     * Worded as what it is throughout: this sends people a link. It does not stop the old
     * password working until somebody uses the link, and the screen says so - a button called
     * "force a reset" that quietly does less than that is worse than no button.
     *
     * @param string $scope administrators|all
     * @return array|\WP_Error
     */
    public static function queuePasswordResets($scope)
    {
        if (!in_array($scope, ['administrators', 'all'], true)) {
            return new \WP_Error(
                'unknown_scope',
                __('That is not a group this plugin can email.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $args = ['fields' => 'ID', 'number' => -1];

        if ($scope === 'administrators') {
            $args['role'] = 'administrator';
        }

        $ids = array_map('intval', get_users($args));

        if (!$ids) {
            return new \WP_Error(
                'nobody_to_email',
                __('There is nobody in that group to email.', 'fluent-security'),
                ['status' => 422]
            );
        }

        update_option(self::QUEUE_OPTION, [
            'scope'     => $scope,
            'pending'   => $ids,
            'total'     => count($ids),
            'sent'      => 0,
            'failed'    => 0,
            'started_at' => current_time('mysql')
        ], false);

        self::log(
            'password_resets',
            sprintf(
                /* translators: %s: number of people */
                __('Started sending password reset links to %s people.', 'fluent-security'),
                number_format_i18n(count($ids))
            )
        );

        /* The first batch goes now so the screen has something to report immediately. */
        $progress = self::processQueue();

        return [
            'progress' => $progress,
            'message'  => sprintf(
                /* translators: %s: number of people */
                _n(
                    'Sending a reset link to %s person.',
                    'Sending reset links to %s people.',
                    count($ids),
                    'fluent-security'
                ),
                number_format_i18n(count($ids))
            )
        ];
    }

    /**
     * Send the next batch, and schedule the one after it if there is more to do.
     *
     * @return array
     */
    public static function processQueue()
    {
        $queue = get_option(self::QUEUE_OPTION, []);

        if (!is_array($queue) || empty($queue['pending'])) {
            return self::progress();
        }

        $batch = array_splice($queue['pending'], 0, self::BATCH);

        foreach ($batch as $userId) {
            if (self::sendResetEmail($userId)) {
                $queue['sent']++;
            } else {
                $queue['failed']++;
            }
        }

        update_option(self::QUEUE_OPTION, $queue, false);

        if ($queue['pending']) {
            wp_schedule_single_event(time() + 60, 'fluent_auth_recovery_resets');
        } else {
            self::log(
                'password_resets_done',
                sprintf(
                    /* translators: 1: number sent, 2: number that failed */
                    __('Finished sending password reset links: %1$s sent, %2$s could not be sent.', 'fluent-security'),
                    number_format_i18n($queue['sent']),
                    number_format_i18n($queue['failed'])
                )
            );
        }

        return self::progress();
    }

    /**
     * @return array
     */
    public static function progress()
    {
        $queue = get_option(self::QUEUE_OPTION, []);

        if (!is_array($queue) || empty($queue['total'])) {
            return ['running' => false];
        }

        return [
            'running' => !empty($queue['pending']),
            'scope'   => isset($queue['scope']) ? $queue['scope'] : '',
            'total'   => (int)$queue['total'],
            'sent'    => (int)$queue['sent'],
            'failed'  => (int)$queue['failed']
        ];
    }

    /**
     * @return array
     */
    public static function history()
    {
        $log = get_option(self::LOG_OPTION, []);

        return is_array($log) ? array_slice($log, 0, 10) : [];
    }

    /**
     * @param int $userId
     * @return bool
     */
    protected static function sendResetEmail($userId)
    {
        $user = get_user_by('ID', $userId);

        if (!$user || !is_email($user->user_email)) {
            return false;
        }

        /*
         * Built here rather than through retrieve_password(), which lives in different files
         * in different WordPress versions and sends the standard "someone asked to reset your
         * password" wording. Nobody asked for this one, and an email that says so is the
         * difference between a reset people act on and a reset people report as phishing.
         */
        $key = get_password_reset_key($user);

        if (is_wp_error($key)) {
            return false;
        }

        $url = network_site_url(
            'wp-login.php?action=rp&key=' . rawurlencode($key) . '&login=' . rawurlencode($user->user_login),
            'login'
        );

        $subject = sprintf(
            /* translators: %s: the site name */
            __('Please choose a new password for %s', 'fluent-security'),
            wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES)
        );

        $message = sprintf(
            /* translators: 1: the site name, 2: the reset link */
            __(
                "An administrator of %1\$s is asking everyone to choose a new password as a precaution.\n\nYou did not request this, and nothing is wrong with your account. Please set a new password here:\n\n%2\$s\n\nIf you do nothing, your current password will keep working.",
                'fluent-security'
            ),
            wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES),
            $url
        );

        return (bool)wp_mail($user->user_email, $subject, $message);
    }

    /**
     * @return int
     */
    protected static function revokeApplicationPasswords()
    {
        if (!class_exists('\WP_Application_Passwords')) {
            return 0;
        }

        $users = get_users([
            'fields'     => 'ID',
            'number'     => -1,
            'meta_query' => [
                [
                    'key'     => \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS,
                    'compare' => 'EXISTS'
                ]
            ]
        ]);

        $revoked = 0;

        foreach ($users as $userId) {
            $count = \WP_Application_Passwords::delete_all_application_passwords((int)$userId);

            if (!is_wp_error($count)) {
                $revoked += (int)$count;
            }
        }

        return $revoked;
    }

    /**
     * @return int
     */
    protected static function countSessions()
    {
        global $wpdb;

        $rows = $wpdb->get_col(
            "SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'"
        );

        $sessions = 0;

        foreach ($rows as $row) {
            $tokens = maybe_unserialize($row);

            if (is_array($tokens)) {
                $sessions += count($tokens);
            }
        }

        return $sessions;
    }

    /**
     * Every action here is on the record, with who did it.
     *
     * Written to the auth log the rest of the plugin uses, under its own status so it cannot
     * be counted as a login in the dashboard's figures, and kept as a short list of its own so
     * the recovery screen can say when it was last used without reading the log table.
     *
     * Public because the file recovery writes to the same record - one log, one "last used",
     * whichever half of the recovery was used.
     *
     * @param string $action
     * @param string $description
     * @return void
     */
    public static function log($action, $description)
    {
        global $wpdb;

        $user = wp_get_current_user();

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'    => $user ? $user->user_login : '',
            'user_id'     => $user ? $user->ID : null,
            'ip'          => Helper::getIp(),
            'status'      => SiteActivityHandler::STATUS,
            'media'       => $action,
            'description' => $description,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql')
        ]);

        $history = get_option(self::LOG_OPTION, []);

        if (!is_array($history)) {
            $history = [];
        }

        array_unshift($history, [
            'action'      => $action,
            'description' => $description,
            'by'          => $user ? $user->user_login : '',
            'at'          => current_time('mysql')
        ]);

        update_option(self::LOG_OPTION, array_slice($history, 0, 10), false);
    }
}
