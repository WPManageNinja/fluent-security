<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;
use FluentAuth\App\Services\IpRules;
use FluentAuth\App\Services\SecurityChecks;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Everything the dashboard shows, in one request.
 *
 * The screen used to make three calls and still only had counts and two log tables to
 * show for it. It is one call now because every panel on the page is a different reading
 * of the same two things - the log table over a date range, and the settings - so
 * splitting them across endpoints only means parsing the same range five times and
 * paying for five round trips to draw one screen.
 */
class DashboardController
{
    /**
     * A day's worth of logs at the busiest site is still a small table to group over, but
     * the lists on the page are previews with a "view all" beside them, so they are kept
     * short deliberately rather than for the sake of the query.
     */
    const LIST_LIMIT = 6;

    public static function getDashboard(\WP_REST_Request $request)
    {
        $range = self::resolveRange(sanitize_text_field((string)$request->get_param('day_range')));

        return [
            'range'      => [
                'key'   => $range['key'],
                'label' => $range['label']
            ],
            'stats'      => self::getStats($range),
            'chart'      => self::getChart($range),
            'recent'     => [
                'threats'   => self::getRecentLogs(['failed', 'blocked'], $range),
                'successes' => self::getRecentLogs(['success'], $range)
            ],
            'top_ips'    => self::getTopIps($range),
            'methods'    => self::getLoginMethods($range),
            /*
             * The checklist used to be assembled here. The aside now fetches it from the same
             * endpoint the security screen uses - see _SecurityAside.vue - so there is one
             * answer to "what is wrong with this site" rather than one per screen, and the
             * dashboard's own figures are not held up behind the checks that produce it.
             */
            'protection' => self::getProtection()
        ];
    }

    /**
     * Turns on the protection one checklist item asks for.
     *
     * The parameter names a check, not a setting - see SecurityChecks::apply(), which also
     * re-establishes for itself that the change is safe to make rather than trusting that
     * the dashboard only offered buttons it should have.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function applySecurityCheck(\WP_REST_Request $request)
    {
        return SecurityChecks::apply(sanitize_text_field((string)$request->get_param('key')));
    }

    /* ------------------------------------------------------------------ range */

    /**
     * Turns the range the user picked into the dates to query and the bucket to chart by.
     *
     * The bucket is part of the range rather than a separate choice because it follows
     * from it: one day of activity is only legible by the hour, a year of it only by the
     * month, and there is no reading of either where the other granularity helps.
     *
     * @param string $key
     * @return array
     */
    private static function resolveRange($key)
    {
        $wpTimestamp = current_time('timestamp');
        $endOfToday = date('Y-m-d 23:59:59', $wpTimestamp);

        $ranges = [
            '-0 days'    => [
                'label'  => __('Today', 'fluent-security'),
                'from'   => date('Y-m-d 00:00:00', $wpTimestamp),
                'bucket' => 'hour'
            ],
            '-7 days'    => [
                'label'  => __('Last 7 days', 'fluent-security'),
                'from'   => date('Y-m-d 00:00:00', strtotime('-6 days', $wpTimestamp)),
                'bucket' => 'day'
            ],
            '-30 days'   => [
                'label'  => __('Last 30 days', 'fluent-security'),
                'from'   => date('Y-m-d 00:00:00', strtotime('-29 days', $wpTimestamp)),
                'bucket' => 'day'
            ],
            'this_month' => [
                'label'  => __('This month', 'fluent-security'),
                'from'   => date('Y-m-01 00:00:00', $wpTimestamp),
                'bucket' => 'day'
            ],
            'all_time'   => [
                'label'  => __('All time', 'fluent-security'),
                'from'   => self::firstLogMonth($wpTimestamp),
                'bucket' => 'month'
            ]
        ];

        if (!isset($ranges[$key])) {
            $key = '-30 days';
        }

        return $ranges[$key] + [
                'key' => $key,
                'to'  => $endOfToday
            ];
    }

    /**
     * Where "all time" starts: the month of the oldest log, capped at a year.
     *
     * Logs are pruned on a schedule, so "all time" is rarely more than a few months - but
     * a site that turned pruning off would otherwise chart one bar per month back to
     * whenever it was installed, which is a lot of chart for very little to read.
     *
     * @param int $wpTimestamp
     * @return string
     */
    private static function firstLogMonth($wpTimestamp)
    {
        $oldest = flsDb()->table('fls_auth_logs')->orderBy('created_at', 'ASC')->first();

        $floor = date('Y-m-01 00:00:00', strtotime('-11 months', $wpTimestamp));

        if (!$oldest || !$oldest->created_at) {
            return $floor;
        }

        $oldestMonth = date('Y-m-01 00:00:00', strtotime($oldest->created_at));

        return max($floor, $oldestMonth);
    }

    /* ------------------------------------------------------------------ tiles */

    /**
     * The four numbers along the top.
     *
     * Three of them are the range's activity; the fourth is how many accounts have an
     * authenticator app, which is not a date range at all. It sits with them because it
     * is the one number on the page that says whether a successful login can be trusted,
     * and burying it further down would be reading the room wrong.
     *
     * @param array $range
     * @return array
     */
    private static function getStats($range)
    {
        $counts = [];

        $rows = flsDb()->table('fls_auth_logs')
            ->select(['status', flsDb()->raw('COUNT(*) as total')])
            ->whereBetween('created_at', $range['from'], $range['to'])
            ->groupBy('status')
            ->get();

        foreach ($rows as $row) {
            $counts[$row->status] = (int)$row->total;
        }

        $twoFa = self::getTwoFaCounts();

        return [
            [
                'key'   => 'success',
                'title' => __('Successful Logins', 'fluent-security'),
                'value' => number_format_i18n(Arr::get($counts, 'success', 0)),
                'route' => 'logs',
                'query' => ['status' => 'success']
            ],
            [
                'key'   => 'failed',
                'title' => __('Failed Attempts', 'fluent-security'),
                'value' => number_format_i18n(Arr::get($counts, 'failed', 0)),
                'route' => 'logs',
                'query' => ['status' => 'failed']
            ],
            [
                'key'   => 'blocked',
                'title' => __('Blocked Attempts', 'fluent-security'),
                'value' => number_format_i18n(Arr::get($counts, 'blocked', 0)),
                'route' => 'logs',
                'query' => ['status' => 'blocked']
            ],
            [
                'key'   => 'two_fa',
                'title' => __('Users with 2FA', 'fluent-security'),
                'value' => number_format_i18n($twoFa['enrolled']),
                /* translators: %s: total number of users on the site */
                'meta'  => sprintf(__('of %s users', 'fluent-security'), number_format_i18n($twoFa['total'])),
                'route' => 'settings_two_fa_enrollment'
            ]
        ];
    }

    /* ------------------------------------------------------------------ chart */

    /**
     * A bar per bucket, split by status.
     *
     * Every bucket in the range is returned, including the empty ones. A chart that only
     * plots the days something happened puts a quiet Tuesday and a busy one side by side
     * at the same width, which is the opposite of what a trend line is for.
     *
     * @param array $range
     * @return array
     */
    private static function getChart($range)
    {
        /*
         * The bucket key is cut out of the left of the timestamp rather than built with
         * DATE_FORMAT. A format string is all per-cent signs, and raw SQL goes through
         * wpdb::prepare on its way to the database, which reads every one of them as a
         * placeholder of its own and quietly returns nothing at all.
         */
        $lengths = [
            'hour'  => 13, // 2026-08-08 17
            'day'   => 10, // 2026-08-08
            'month' => 7   // 2026-08
        ];

        $length = $lengths[$range['bucket']];

        $rows = flsDb()->table('fls_auth_logs')
            ->select([
                flsDb()->raw("SUBSTRING(created_at, 1, {$length}) as bucket"),
                'status',
                flsDb()->raw('COUNT(*) as total')
            ])
            ->whereBetween('created_at', $range['from'], $range['to'])
            ->groupBy(flsDb()->raw("SUBSTRING(created_at, 1, {$length})"))
            ->groupBy('status')
            ->get();

        $totals = [];

        foreach ($rows as $row) {
            $totals[$row->bucket][$row->status] = (int)$row->total;
        }

        $points = [];
        $max = 0;

        foreach (self::buckets($range) as $bucket) {
            $counts = [
                'success' => (int)Arr::get($totals, $bucket['key'] . '.success', 0),
                'failed'  => (int)Arr::get($totals, $bucket['key'] . '.failed', 0),
                'blocked' => (int)Arr::get($totals, $bucket['key'] . '.blocked', 0)
            ];

            $max = max($max, array_sum($counts));

            $points[] = [
                'label'   => $bucket['label'],
                'tooltip' => $bucket['tooltip'],
                'counts'  => $counts
            ];
        }

        return [
            'points' => $points,
            'max'    => $max,
            'series' => [
                ['key' => 'success', 'label' => __('Successful', 'fluent-security')],
                ['key' => 'failed', 'label' => __('Failed', 'fluent-security')],
                ['key' => 'blocked', 'label' => __('Blocked', 'fluent-security')]
            ]
        ];
    }

    /**
     * Every bucket in the range, in order, with the labels to print under and inside it.
     *
     * The keys have to be built the same way MySQL's DATE_FORMAT built them or the counts
     * will not line up, which is why the formats are paired here rather than derived.
     *
     * @param array $range
     * @return array
     */
    private static function buckets($range)
    {
        $steps = [
            'hour'  => ['+1 hour', 'Y-m-d H', 'H:00', 'M j, H:00'],
            'day'   => ['+1 day', 'Y-m-d', 'M j', 'M j, Y'],
            'month' => ['+1 month', 'Y-m', 'M', 'F Y']
        ];

        list($step, $keyFormat, $labelFormat, $tooltipFormat) = $steps[$range['bucket']];

        $cursor = strtotime($range['from']);
        $end = strtotime($range['to']);

        $buckets = [];

        while ($cursor <= $end) {
            $buckets[] = [
                'key'     => date($keyFormat, $cursor),
                'label'   => date_i18n($labelFormat, $cursor),
                'tooltip' => date_i18n($tooltipFormat, $cursor)
            ];

            $cursor = strtotime($step, $cursor);
        }

        return $buckets;
    }

    /* ------------------------------------------------------------------ lists */

    /**
     * @param array $statuses
     * @param array $range
     * @return array
     */
    private static function getRecentLogs($statuses, $range)
    {
        $logs = flsDb()->table('fls_auth_logs')
            ->whereIn('status', $statuses)
            ->whereBetween('created_at', $range['from'], $range['to'])
            ->orderBy('id', 'DESC')
            ->limit(self::LIST_LIMIT)
            ->get();

        $wpTimestamp = current_time('timestamp');

        $formatted = [];

        foreach ($logs as $log) {
            $formatted[] = [
                'id'          => (int)$log->id,
                'username'    => $log->username,
                'status'      => $log->status,
                'ip'          => $log->ip,
                'media'       => $log->media,
                'browser'     => trim($log->device_os . ' / ' . $log->browser, ' /'),
                'created_at'  => $log->created_at,
                'time_ago'    => self::timeAgo($log->created_at, $wpTimestamp)
            ];
        }

        return $formatted;
    }

    /**
     * The addresses trying hardest to get in.
     *
     * Grouped by address rather than listed one attempt per row: a single IP making four
     * hundred attempts is one fact about the site, and as a list of four hundred rows it
     * is a fact you have to scroll to notice.
     *
     * @param array $range
     * @return array
     */
    private static function getTopIps($range)
    {
        $rows = flsDb()->table('fls_auth_logs')
            ->select([
                'ip',
                flsDb()->raw('COUNT(*) as attempts'),
                flsDb()->raw('COUNT(DISTINCT username) as usernames'),
                flsDb()->raw('MAX(created_at) as last_seen')
            ])
            ->whereIn('status', ['failed', 'blocked'])
            ->whereBetween('created_at', $range['from'], $range['to'])
            ->where('ip', '!=', '')
            ->groupBy('ip')
            ->orderBy('attempts', 'DESC')
            ->limit(self::LIST_LIMIT)
            ->get();

        $wpTimestamp = current_time('timestamp');

        $formatted = [];

        foreach ($rows as $row) {
            $formatted[] = [
                'ip'        => $row->ip,
                'attempts'  => (int)$row->attempts,
                'usernames' => (int)$row->usernames,
                'last_seen' => self::timeAgo($row->last_seen, $wpTimestamp),
                // So the card can offer to block an address, or say that it already is.
                'is_blocked' => IpRules::isOnBlockList($row->ip)
            ];
        }

        return $formatted;
    }

    /**
     * How people actually signed in over the range.
     *
     * Worth its own panel because it answers a question the settings cannot: turning on
     * magic links or an authenticator app says what is available, not what anybody uses.
     *
     * @param array $range
     * @return array
     */
    private static function getLoginMethods($range)
    {
        $rows = flsDb()->table('fls_auth_logs')
            ->select(['media', flsDb()->raw('COUNT(*) as total')])
            ->where('status', 'success')
            ->whereBetween('created_at', $range['from'], $range['to'])
            ->groupBy('media')
            ->orderBy('total', 'DESC')
            ->get();

        $total = 0;

        foreach ($rows as $row) {
            $total += (int)$row->total;
        }

        $methods = [];

        foreach ($rows as $row) {
            $media = $row->media ?: 'web';
            $count = (int)$row->total;

            $methods[] = [
                'key'     => $media,
                'label'   => Helper::getLoginMediaLabel($media),
                'count'   => $count,
                'percent' => $total ? round(($count / $total) * 100) : 0
            ];
        }

        return $methods;
    }

    /**
     * The standing facts about the site that are not counts of anything in the range.
     *
     * @return array
     */
    private static function getProtection()
    {
        $settings = Helper::getAuthSettings();
        $scan = IntegrityHelper::getSettings();
        $twoFa = self::getTwoFaCounts();

        return [
            'two_fa'    => $twoFa,
            'two_fa_enabled' => Arr::get($settings, 'totp_2fa') === 'yes',
            'scan'      => [
                'registered'   => in_array(Arr::get($scan, 'status'), ['active', 'self'], true),
                /*
                 * The stored verdict covers core only - see IntegrityHelper::hasExtensionIssues.
                 * Without the second half this tile reports a healthy site while the scans screen
                 * lists changed plugins.
                 */
                'is_ok'        => Arr::get($scan, 'is_ok') !== 'no'
                    && !IntegrityHelper::hasExtensionIssues(),
                'last_checked' => self::timeAgo(Arr::get($scan, 'last_checked'), current_time('timestamp')),
                /*
                 * Whether anything is scheduled, said apart from when the last scan ran.
                 *
                 * A connected site with the schedule switched off reports nothing at all, and
                 * a row that only says "last scan: 3 days ago" cannot tell that apart from a
                 * schedule that is running and simply has not come round yet.
                 *
                 * Both halves of the condition the cron actually guards on, so this cannot
                 * claim a schedule the cron would decline to run - see BasicTasksHandler.
                 */
                'scheduled'    => Arr::get($scan, 'auto_scan') === 'yes'
                    && Arr::get($scan, 'status') === 'active',
                'interval'     => IntegrityHelper::normaliseScanInterval(Arr::get($scan, 'scan_interval')),
                /* Scanning without the alerts service: there is no schedule to have here. */
                'self_managed' => Arr::get($scan, 'status') === 'self',
                /* '', 'disabled' or 'revoked' - see IntegrityHelper::markRelayRejected. */
                'disconnected' => (string)Arr::get($scan, 'relay_rejection', '')
            ],
            'retention' => (int)Arr::get($settings, 'auto_delete_logs_day', 0),
            'digest'    => Arr::get($settings, 'digest_summary', '')
        ];
    }

    /**
     * "5 mins ago", or nothing at all if there is no date to say it about.
     *
     * Every date on this screen is nullable - the log columns are, and a site that has
     * never scanned has no last scan - and passing a null through strtotime() is a
     * deprecation notice on PHP 8 and "55 years ago" on the page.
     *
     * @param string|null $date
     * @param int $wpTimestamp
     * @return string
     */
    private static function timeAgo($date, $wpTimestamp)
    {
        if (!$date) {
            return '';
        }

        /* translators: %s: a human readable time difference, e.g. "5 mins" */
        return sprintf(
            __('%s ago', 'fluent-security'),
            human_time_diff(strtotime($date), $wpTimestamp)
        );
    }

    /**
     * @return array
     */
    private static function getTwoFaCounts()
    {
        return [
            'enrolled' => TwoFaController::countEnrolledUsers(),
            /*
             * The people who could enrol, not everybody with an account - see
             * TwoFaController::countEligibleUsers(). This used to be an unfiltered user
             * count, which on any site with customers or subscribers made the tile read
             * far worse than the truth: nobody in those roles is offered a second factor,
             * so none of them were ever going to appear in the numerator.
             */
            'total'    => TwoFaController::countEligibleUsers()
        ];
    }
}
