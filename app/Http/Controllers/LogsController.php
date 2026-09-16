<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Helper;

class LogsController
{
    public static function getLogs(\WP_REST_Request $request)
    {
        $orderByColumn = sanitize_sql_orderby($request->get_param('sortBy')) ?: 'id';
        $orderBy = sanitize_sql_orderby($request->get_param('sortType')) ?: 'DESC';

        $query = flsDb()->table('fls_auth_logs')->orderBy($orderByColumn, $orderBy);

        $statuses = self::readFilter($request->get_param('statuses'));

        if ($statuses) {
            $query->whereIn('status', $statuses);
        }

        /*
         * Narrowing within a view: site activity holds plugins going on and off, files
         * being quarantined and reset requests, and past a handful of rows the only way to
         * follow one of those is to stop showing the others.
         */
        $events = self::readFilter($request->get_param('events'));

        if ($events) {
            $query->whereIn('media', $events);
        }

        /*
         * The address is searched as well as the name. Following one attacker across a log
         * is the most common reason to search it at all, and until now the only way to do
         * that was to read every page looking for the same number.
         */
        if ($search = $request->get_param('search')) {
            $search = sanitize_text_field($search);
            $query->where(function ($q) use ($search) {
                $q->where('username', 'LIKE', '%' . $search . '%');
                $q->orWhere('ip', 'LIKE', '%' . $search . '%');
                $q->orWhere('media', 'LIKE', '%' . $search . '%');
                return $q;
            });
        }

        $logs = $query->paginate();

        $wpTimestamp = current_time('timestamp');
        $dateFormat = get_option('date_format') . ' ' . get_option('time_format');

        foreach ($logs['data'] as $log) {
            $timestamp = strtotime($log->created_at);

            /* translators: %s: a human readable time difference, e.g. "5 mins" */
            $log->human_time_diff = sprintf(
                __('%s ago', 'fluent-security'),
                human_time_diff($timestamp, $wpTimestamp)
            );

            // The exact moment, in the format and language the site is set to.
            $log->created_at_human = date_i18n($dateFormat, $timestamp);

            $log->media_label = Helper::getLoginMediaLabel($log->media);

            /*
             * The screen renders this as HTML, because WordPress's own login errors are
             * written with <strong> around the name and a "Lost your password?" link, and
             * showing the tags to the reader would be worse than showing the markup.
             *
             * So it is cut down to exactly that here rather than trusted. A description is
             * whatever the WP_Error that reached `wp_login_failed` carried, and only core's
             * own messages are known to have escaped the username they quote - any other
             * plugin on the site can put a WP_Error into that hook, and the row is written
             * before anybody has looked at it. Filtered on the way out rather than on the
             * way in, so rows already in the table are covered too.
             */
            $log->description = wp_kses($log->description, [
                'strong' => [],
                'b'      => [],
                'em'     => [],
                'i'      => [],
                'code'   => [],
                'br'     => [],
                'a'      => ['href' => [], 'title' => []]
            ]);
        }

        return [
            'logs' => $logs,
            /*
             * Built from the rows that are there rather than from a list kept by hand, so
             * it cannot offer an event the log has none of, cannot go stale when something
             * new starts being recorded, and still names events written under older slugs.
             *
             * Deliberately blind to $events, or choosing one would collapse the list it
             * was chosen from down to that one.
             */
            'events' => self::getEventOptions($request->get_param('view'), $statuses),
            /*
             * How long these rows last. The screen says so because the log deletes itself
             * on a schedule, and a gap where last month used to be otherwise reads as
             * something having gone wrong rather than as the setting doing its job.
             *
             * Sent with the rows rather than read from the settings the admin screen was
             * booted with, so changing the number and coming back shows the new one.
             */
            'retention' => (int)Helper::getSetting('auto_delete_logs_day')
        ];
    }

    /**
     * A list filter from the request: sanitised, emptied of blanks, and read as "no filter"
     * when it is absent or says "all".
     *
     * @param mixed $value
     * @return array<int, string>
     */
    private static function readFilter($value)
    {
        if (!$value) {
            return [];
        }

        $value = array_filter(map_deep((array)$value, 'sanitize_text_field'));

        if (!$value || in_array('all', $value)) {
            return [];
        }

        return array_values($value);
    }

    /**
     * The kinds of event present in the rows the current view covers.
     *
     * Only the views that ask for it, which is site activity and nothing else: it is the
     * one view holding several kinds of event. Asking the view first also keeps the extra
     * query off every other one.
     *
     * @param mixed              $view
     * @param array<int, string> $statuses
     * @return array<int, array<string, string>>
     */
    private static function getEventOptions($view, $statuses)
    {
        $views = Helper::getLogViews();
        $view = is_string($view) ? $view : '';

        if (!$view || empty($views[$view]['events'])) {
            return [];
        }

        $query = flsDb()->table('fls_auth_logs')->selectDistinct('media');

        if ($statuses) {
            $query->whereIn('status', $statuses);
        }

        $options = [];

        foreach ($query->get() as $row) {
            /* Rows written without one cannot be filtered for, so they are not offered. */
            if (empty($row->media)) {
                continue;
            }

            $options[] = [
                'value' => $row->media,
                'label' => Helper::getLoginMediaLabel($row->media)
            ];
        }

        usort($options, function ($a, $b) {
            return strcasecmp($a['label'], $b['label']);
        });

        return $options;
    }

    public static function deleteLog(\WP_REST_Request $request)
    {
        $id = (int) $request->get_param('id');
        flsDb()->table('fls_auth_logs')->where('id', $id)->delete();

        return [
            'message' => __('Log has been deleted', 'fluent-security')
        ];
    }

    public static function deleteAllLog(\WP_REST_Request $request)
    {
        global $wpdb;

        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}fls_auth_logs");

        return [
            'message' => __('All Logs has been deleted', 'fluent-security')
        ];

    }
}
