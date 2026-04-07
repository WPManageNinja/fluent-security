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

        if ($statuses = $request->get_param('statuses')) {
            $statuses = array_filter(map_deep($statuses, 'sanitize_text_field'));
            if ($statuses && !in_array('all', $statuses)) {
                $query->whereIn('status', $statuses);
            }
        }

        if ($search = $request->get_param('search')) {
            $search = sanitize_text_field($search);
            $query->where(function ($q) use ($search) {
                $q->where('username', 'LIKE', '%' . $search . '%');
                $q->orWhere('media', 'LIKE', '%' . $search . '%');
                return $q;
            });
        }

        $logs = $query->paginate();

        $wpTimestamp = current_time('timestamp');
        foreach ($logs['data'] as $log) {
            $log->human_time_diff = human_time_diff(strtotime($log->created_at), $wpTimestamp) . ' ago';
        }

        return [
            'logs' => $logs
        ];
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

    public static function quickStats(\WP_REST_Request $request)
    {
        $fromRange = sanitize_text_field($request->get_param('day_range'));

        if (!$fromRange) {
            $fromRange = '-0 days';
        }

        $wpTimestamp = current_time('timestamp');

        if ($fromRange == 'this_month') {
            $fromDate = date('Y-m-01 00:00:00', $wpTimestamp);
        } else if ($fromRange == 'all_time') {
            $fromDate = '1970-01-01 00:00:00';
        } else {
            $fromDate = date('Y-m-d 00:00:00', strtotime($fromRange, $wpTimestamp));
        }

        $toDate = date('Y-m-d 23:59:59', $wpTimestamp);

        $counts = flsDb()->table('fls_auth_logs')
            ->select(['status', flsDb()->raw('count(*) as total')])
            ->whereBetween('created_at', $fromDate, $toDate)
            ->groupBy('status')
            ->get();

        $items = [
            'failed'  => [
                'count' => 0,
                'title' => __('Failed Logins', 'fluent-security')
            ],
            'blocked' => [
                'count' => 0,
                'title' => __('Blocked Logins', 'fluent-security')
            ],
            'success' => [
                'count' => 0,
                'title' => __('Successful Logins', 'fluent-security')
            ]
        ];

        foreach ($counts as $countItem) {
            if (isset($items[$countItem->status])) {
                $items[$countItem->status]['count'] = $countItem->total;
            }
        }

        if (Helper::getSetting('magic_login') === 'yes') {
            $items['magic_login'] = [
                'title' => __('Login via URL', 'fluent-security'),
                'count' => flsDb()->table('fls_login_hashes')
                    ->where('status', 'used')
                    ->where('use_type', 'magic_login')
                    ->whereBetween('created_at', $fromDate, $toDate)
                    ->count()
            ];
        }

        return [
            'stats' => $items
        ];
    }
}
