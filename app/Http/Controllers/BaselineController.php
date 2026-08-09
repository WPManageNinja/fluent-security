<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Baseline\BaselineScanner;
use FluentAuth\App\Services\Baseline\BaselineStore;

/**
 * The snapshot: what it covers, taking it, and throwing it away.
 *
 * Comparing against it is not here. That happens on the scan and on the schedule, and its
 * result reaches the screen through BaselineCheck like every other finding.
 */
class BaselineController
{
    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function getBaseline(\WP_REST_Request $request)
    {
        return ['baseline' => BaselineScanner::summary()];
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function takeSnapshot(\WP_REST_Request $request)
    {
        $result = BaselineScanner::snapshot();

        if (!empty($result['failed'])) {
            return new \WP_Error(
                'snapshot_failed',
                __('The snapshot could not be stored. Your database user may not be allowed to create tables.', 'fluent-security'),
                ['status' => 500]
            );
        }

        if (empty($result['taken'])) {
            return new \WP_Error(
                'nothing_to_snapshot',
                __('Every plugin and theme on this site can be checked against WordPress.org, so there is nothing a snapshot would add.', 'fluent-security'),
                ['status' => 422]
            );
        }

        return [
            'baseline' => BaselineScanner::summary(),
            'message'  => sprintf(
                /* translators: %s: number of plugins and themes */
                _n(
                    'Snapshot taken of %s plugin or theme.',
                    'Snapshot taken of %s plugins and themes.',
                    $result['taken'],
                    'fluent-security'
                ),
                number_format_i18n($result['taken'])
            )
        ];
    }

    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function compare(\WP_REST_Request $request)
    {
        $result = BaselineScanner::compare();

        return [
            'result'   => $result,
            'baseline' => BaselineScanner::summary()
        ];
    }

    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function clear(\WP_REST_Request $request)
    {
        BaselineStore::clear();

        return [
            'baseline' => BaselineScanner::summary(),
            'message'  => __('The snapshot has been cleared.', 'fluent-security')
        ];
    }
}
