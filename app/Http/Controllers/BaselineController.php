<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Baseline\BaselineScanner;
use FluentAuth\App\Services\Baseline\BaselineStore;

/**
 * The snapshot: what it covers, taking it, comparing against it, and throwing it away.
 *
 * Comparing is budgeted and returns what is left, because hashing wp-content takes longer
 * than one request may live. The browser calls it until nothing remains - the same way it
 * walks the plugins and themes during a scan, and for the same reason.
 */
class BaselineController
{
    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function getBaseline(\WP_REST_Request $request)
    {
        return self::payload();
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function takeSnapshot(\WP_REST_Request $request)
    {
        $scopes = self::scopes($request);

        $result = BaselineScanner::snapshot($scopes);

        if (!empty($result['failed'])) {
            return new \WP_Error(
                'snapshot_failed',
                __('The snapshot could not be stored. Your database user may not be allowed to create tables.', 'fluent-security'),
                ['status' => 500]
            );
        }

        if (empty($result['taken'])) {
            /*
             * Two different nothings. Asking for one plugin and getting none back means the
             * name did not match anything snapshottable - not that the site has nothing to
             * snapshot, which is what the general message would tell somebody who had just
             * pressed a button on a row they were looking at.
             */
            if ($scopes) {
                return new \WP_Error(
                    'nothing_to_snapshot',
                    __('That plugin or theme is no longer installed, so there was nothing to record.', 'fluent-security'),
                    ['status' => 404]
                );
            }

            return new \WP_Error(
                'nothing_to_snapshot',
                __('Every plugin and theme on this site can be checked against WordPress.org, so there is nothing a snapshot would add.', 'fluent-security'),
                ['status' => 422]
            );
        }

        return self::payload([
            'message' => sprintf(
                /* translators: %s: number of plugins and themes */
                _n(
                    'Snapshot taken of %s plugin or theme.',
                    'Snapshot taken of %s plugins and themes.',
                    $result['taken'],
                    'fluent-security'
                ),
                number_format_i18n($result['taken'])
            )
        ]);
    }

    /**
     * One pass of the comparison, as much as the budget allows.
     *
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function compare(\WP_REST_Request $request)
    {
        /*
         * Clamped rather than trusted. This is the one parameter that decides how long a
         * request runs, and the ceiling is well under anybody's max_execution_time so a
         * caller cannot ask for a pass that dies half way and reports nothing.
         */
        $budget = (int)$request->get_param('budget');
        $budget = $budget ? min(60, max(5, $budget)) : null;

        $result = BaselineScanner::compare($budget);

        return self::payload(['result' => $result]);
    }

    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function clear(\WP_REST_Request $request)
    {
        BaselineStore::clear();

        return self::payload([
            'message' => __('The snapshot has been cleared.', 'fluent-security')
        ]);
    }

    /**
     * The whole state of the snapshot, returned by everything here.
     *
     * Every action changes what the screens should show, and handing back the new state
     * rather than an acknowledgement means no screen has to guess at it or fetch it again.
     *
     * @param array $extra
     * @return array
     */
    protected static function payload($extra = [])
    {
        return array_merge($extra, [
            'baseline' => BaselineScanner::summary(),
            'units'    => BaselineScanner::units()
        ]);
    }

    /**
     * Which units the caller is asking about, if any.
     *
     * @param \WP_REST_Request $request
     * @return array
     */
    protected static function scopes(\WP_REST_Request $request)
    {
        $scopes = $request->get_param('scopes');

        if (!$scopes) {
            return [];
        }

        $scopes = is_array($scopes) ? $scopes : [$scopes];

        return array_values(array_filter(array_map('sanitize_text_field', $scopes)));
    }
}
