<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Registry;

/**
 * The security screen's whole API surface: what is wrong, fix it, accept it.
 *
 * Three endpoints for however many checks the plugin grows, because the screen only ever
 * renders findings and a finding only ever offers those two verbs.
 */
class SecurityFindingsController
{
    /**
     * Everything answerable without making the reader wait.
     *
     * The deep checks - checksums, file hashing - are not run here. They report their stored
     * result through their own screen and their own schedule; a page load that walked
     * wp-content would take a minute and would do it on every visit.
     *
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function getFindings(\WP_REST_Request $request)
    {
        return Registry::summary([Check::COST_INSTANT, Check::COST_PROBE]);
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function fix(\WP_REST_Request $request)
    {
        $result = Registry::fix(
            sanitize_text_field((string)$request->get_param('check')),
            sanitize_text_field((string)$request->get_param('finding'))
        );

        if (is_wp_error($result)) {
            return $result;
        }

        return self::withSummary($result);
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function accept(\WP_REST_Request $request)
    {
        $result = Registry::accept(
            sanitize_text_field((string)$request->get_param('check')),
            sanitize_text_field((string)$request->get_param('finding'))
        );

        if (is_wp_error($result)) {
            return $result;
        }

        return self::withSummary($result);
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function unaccept(\WP_REST_Request $request)
    {
        $result = Registry::unaccept(
            sanitize_text_field((string)$request->get_param('check')),
            sanitize_text_field((string)$request->get_param('finding'))
        );

        if (is_wp_error($result)) {
            return $result;
        }

        return self::withSummary($result);
    }

    /**
     * Send the recalculated list back with every write.
     *
     * Turning one thing on can move another - blocking application passwords changes what
     * the two-factor row has to say about this site - so the screen redraws from the server's
     * answer rather than striking a row out locally and drifting from it.
     *
     * @param array $result
     * @return array
     */
    protected static function withSummary($result)
    {
        Registry::reset();

        return array_merge($result, Registry::summary([Check::COST_INSTANT, Check::COST_PROBE]));
    }
}
