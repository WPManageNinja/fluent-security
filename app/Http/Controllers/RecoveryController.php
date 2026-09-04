<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Registry;
use FluentAuth\App\Services\Recovery\RecoveryService;

/**
 * The recovery screen.
 *
 * Everything here needs the same capability as the rest of the plugin's admin API, and every
 * write it performs is confirmed in the interface before it is called - but the checks that
 * matter are in RecoveryService, which re-establishes them for itself rather than trusting
 * that the screen only offered buttons it should have.
 */
class RecoveryController
{
    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function getRecovery(\WP_REST_Request $request)
    {
        $summary = Registry::summary([Check::COST_INSTANT, Check::COST_PROBE]);

        return [
            'administrators' => RecoveryService::administrators(),
            'progress'       => RecoveryService::progress(),
            'history'        => RecoveryService::history(),
            /*
             * What the findings list is holding, so the screen can lead with the reason
             * somebody is on it - and so the last step can stay shut until it is empty.
             */
            'outstanding'    => [
                'to_fix' => $summary['counts']['to_fix'],
                /*
                 * Fix and look, not everything open: best-practice advice is listed on the
                 * findings tab but is not something a site being recovered has to clear, and
                 * counting it here would keep a badge on the tab that nothing can put out.
                 */
                'open'   => $summary['counts']['attention']
            ]
        ];
    }

    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function secureNow(\WP_REST_Request $request)
    {
        return RecoveryService::secureNow();
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function passwordResets(\WP_REST_Request $request)
    {
        return RecoveryService::queuePasswordResets(
            sanitize_text_field((string)$request->get_param('scope'))
        );
    }
}
