<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Registry;
use FluentAuth\App\Services\Recovery\FileRecovery;
use FluentAuth\App\Services\Recovery\RecoveryService;
use FluentAuth\App\Services\Recovery\SaltRotation;

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
            /*
             * What the first step would actually cost, so the warning on it can name a number
             * instead of a category. See RecoveryService::impact().
             */
            'impact'         => RecoveryService::impact(),
            /*
             * Whether the opt-in key rotation can be offered on this install, or why not.
             * Answered here rather than when it is confirmed, so the checkbox is never shown
             * on a site where it was always going to refuse. See SaltRotation::state().
             */
            'salts'          => SaltRotation::state(),
            'history'        => RecoveryService::history(),
            /* What the last scan found, and what can be put back from here. */
            'files'          => FileRecovery::summary(),
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
        /*
         * Opt-in and read strictly. Anything other than the exact string is no - the default
         * for a parameter that rewrites wp-config.php should not be reachable by a typo, a
         * stray "0", or a client that sends the key with nothing in it.
         */
        $rotateSalts = 'yes' === (string)$request->get_param('rotate_salts');

        return RecoveryService::secureNow($rotateSalts);
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

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function reinstallCore(\WP_REST_Request $request)
    {
        return FileRecovery::reinstallCore();
    }

    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function reinstallExtension(\WP_REST_Request $request)
    {
        return FileRecovery::reinstallExtension(
            sanitize_text_field((string)$request->get_param('type')),
            /*
             * Not sanitize_text_field(): a plugin key is "folder/file.php" and the theme key
             * is a folder name, and both are only ever matched against the inventory - a
             * key that names nothing installed is answered with a 404, not acted on.
             */
            (string)$request->get_param('key')
        );
    }
}
