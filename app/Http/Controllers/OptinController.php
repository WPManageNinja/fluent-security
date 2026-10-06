<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Optin;

/**
 * The mailing list signup's two endpoints: yes, and not now.
 *
 * Thin on purpose, like OnboardingController - what an answer means, what it sends and how
 * long a "not now" holds all live in the Optin service, so the rules are the same whether
 * they are reached from the wizard's last screen, from the dashboard card, or from a test.
 */
class OptinController
{
    /**
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function subscribe(\WP_REST_Request $request)
    {
        return Optin::subscribe(
            (string)$request->get_param('email'),
            (string)$request->get_param('full_name'),
            $request->get_param('share_essentials') === 'yes'
        );
    }

    /**
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function dismiss(\WP_REST_Request $request)
    {
        return Optin::dismiss();
    }
}
