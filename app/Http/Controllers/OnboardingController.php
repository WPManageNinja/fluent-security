<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\Onboarding;

/**
 * The setup wizard's endpoints.
 *
 * Thin on purpose. Everything about what a step means, what an answer is allowed to say
 * and what gets written lives in the Onboarding service, so that the rules hold whether
 * they are reached from here, from WP-CLI or from a test.
 */
class OnboardingController
{
    /**
     * Everything the wizard needs to draw itself.
     *
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function getOnboarding(\WP_REST_Request $request)
    {
        return Onboarding::payload();
    }

    /**
     * Applies every answer in one write and closes the wizard.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function complete(\WP_REST_Request $request)
    {
        $answers = $request->get_param('answers');

        return Onboarding::complete(is_array($answers) ? $answers : []);
    }

    /**
     * Leaves the wizard without writing a setting.
     *
     * @param \WP_REST_Request $request
     * @return array
     */
    public static function skip(\WP_REST_Request $request)
    {
        return Onboarding::skip();
    }
}
