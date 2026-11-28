<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\SocialAuthHandler;

/**
 * A member who cancels at the provider comes back with error= and no code. Sending them
 * to the provider again put them on the consent screen they had just left, with no way
 * back to the site; they belong on the login page.
 */
class SocialAuthCancelTest extends BaseTestCase
{
    public function providers()
    {
        return [
            'github'   => ['handleGitHubActions', ['error' => 'access_denied', 'state' => 'x']],
            'google'   => ['handleGoogleActions', ['error' => 'access_denied', 'state' => 'x']],
            'facebook' => ['handleFacebookActions', ['error' => 'access_denied', 'error_reason' => 'user_denied', 'state' => 'x']],
            'linkedin' => ['handleLinkedInActions', ['error' => 'user_cancelled_authorize', 'state' => 'x']],
        ];
    }

    /**
     * @dataProvider providers
     */
    public function testACancelledConsentIsNotSentBackToTheProvider($method, $reply)
    {
        $redirected = null;
        $trap = function ($location) use (&$redirected) {
            $redirected = $location;
            throw new \RuntimeException('redirected');
        };
        add_filter('wp_redirect', $trap);

        try {
            $handler = new \ReflectionMethod(SocialAuthHandler::class, $method);
            $handler->setAccessible(true);
            $handler->invoke(new SocialAuthHandler(), array_merge(['fs_auth' => 'x'], $reply));
        } catch (\RuntimeException $e) {
            // Reported below.
        } finally {
            remove_filter('wp_redirect', $trap);
        }

        $this->assertNull($redirected, 'A cancelled sign-in was redirected to ' . $redirected);
    }
}
