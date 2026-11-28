<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\LinkedInAuthService;

/**
 * Social login signs in whichever WordPress account holds the email the provider hands
 * back, so LinkedIn's userinfo must vouch for that address before we use it.
 */
class LinkedInAuthTest extends BaseTestCase
{
    private $stub;

    public function tearDown(): void
    {
        if ($this->stub) {
            remove_filter('pre_http_request', $this->stub, 10);
            $this->stub = null;
        }
        parent::tearDown();
    }

    private function userInfoSaying($claims)
    {
        $this->stub = function () use ($claims) {
            return [
                'headers'  => [],
                'body'     => wp_json_encode($claims),
                'response' => ['code' => 200, 'message' => 'OK'],
                'cookies'  => []
            ];
        };
        add_filter('pre_http_request', $this->stub, 10, 1);

        return LinkedInAuthService::getDataByAccessToken('token');
    }

    public function unverifiedClaims()
    {
        return [
            'false'   => [['email_verified' => false]],
            '"false"' => [['email_verified' => 'false']],
            'missing' => [[]],
        ];
    }

    /**
     * @dataProvider unverifiedClaims
     */
    public function testAnUnverifiedLinkedInEmailIsRejected($claims)
    {
        $result = $this->userInfoSaying(array_merge(['email' => 'victim@example.test', 'name' => 'V'], $claims));

        $this->assertWPError($result);
        $this->assertSame('email_unverified', $result->get_error_code());
    }

    public function testAVerifiedLinkedInEmailIsAccepted()
    {
        foreach ([true, 'true'] as $verified) {
            $result = $this->userInfoSaying([
                'email'          => 'jane@example.test',
                'email_verified' => $verified,
                'given_name'     => 'Jane',
                'family_name'    => 'Doe',
            ]);
            remove_filter('pre_http_request', $this->stub, 10);

            $this->assertIsArray($result);
            $this->assertSame('jane@example.test', $result['email']);
            $this->assertSame('Jane Doe', $result['full_name']);
            $this->assertSame('jane', $result['username']);
        }
    }
}
