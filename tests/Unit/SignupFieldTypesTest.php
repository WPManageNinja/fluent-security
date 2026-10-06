<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;

/**
 * Fields another plugin adds to the signup form through
 * `fluent_auth/registration_form_fields`.
 *
 * Fluent Support moves its address fields here when it hands its portal to FluentAuth,
 * and one of them is a country select. Before select was rendered, a field of that type
 * was dropped from the form without a word.
 */
class SignupFieldTypesTest extends BaseTestCase
{
    private $fieldsFilter;

    public function setUp(): void
    {
        parent::setUp();
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes']);
        update_option('users_can_register', 1);

        $this->fieldsFilter = function ($fields) {
            $fields['country'] = [
                'required'    => true,
                'type'        => 'select',
                'label'       => 'Country',
                'id'          => 'fls_country',
                'placeholder' => 'Select a Country',
                'options'     => ['BD' => 'Bangladesh', 'US' => 'United States', 'XX' => '<b>Bold</b>']
            ];

            return $fields;
        };

        add_filter('fluent_auth/registration_form_fields', $this->fieldsFilter);
    }

    public function tearDown(): void
    {
        remove_filter('fluent_auth/registration_form_fields', $this->fieldsFilter);
        parent::tearDown();
    }

    public function test_select_is_a_declared_field_type()
    {
        $this->assertContains('select', CustomAuthHandler::SIGNUP_FIELD_TYPES);
    }

    public function test_a_select_field_renders_with_its_options()
    {
        $html = (new CustomAuthHandler())->registrationForm([]);

        $this->assertStringContainsString('<select id="fls_country" name="country" required>', $html);
        $this->assertStringContainsString('<option value="" disabled selected>Select a Country</option>', $html);
        $this->assertStringContainsString('<option value="BD">Bangladesh</option>', $html);
        $this->assertStringContainsString('fls_field_group fls_field_country', $html);
    }

    public function test_option_labels_are_escaped()
    {
        $html = (new CustomAuthHandler())->registrationForm([]);

        $this->assertStringContainsString('&lt;b&gt;Bold&lt;/b&gt;', $html);
        $this->assertStringNotContainsString('<b>Bold</b>', $html);
    }

    public function test_an_unknown_field_type_is_still_left_out()
    {
        add_filter('fluent_auth/registration_form_fields', $filter = function ($fields) {
            $fields['bio'] = ['type' => 'textarea', 'label' => 'Bio', 'id' => 'fls_bio'];
            return $fields;
        });

        $html = (new CustomAuthHandler())->registrationForm([]);
        remove_filter('fluent_auth/registration_form_fields', $filter);

        $this->assertStringNotContainsString('fls_field_bio', $html);
    }

    public function test_a_required_select_must_be_chosen()
    {
        $errors = (new CustomAuthHandler())->validateSignUpData($this->validData(['country' => '']));

        $this->assertArrayHasKey('country', $errors);
    }

    public function test_a_select_accepts_only_its_own_options()
    {
        $handler = new CustomAuthHandler();

        $this->assertArrayNotHasKey('country', $handler->validateSignUpData($this->validData(['country' => 'BD'])));
        $this->assertArrayHasKey('country', $handler->validateSignUpData($this->validData(['country' => 'ZZ'])));
        $this->assertArrayHasKey('country', $handler->validateSignUpData($this->validData(['country' => ['BD']])));
    }

    public function test_an_optional_select_may_be_left_empty()
    {
        add_filter('fluent_auth/registration_form_fields', $filter = function ($fields) {
            $fields['country']['required'] = false;
            return $fields;
        }, 20);

        $errors = (new CustomAuthHandler())->validateSignUpData($this->validData(['country' => '']));
        remove_filter('fluent_auth/registration_form_fields', $filter, 20);

        $this->assertArrayNotHasKey('country', $errors);
    }

    private function validData($overrides = [])
    {
        return array_merge([
            'first_name' => 'Jane',
            'username'   => 'jane',
            'email'      => 'jane@example.org',
            'password'   => 'a-long-password'
        ], $overrides);
    }
}
