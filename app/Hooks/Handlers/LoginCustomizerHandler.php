<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\AuthService;

class LoginCustomizerHandler
{

    public function register()
    {
        add_action('login_init', [$this, 'maybeCustomizeAuthPage']);
    }

    public function maybeCustomizeAuthPage()
    {
        add_filter('registration_errors', [$this, 'maybeInterceptRegistration'], 10, 3);
        add_action('register_post', [$this, 'maybeIntercept2FaRegistration'], 10, 3);

        $settings = $this->getSettings();
        if ($settings['enabled'] !== 'yes') {
            return;
        }
        $currentAction = $this->getCurrentAction();
        if (!$currentAction) {
            return;
        }

        $formType = $this->getFormType($currentAction);

        if (!$formType) {
            return;
        }

        $this->loadCustomizedDesign($currentAction, $formType);
    }

    private function loadCustomizedDesign($currentAction, $formType)
    {

        $allSettings = $this->getSettings();

        $formSettings = Arr::get($allSettings, $formType, []);

        $isSecureSignUp = $formType == 'register' && $formSettings['extend_signup_form'] == 'yes';

        add_action('login_enqueue_scripts', function () use ($formType, $allSettings, $isSecureSignUp) {
            wp_enqueue_style(
                'fls-login-customizer',
                FLUENT_AUTH_PLUGIN_URL . 'dist/public/login_customizer.css',
                [],
                FLUENT_AUTH_VERSION
            );

            $designs = Arr::get($allSettings, $formType . '.design', []);
            $css = '';
            foreach ($designs as $designKey => $designValue) {
                if ($designValue) {
                    $css .= '--fls-' . $designKey . ': ' . $designValue . ';';
                }
            }
            $cssVars = '.fls_login_page_wrap { ' . $css . '  }';

            if ($isSecureSignUp) {
                $cssVars .= '#reg_passmail { display: none !important; }';
            }

            wp_add_inline_style('fls-login-customizer', $cssVars);
        });

        add_action('login_header', function () use ($formSettings, $formType) {

            $extraCssClass = apply_filters('fluent_auth/extra_ogin_page_wrap_css_class', '');

            ?>
            <div class="fls_login_page_wrap fls_form_type_<?php echo esc_attr($formType); ?> <?php echo esc_attr($extraCssClass); ?>">
            <div class="fls_login_form_wrap"><div class="fls_form_wrap">
            <div class="fls_login_header">
                <h1><?php echo wp_kses_post(Arr::get($formSettings, 'title')); ?></h1>
                <p><?php echo wp_kses_post(Arr::get($formSettings, 'description')); ?></p>
            </div>
            <?php
        });

        add_action('login_footer', function () use ($formSettings) {
            ?>
            </div></div> <!-- End of fls_form_wrap and fls_login_form_wrap-->

            <div class="fls_login_cusom_content_wrap">
                <div class="fls_login_cusom_content">
                    <div class="fls_login_cusom_content_inner">
                        <h1><?php echo wp_kses_post(Arr::get($formSettings, 'side_content.title', '')); ?></h1>
                        <p><?php echo wp_kses_post(Arr::get($formSettings, 'side_content.description', '')); ?></p>
                    </div>
                </div>
            </div>
            </div> <!-- End of fls_login_page_wrap-->
            <?php
        });


        if ($isSecureSignUp) {
            add_action('register_form', function () {
                // We will add the custom fields here
                $fullName = Arr::get($_POST, 'user_full_name', '');
                $password = Arr::get($_POST, 'user_password', '');
                $confirmPassword = Arr::get($_POST, 'user_confirm_password', '');

                ?>
                <p>
                    <label for="user_full_name"><?php _e('Your Full Name', 'fluent-security'); ?></label>
                    <input type="text" name="user_full_name" id="user_full_name" class="input"
                           value="<?php echo esc_attr($fullName); ?>" size="100" autocomplete="name"
                           required="required"/>
                </p>

                <p>
                    <label for="user_password"><?php _e('Password', 'fluent-security'); ?></label>
                    <input type="password" name="user_password" id="user_password" class="input"
                           value="<?php echo htmlspecialchars($password, ENT_QUOTES, 'UTF-8'); ?>" size="50"
                           required="required"/>
                </p>

                <p>
                    <label for="user_confirm_password"><?php _e('Re-Enter Password', 'fluent-security'); ?></label>
                    <input type="password" name="user_confirm_password"
                           value="<?php echo htmlspecialchars($confirmPassword, ENT_QUOTES, 'UTF-8'); ?>"
                           id="user_confirm_password" class="input" size="50" required="required"/>
                </p>

                <p>
                    <label for="agree_terms">
                        <input type="checkbox" name="agree_terms" id="agree_terms" value="agreed" size="50"
                               required="required"/>
                        <?php _e('I agree to the terms and conditions', 'fluent-security'); ?>
                    </label>
                </p>
                <?php
            });
        }

    }


    public function maybeInterceptRegistration(\WP_Error $errors, $sanitized_user_login, $user_email)
    {
        if ($errors->has_errors()) {
            return $errors;
        }

        if ($this->validateRegistrationData($errors, $_POST)->has_errors()) {
            return $errors;
        }

        $errors->add('confirm_token', sprintf(__('A verification code has been sent to %s. Please provide the code below:', 'fluent-security'), $user_email));

        add_filter('fluent_auth/extra_ogin_page_wrap_css_class', function ($cssClass) {
            return 'fls_register_form_token';
        });

        $fullName = Arr::get($_POST, 'user_full_name', '');

        $nameArr = explode(' ', $fullName);
        $firstName = array_shift($nameArr);
        $lastName = implode(' ', $nameArr);

        $formData = [
            'email'      => $user_email,
            'first_name' => $firstName,
            'last_name'  => $lastName,
        ];

        add_action('register_form', function () use ($formData) {
            echo (new CustomAuthHandler())->sendSignupEmailVerificationHtml($formData);
        });

        return $errors;
    }

    public function maybeIntercept2FaRegistration($sanitized_user_login, $user_email, \WP_Error $errors)
    {
        if ($errors->has_errors()) {
            return false; // it's an aleady error
        }

        $verficationHash = Arr::get($_POST, '_email_verification_hash', '');
        if (!$verficationHash) {
            return false;
        }

        $token = Arr::get($_POST, '_email_verification_token', '');

        $isTokenValidated = AuthService::verifyTokenHash($verficationHash, $token);
        if (is_wp_error($isTokenValidated)) {
            $errors->add('confirm_token', $isTokenValidated->get_error_message());
            return false;
        }

        $validationErrors = $this->validateRegistrationData($_POST);
        if ($validationErrors->has_errors()) {
            foreach ($validationErrors->get_error_codes() as $code) {
                foreach ($validationErrors->get_error_messages($code) as $error_message) {
                    $errors->add($code, $error_message);
                }
            }

            return false;
        }

        $fullName = Arr::get($_POST, 'user_full_name', '');
        $fullNameArr = explode(' ', $fullName);
        $firstName = array_shift($fullNameArr);
        $lastName = implode(' ', $fullNameArr);

        $formData = [
            'username'   => $sanitized_user_login,
            'email'      => $user_email,
            'password'   => Arr::get($_POST, 'user_password'),
            'first_name' => $firstName,
            'last_name'  => $lastName,
        ];

        $formData = apply_filters('fluent_auth/signup_form_data', $formData);

        $userRole = apply_filters('fluent_auth/signup_default_role', get_option('default_role'), $formData);

        $userId = AuthService::registerNewUser($sanitized_user_login, $user_email, $formData['password'], [
            'role'        => $userRole,
            'first_name'  => Arr::get($formData, 'first_name'),
            'last_name'   => Arr::get($formData, 'last_name'),
            '__validated' => true
        ]);

        if (is_wp_error($userId)) {
            $errors->add('registration_error', $userId->get_error_message());
            return false;
        }

        $user = get_user_by('ID', $userId);
        $isAutoLogin = apply_filters('fluent_auth/auto_login_after_signup', true, $user);
        if ($isAutoLogin) {
            AuthService::makeLogin($userId);
        }

        if (!get_current_user_id()) {
            $redirect_to = !empty($_POST['redirect_to']) ? $_POST['redirect_to'] : 'wp-login.php?checkemail=registered';
            wp_safe_redirect($redirect_to);
            exit;
        }

        $redirect_to = !empty($_POST['redirect_to']) ? $_POST['redirect_to'] : null;

        if (!$redirect_to) {
            $redirectUrl = admin_url();
            if (isset($_POST['redirect_to']) && filter_var($_POST['redirect_to'], FILTER_VALIDATE_URL)) {
                $redirectUrl = sanitize_url($_POST['redirect_to']);
            } else {
                $redirectUrl = apply_filters('login_redirect', $redirectUrl, false, $user);
            }
        }

        wp_redirect($redirectUrl);
        exit();
    }

    private function validateRegistrationData($data)
    {
        $errors = new \WP_Error();

        if (empty($data['user_full_name'])) {
            $errors->add('user_full_name', __('Please enter your full name.', 'fluent-security'));
        }


        $fullName = Arr::get($data, 'user_full_name', '');

        // check if the name is valid
        // Consider if there has any special characters like +, -, *, /, etc
        // only check the +,-,*,$,/,=,%,!,@,#,^,&,*,(,),_,{,},[,],:,;,',",<,>,?,|,`,~,,
        if (preg_match('/[\'^£$%&*()}{@#~?><>,|=_+¬-]/u', $fullName)) {
            $errors->add('user_full_name', __('Please provide a full name.', 'fluent-security'));
        }

        // check if there has any http or https
        if (preg_match('/http|https/', $fullName)) {
            $errors->add('user_full_name', __('Please provide a valid name.', 'fluent-security'));
        }

        if (empty($data['user_password'])) {
            $errors->add('user_password', __('Please enter your password.', 'fluent-security'));
        }

        if ($data['user_password'] !== $data['user_confirm_password']) {
            $errors->add('user_confirm_password', __('Password and Confirm password need to be matched', 'fluent-security'));
        }

        if (empty($data['agree_terms'])) {
            $errors->add('agree_terms', __('Please agree to the terms and conditions.', 'fluent-security'));
        }

        return $errors;
    }

    private function getSettings()
    {
        $defaults = [
            'enabled'                => 'yes',
            'login'                  => [
                'title'        => 'Welcome Back to {{site.name}}',
                'description'  => 'Please enter your details to login',
                'design'       => [
                    'background'         => '#ffffff',
                    'color'              => '#19283a',
                    'btn_primary_bg'     => '#2B2E33',
                    'btn_primary_color'  => '#ffffff',
                    'form_bg'            => '',
                    'side_bg_image_url'  => '',
                    'side_background'    => '#f5f7fa',
                    'side_heading_color' => '#19283a',
                    'side_content_color' => '#19283a'
                ],
                'side_content' => [
                    'title'       => 'Welcome to {{site.name}}',
                    'description' => ''
                ]
            ],
            'register'               => [
                'title'              => 'Sign up to {{site.name}}',
                'description'        => 'Please enter your details to register',
                'extend_signup_form' => 'yes',
                'design'             => [
                    'background'         => '#ffffff',
                    'color'              => '#19283a',
                    'btn_primary_bg'     => '#2B2E33',
                    'btn_primary_color'  => '#ffffff',
                    'form_bg'            => '',
                    'side_bg_image_url'  => '',
                    'side_background'    => '#f5f7fa',
                    'side_heading_color' => '#19283a',
                    'side_content_color' => '#19283a'
                ],
                'side_content'       => [
                    'title'       => 'Welcome to {{site.name}}',
                    'description' => ''
                ]
            ],
            'reset_password'         => [
                'title'       => 'Reset Your Password',
                'description' => ''
            ],
            'reset_password_confirm' => [
                'title'       => 'Set Your New Password',
                'description' => ''
            ]
        ];

        return $defaults;
    }

    private function getCurrentAction()
    {
        $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';

        if (isset($_GET['key'])) {
            $action = 'resetpass';
        }

        if (isset($_GET['checkemail'])) {
            $action = 'checkemail';
        }

        $default_actions = array(
            'confirm_admin_email',
            'postpass',
            'logout',
            'lostpassword',
            'retrievepassword',
            'resetpass',
            'rp',
            'register',
            'checkemail',
            'confirmaction',
            'login'
        );

        if (!in_array($action, $default_actions, true)) {
            $action = '';
        }

        return $action;
    }

    public function getFormType($action)
    {
        $type = 'login';
        switch ($action) {
            case 'login':
                $type = 'login';
                break;
            case 'register':
                $type = 'register';
                break;
            case 'lostpassword':
                $type = 'reset_password';
                break;
            case 'retrievepassword':
                $type = 'reset_password_confirm';
                break;
            default:
                return 'login';
        }

        return $type;
    }

}
