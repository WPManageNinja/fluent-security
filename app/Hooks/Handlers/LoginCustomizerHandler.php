<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;

class LoginCustomizerHandler
{

    public function register()
    {
        add_action('login_head', function () {
            if (!$this->isSecureSignupForm()) {
                return;
            }
            ?>
            <style>
                #login #reg_passmail {
                    display: none !important;
                }

                #login p.fs_reg_item_terms {
                    margin-bottom: 20px;
                }

                body.fls_register_form_token #registerform > p {
                    display: none !important;
                }
            </style>
            <?php
        });

        add_action('register_form', function () {
            if (!$this->isSecureSignupForm()) {
                return;
            }
            $this->addExtendedRegFields();
        });

        add_filter('registration_errors', [$this, 'maybeInterceptRegistration'], 10, 3);
        add_action('register_post', [$this, 'maybeIntercept2FaRegistration'], 10, 3);

        add_action('login_init', [$this, 'maybeCustomizeAuthPage']);
    }

    public function maybeCustomizeAuthPage()
    {
        $settings = $this->getSettings();

        if ($settings['status'] !== 'yes') {
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

        if (!$formSettings) {
            $formSettings = Arr::get($allSettings, 'login', []);

            $formSettings['form']['title'] = '';
            $formSettings['form']['description'] = '';

            if ($formType == 'reset_password') {
                $formSettings['form']['title'] = __('Reset Password', 'fluent-security');
                $formSettings['form']['description'] = '';
            }
        }

        $smartCodeParse = new \FluentAuth\App\Services\SmartCodeParser();

        $formSettings['form']['title'] = $smartCodeParse->parse($formSettings['form']['title'], null);
        $formSettings['form']['description'] = $smartCodeParse->parse($formSettings['form']['description'], null);

        if (isset($formSettings['banner'])) {
            $formSettings['banner']['title'] = $smartCodeParse->parse($formSettings['banner']['title'], null);
            $formSettings['banner']['description'] = $smartCodeParse->parse($formSettings['banner']['description'], null);
        } else {
            $loginForm = Arr::get($allSettings, 'login', []);
            $formSettings['banner']['title'] = $smartCodeParse->parse($loginForm['banner']['title'], null);
            $formSettings['banner']['description'] = $smartCodeParse->parse($loginForm['banner']['description'], null);
        }

        add_action('login_enqueue_scripts', function () use ($formSettings) {
            wp_enqueue_style(
                'fls-login-customizer',
                FLUENT_AUTH_PLUGIN_URL . 'dist/public/login_customizer.css',
                [],
                FLUENT_AUTH_VERSION
            );

            $bannerDesignElements = ['title_color', 'text_color', 'button_color', 'button_label_color', 'background_color', 'background_image'];
            $formDesignElements = ['title_color', 'text_color', 'button_color', 'button_label_color', 'background_color', 'background_image'];

            $bannerValues = array_filter(Arr::only(Arr::get($formSettings, 'banner', []), $bannerDesignElements));
            $formValues = array_filter(Arr::only(Arr::get($formSettings, 'form', []), $formDesignElements));

            $css = '';
            foreach ($bannerValues as $designKey => $designValue) {
                if ($designValue) {
                    $css .= '--fls-banner-' . $designKey . ': ' . $designValue . ';';
                }
            }

            foreach ($formValues as $designKey => $designValue) {
                if ($designValue) {
                    $css .= '--fls-form-' . $designKey . ': ' . $designValue . ';';
                }
            }

            $cssVars = ':root { ' . $css . '  }';

            wp_add_inline_style('fls-login-customizer', $cssVars);
        });

        add_action('login_header', function () use ($formSettings, $formType) {

            $extraCssClass = apply_filters('fluent_auth/extra_login_page_wrap_css_class', '');
            $extraCssClass .= 'fls_layout_banner_' . Arr::get($formSettings, 'banner.position');

            ?>
            <div class="fls_login_page_wrap fls_form_type_<?php echo esc_attr($formType); ?> <?php echo esc_attr($extraCssClass); ?>">
            <div class="fls_login_form_wrap"><div class="fls_form_wrap">
            <div class="fls_login_header">
                <h1><?php echo wp_kses_post(Arr::get($formSettings, 'form.title')); ?></h1>
                <p><?php echo wp_kses_post(Arr::get($formSettings, 'form.description')); ?></p>
            </div>
            <?php
        });

        add_action('login_footer', function () use ($formSettings) {
            $backgroundImage = Arr::get($formSettings, 'banner.background_image');
            ?>
            </div></div> <!-- End of fls_form_wrap and fls_login_form_wrap-->

            <div style="<?php if ($backgroundImage) {
                echo 'background-image: url(' . esc_url($backgroundImage) . ')';
            } ?>" class="fls_login_cusom_content_wrap">
                <div class="fls_login_cusom_content">
                    <div class="fls_login_cusom_content_inner">
                        <?php if ($logo = Arr::get($formSettings, 'banner.logo')): ?>
                            <div class="fls_banner_header_logo">
                                <img src="<?php echo esc_url($logo); ?>"
                                     alt="<?php echo esc_attr__('Logo', 'fluent-security'); ?>"/>
                            </div>
                        <?php endif; ?>
                        <h1><?php echo wp_kses_post(Arr::get($formSettings, 'banner.title', '')); ?></h1>
                        <p><?php echo wp_kses_post(Arr::get($formSettings, 'banner.description', '')); ?></p>
                    </div>
                </div>
            </div>
            </div> <!-- End of fls_login_page_wrap-->
            <?php
        });

    }

    public function addExtendedRegFields()
    {
        $policyUrl = get_privacy_policy_url();
        $policyUrl = apply_filters('fluent_auth/signup_policy_url', $policyUrl);

        // We will add the custom fields here
        $fullName = Arr::get($_POST, 'user_full_name', '');
        $password = Arr::get($_POST, 'user_password', '');
        $confirmPassword = Arr::get($_POST, 'user_confirm_password', '');
        $agreeTerms = Arr::get($_POST, 'agree_terms', '');
        ?>
        <p class="fs_reg_item fs_reg_item_full_name">
            <label for="user_full_name"><?php _e('Your Full Name', 'fluent-security'); ?></label>
            <input type="text" name="user_full_name" id="user_full_name" class="input" value="<?php echo esc_attr($fullName); ?>" size="100" autocomplete="name" required="required"/>
        </p>

        <p class="fs_reg_item fs_reg_item_password">
            <label for="user_password"><?php _e('Password', 'fluent-security'); ?></label>
            <input type="password" name="user_password" id="user_password" class="input" value="<?php echo htmlspecialchars($password, ENT_QUOTES, 'UTF-8'); ?>" size="50" required="required"/>
        </p>

        <p class="fs_reg_item fs_reg_item_conf_password">
            <label for="user_confirm_password"><?php _e('Re-Enter Password', 'fluent-security'); ?></label>
            <input type="password" name="user_confirm_password" value="<?php echo htmlspecialchars($confirmPassword, ENT_QUOTES, 'UTF-8'); ?>" id="user_confirm_password" class="input" size="50" required="required"/>
        </p>

        <p class="fs_reg_item fs_reg_item_terms">
            <label for="agree_terms">
                <input type="checkbox" <?php echo $agreeTerms ? 'checked' : ''; ?> name="agree_terms" id="agree_terms" value="agreed" size="50" required="required"/>
                <?php if ($policyUrl): ?>
                    <?php printf(__('I agree to the %s', 'fluent-security'), '<a target="_blank" rel="noopener" href="' . esc_url($policyUrl) . '">' . __('terms and conditions.') . '</a>'); ?>
                <?php else: ?>
                    <?php _e('I agree to the terms and conditions', 'fluent-security'); ?>
                <?php endif; ?>
            </label>
        </p>
        <?php
    }

    public function maybeInterceptRegistration(\WP_Error $errors, $sanitized_user_login, $user_email)
    {
        if(did_action('fluent_auth/after_signup_validation')) {
            return $errors;
        }

        if(!did_action('login_init')) {
            return  $errors; // we only intercept the registration form in the wp-login.php
        }

        if ($errors->has_errors()) {
            return $errors;
        }

        if (!$this->isSecureSignupForm()) {
            return $errors;
        }

        $registrationValidation = $this->validateRegistrationData($_POST);

        if ($registrationValidation->has_errors()) {
            return $registrationValidation;
        }

        $errors->add('confirm_token', sprintf(__('A verification code has been sent to %s. Please provide the code below:', 'fluent-security'), $user_email));

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

        add_action('login_body_class', function ($classes) {
            $classes[] = 'fls_register_form_token';
            return $classes;
        });

        return $errors;
    }

    public function maybeIntercept2FaRegistration($sanitized_user_login, $user_email, \WP_Error $errors)
    {
        if (did_action('fluent_auth/after_signup_validation')) {
            return false;
        }

        if ($errors->has_errors()) {
            return false; // it's an aleady error
        }

        if (!$this->isSecureSignupForm()) {
            return false;
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

        if ($user) {
            $isAutoLogin = apply_filters('fluent_auth/auto_login_after_signup', true, $user);
            if ($isAutoLogin) {
                $user = AuthService::makeLogin($user);
            }
        }

        if (!get_current_user_id()) {
            $redirect_to = !empty($_POST['redirect_to']) ? $_POST['redirect_to'] : 'wp-login.php?checkemail=registered';
            wp_safe_redirect($redirect_to);
            exit;
        }

        $redirectUrl = admin_url();
        $intendedRedirectUrl = false;
        if (isset($_POST['redirect_to']) && filter_var($_POST['redirect_to'], FILTER_VALIDATE_URL)) {
            $redirectUrl = sanitize_url($_POST['redirect_to']);
            $intendedRedirectUrl = $redirectUrl;
        }

        $redirectUrl = apply_filters('login_redirect', $redirectUrl, $intendedRedirectUrl, $user);

        wp_redirect($redirectUrl);
        exit();
    }

    private function validateRegistrationData($data)
    {
        $errors = new \WP_Error();

        if (!empty($data['first_name'])) {
            $data['user_full_name'] = trim(Arr::get($data, 'first_name') . ' ' . Arr::get($data, 'last_name'));
        }

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
        return Helper::getAuthCustomizerSettings();
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
            'login',
            'fls_2fa_email'
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
                $type = 'signup';
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

    public function isSecureSignupForm()
    {
        $settings = Helper::getAuthSettings();
        $enabled = Arr::get($settings, 'secure_signup_form', 'no') === 'yes';

        if (!$enabled) {
            $customSignUpSettings = $this->getSettings();
            $enabled = Arr::get($customSignUpSettings, 'enabled', 'no') === 'yes';
        }

        return $enabled;

    }
}
