<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;

class CustomAuthHandler
{

    protected $loaded = false;

    public function register()
    {
        add_shortcode('fluent_auth_login', array($this, 'loginForm'));
        add_shortcode('fluent_auth_signup', array($this, 'registrationForm'));
        add_shortcode('fluent_auth', array($this, 'authForm'));
        add_shortcode('fluent_auth_reset_password', array($this, 'restPasswordForm'));
        add_shortcode('fluent_auth_magic_login', array($this, 'magicLoginForm'));

        /*
         * Alter Login And Logout Redirect URLs
         */
        add_filter('login_redirect', array($this, 'alterLoginRedirectUrl'), 999, 3);
        add_filter('logout_redirect', array($this, 'alterLogoutRedirectUrl'), 999, 3);

        add_action('wp_ajax_nopriv_fluent_auth_login', array($this, 'handleLoginAjax'));
        add_action('wp_ajax_nopriv_fluent_auth_signup', array($this, 'handleSignupAjax'));
        add_action('wp_ajax_nopriv_fluent_auth_rp', array($this, 'handlePasswordResentAjax'));
        add_action('fls_load_login_helper', array($this, 'loadAssets'));
    }

    public function alterLoginRedirectUrl($redirect_to, $intentRedirectTo, $user)
    {
        if (is_wp_error($user)) {
            return $redirect_to;
        }

        // check if we have value from cookie _fls_redirect_to
        if (isset($_COOKIE['_fls_redirect_to']) && filter_var($_COOKIE['_fls_redirect_to'], FILTER_VALIDATE_URL)) {
            $redirect_to = sanitize_url($_COOKIE['_fls_redirect_to']);
            $validatedRedirectUrl = Helper::getValidatedRedirectUrl($redirect_to, admin_url());
            unset($_COOKIE['_fls_redirect_to']);
            setcookie('_fls_redirect_to', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN);
            if ($validatedRedirectUrl == $redirect_to) {
                return $redirect_to;
            }

        }

        if (apply_filters('fluent_auth/respect_front_login_url', true) && strpos($redirect_to, '/wp-admin') === false) {
            // it's a frontend redirect url
        } else if ($url = $this->getDefaultLoginRedirectUrl($user)) {
            $redirect_to = $url;
        }

        return $redirect_to;
    }

    public function alterLogoutRedirectUrl($redirect_to, $intentRedirectTo, $user)
    {
        if (is_wp_error($user)) {
            return $redirect_to;
        }

        if ($url = $this->getDefaultLogoutRedirectUrl($user)) {
            return $url;
        }

        return $redirect_to;
    }

    /**
     * loginForm will generate html for login form
     * @param $attributes
     * @return string
     */
    public function loginForm($attributes, $headerContent = '')
    {
        if (!$this->isEnabled()) {
            return '';
        }

        if (get_current_user_id()) {
            $message = apply_filters('fluent_auth/already_logged_in_message',
                sprintf(__('You are already logged in. <a href="%s">Go to Home Page</a>', 'fluent-security'), site_url())
            );

            if (!$message) {
                return '';
            }

            return '<p>' . $message . '</p>';
        }

        $this->loadAssets();
        $attributes = $this->getShortcodes($attributes);
        $this->handleAlreadyLoggedIn($attributes);

        $return = '<div id="fls_login_form" class="fls_login_wrapper">';

        if ($headerContent) {
            $return .= $headerContent;
        }

        $redirect = '';
        $requestedRedirectTo = '';

        if (!empty($attributes['redirect_to']) && filter_var($attributes['redirect_to'], FILTER_VALIDATE_URL)) {
            $redirect = $attributes['redirect_to'];
            $requestedRedirectTo = $redirect;
            add_filter('fluent_auth/social_redirect_to', function ($url) use ($redirect) {
                return $redirect;
            });
        }

        /*
         * Filter login form
         *
         * @since v1.0.0
         *
         * @param array $loginArgs
         */
        $loginArgs = apply_filters('fluent_auth/login_form_args', [
            'echo'              => false,
            'redirect'          => $redirect,
            'force_redirect_to' => $requestedRedirectTo,
            'remember'          => true,
            'value_remember'    => true,
            'action_url'        => site_url('/')
        ]);

        $return .= $this->nativeLoginForm($loginArgs);

        if ($attributes['show-signup'] == 'true' && get_option('users_can_register')) {
            $return .= '<p style="text-align: center">'
                . __('Not registered?', 'fluent-security')
                . ' <a href="#" id="fls_show_signup">'
                . __('Create an Account', 'fluent-security')
                . '</a></p>';
        }

        if ($attributes['show-reset-password'] == 'true') {
            $return .= '<p style="text-align: center">'
                . __('Forgot your password?', 'fluent-security')
                . ' <a href="#" id="fls_show_reset_password">'
                . __('Reset Password', 'fluent-security')
                . '</a></p>';
        }

        $return .= '</div>';
        return $return;
    }

    /**
     * registrationForm method will generate html for sign up form
     * @param $attributes
     * @return string
     */
    public function registrationForm($attributes, $headerContent = '')
    {
        if (!$this->isEnabled()) {
            return '';
        }

        if (!get_option('users_can_register')) {
            return '<p>' . sprintf(__('User registration is not enabled. <a href="%s">Go to Home Page</a>', 'fluent-security'), esc_url(site_url())) . '</p>';
        }

        if (get_current_user_id()) {
            $message = apply_filters('fluent_auth/already_logged_in_message',
                sprintf(__('You are already logged in. <a href="%s">Go to Home Page</a>', 'fluent-security'), site_url())
            );
            return '<p>' . $message . '</p>';
        }

        $attributes = $this->getShortcodes($attributes);
        $this->handleAlreadyLoggedIn($attributes);

        $registrationFields = $this->getSignupFields();
        $hide = $attributes['hide'] == 'true' ? 'hide' : '';

        $this->loadAssets($hide);

        return $this->buildRegistrationForm($registrationFields, $hide, $attributes, $headerContent);
    }

    // This method `buildRegistrationForm` will generate html for sign up form
    private function buildRegistrationForm($registrationFields, $hide, $attributes, $headerContent = '')
    {

        $registrationForm = '<div class="fls_registration_wrapper ' . esc_attr($hide) . '">';

        if ($headerContent) {
            $registrationForm .= $headerContent;
        }

        $registrationForm .= '<form id="flsRegistrationForm" class="fls_registration_form" method="post" name="fls_registration_form"><div class="fls_registration_fields">';

        foreach ($registrationFields as $fieldName => $registrationField) {
            $registrationForm .= $this->renderField($fieldName, $registrationField);
        }

        $registrationForm .= '<input type="hidden" name="__redirect_to" value="' . esc_url($attributes['redirect_to']) . '">';
        $registrationForm .= '<input type="hidden" name="_fls_signup_nonce" value="' . wp_create_nonce('fluent_auth_signup_nonce') . '">';
        $registrationForm .= '<button type="submit" id="fls_submit">' . $this->submitBtnLoadingSvg() . '<span>' . __('Signup', 'fluent-security') . '</span></button>';

        $registrationForm .= '</div></form>';

        $registrationForm .= apply_filters('fluent_auth/after_registration_form_close', '', $registrationFields, $attributes);

        if ($hide) {
            $registrationForm .= '<p style="text-align: center">'
                . __('Already have an account?', 'fluent-security')
                . ' <a href="#" id="fls_show_login">'
                . __('Login', 'fluent-security')
                . '</a></p>';
        }

        $registrationForm .= '</div>';

        return $registrationForm;
    }

    public function restPasswordForm($attributes, $headerContent = '')
    {
        if (!$this->isEnabled()) {
            return '';
        }

        if (get_current_user_id()) {
            $message = apply_filters('fluent_auth/already_logged_in_message',
                sprintf(__('You are already logged in. <a href="%s">Go to Home Page</a>', 'fluent-security'), site_url())
            );
            return '<p>' . $message . '</p>';
        }

        $attributes = $this->getShortcodes($attributes);
        $this->handleAlreadyLoggedIn($attributes);

        $resetPasswordFields = static::resetPasswordFields();
        $hide = $attributes['hide'] == 'true' ? 'hide' : '';

        $this->loadAssets($hide);

        return $this->buildResetPassForm($resetPasswordFields, $hide, $attributes, $headerContent);
    }

    // This method `buildResetPassForm` will generate html for password reset form
    private function buildResetPassForm($resetPasswordFields, $hide, $attributes, $headerContent = '')
    {
        $resetPasswordForm = '<div class="fls_reset_pass_wrapper ' . $hide . '">';

        if ($headerContent) {
            $resetPasswordForm .= $headerContent;
        }

        $resetPasswordForm .= '<form id="flsResetPasswordForm" class="fls_reset_pass_form" method="post" name="fls_reset_pass_form">';

        foreach ($resetPasswordFields as $fieldName => $resetPasswordField) {
            $resetPasswordForm .= $this->renderField($fieldName, $resetPasswordField);
        }

        $resetPasswordForm .= '<input type="hidden" name="__redirect_to" value="' . $attributes['redirect_to'] . '">';
        $resetPasswordForm .= '<input type="hidden" name="_fls_reset_pass_nonce" value="' . wp_create_nonce('fluent_auth_reset_pass_nonce') . '">';
        $resetPasswordForm .= '<button type="submit" id="fls_reset_pass">' . $this->submitBtnLoadingSvg() . '<span>' . __('Reset Password', 'fluent-security') . '</span></button>';

        $resetPasswordForm .= '</form>';

        $resetPasswordForm .= '</div>';

        return $resetPasswordForm;
    }

    /**
     * authForm will render the login form html
     * @param $attributes
     * @return string
     */
    public function authForm($attributes)
    {
        if (!$this->isEnabled()) {
            return '';
        }

        if (get_current_user_id()) {
            $message = apply_filters('fluent_auth/already_logged_in_message',
                sprintf(__('You are already logged in. <a href="%s">Go to Home Page</a>', 'fluent-security'), site_url())
            );
            return '<p>' . $message . '</p>';
        }
        $atts = $this->getShortcodes($attributes);

        $authForm = '<div class="fls_auth_wrapper">';

        $authForm .= do_shortcode('[fluent_auth_login redirect_to="' . esc_url($atts['redirect_to']) . '" show-signup=true show-reset-password=true]');

        if (get_option('users_can_register')) {
            $authForm .= do_shortcode('[fluent_auth_signup redirect_to="' . esc_url($atts['redirect_to']) . '" hide=true]');
        }

        $authForm .= do_shortcode('[fluent_auth_reset_password redirect_to="' . esc_url($atts['redirect_to']) . '" hide=true]');

        $authForm .= '</div>';

        return $authForm;
    }

    public function magicLoginForm($attributes, $content = '')
    {
        $magicHandler = new MagicLoginHandler();
        if (!$this->isEnabled() || !$magicHandler->isEnabled()) {
            return '';
        }

        if (get_current_user_id()) {
            $message = apply_filters('fluent_auth/already_logged_in_message',
                sprintf(__('You are already logged in. <a href="%s">Go to Home Page</a>', 'fluent-security'), site_url())
            );
            return '<p>' . $message . '</p>';
        }

        $atts = $this->getShortcodes($attributes);

        $magicHandler->pushAssets();

        ob_start();
        ?>
        <div id="fls_magic_login">
            <div class="fls_magic_login_form fls_magic_login">
                <?php if ($content): ?>
                    <div class="fls_magic_content">
                        <?php echo wp_kses_post($content); ?>
                    </div>
                <?php endif; ?>
                <label for="fls_magic_logon">
                    <?php _e('Your Email/Username', 'fluent-security'); ?>
                </label>
                <input placeholder="<?php _e('Your Email/Username', 'fluent-security'); ?>" id="fls_magic_logon"
                       class="fls_magic_input" type="text"/>
                <input id="fls_magic_logon_nonce" type="hidden"
                       value="<?php echo wp_create_nonce('fls_magic_logon_nonce'); ?>"/>
                <?php if (!empty($atts['redirect_to'])): ?>
                    <input type="hidden" value="<?php echo esc_url($atts['redirect_to']); ?>" name="redirect_to"/>
                <?php endif; ?>
                <div class="fls_magic_submit_wrapper">
                    <button class="button button-primary button-large" id="fls_magic_submit">
                        <?php _e('Continue', 'fluent-security'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php

        return ob_get_clean();
    }

    /**
     * renderField method will generate html for a field
     * @param $fieldName
     * @param $field
     * @return string
     */
    private function renderField($fieldName, $field)
    {
        $fieldType = Arr::get($field, 'type');
        $isRequired = Arr::get($field, 'required');
        $isRequired = $isRequired ? 'is-required' : '';

        $textTypes = ['text', 'email', 'password'];

        $html = '<div class="fls_field_group fls_field_' . $fieldName . '">';
        if ($label = Arr::get($field, 'label')) {
            $html .= '<div class="fls_field_label ' . $isRequired . '"><label for="' . Arr::get($field, 'id') . '">' . $label . '</label></div>';
        }

        if (in_array($fieldType, $textTypes)) {

            $inputAtts = array_filter([
                'type'        => esc_attr($fieldType),
                'id'          => esc_attr(Arr::get($field, 'id')),
                'placeholder' => esc_attr(Arr::get($field, 'placeholder')),
                'name'        => esc_attr($fieldName)
            ]);

            $atts = '';

            foreach ($inputAtts as $attKey => $att) {
                $atts .= $attKey . '="' . $att . '" ';
            }

            if (Arr::get($field, 'required')) {
                $atts .= 'required';
            }

            $html .= '<div class="fs_input_wrap"><input ' . $atts . '/></div>';
        } else {
            return '';
        }

        return $html . '</div>';
    }

    /**
     * getSignupFields method will return the list of fields that will be used for sign up form
     * @return mixed
     */
    public function getSignupFields()
    {
        /*
         * Filter signup form field
         *
         * @since v1.0.0
         *
         * @param array $fields Form fields
         */
        return apply_filters('fluent_auth/registration_form_fields', [
            'first_name' => [
                'required'    => true,
                'type'        => 'text',
                'label'       => __('First name', 'fluent-security'),
                'id'          => 'fls_first_name',
                'placeholder' => __('First name', 'fluent-security')
            ],
            'last_name'  => [
                'type'        => 'text',
                'label'       => __('Last Name', 'fluent-security'),
                'id'          => 'fls_last_name',
                'placeholder' => __('Last name', 'fluent-security')
            ],
            'username'   => [
                'required'    => true,
                'type'        => 'text',
                'label'       => __('Username', 'fluent-security'),
                'id'          => 'fls_reg_username',
                'placeholder' => __('Username', 'fluent-security')
            ],
            'email'      => [
                'required'    => true,
                'type'        => 'email',
                'label'       => __('Email Address', 'fluent-security'),
                'id'          => 'fls_reg_email',
                'placeholder' => __('Your Email Address', 'fluent-security')
            ],
            'password'   => [
                'required'    => true,
                'type'        => 'password',
                'label'       => __('Password', 'fluent-security'),
                'id'          => 'fls_reg_password',
                'placeholder' => __('Password', 'fluent-security')
            ]
        ]);
    }

    public static function resetPasswordFields()
    {
        /*
         * Filter reset password form field
         *
         * @since v1.5.7
         *
         * @param array $fields Form fields
         */
        return apply_filters('fluent_auth/reset_password_form', [
            'user_login' => [
                'required'    => true,
                'type'        => 'text',
                'label'       => __('Email Address', 'fluent-security'),
                'id'          => 'fls_email',
                'placeholder' => __('Your Email Address', 'fluent-security')
            ]
        ]);
    }

    protected function submitBtnLoadingSvg()
    {
        $loadingIcon = '<svg version="1.1" class="fls_loading_svg" x="0px" y="0px" width="40px" height="20px" viewBox="0 0 50 50" style="enable-background:new 0 0 50 50;" xml:space="preserve">
            <path fill="currentColor" d="M43.935,25.145c0-10.318-8.364-18.683-18.683-18.683c-10.318,0-18.683,8.365-18.683,18.683h4.068c0-8.071,6.543-14.615,14.615-14.615c8.072,0,14.615,6.543,14.615,14.615H43.935z">
              <animateTransform attributeType="xml"
                attributeName="transform"
                type="rotate"
                from="0 25 25"
                to="360 25 25"
                dur="0.6s"
                repeatCount="indefinite"/>
              </path>
        </svg>';

        /*
         * Filter signup form loading icon
         *
         * @since v1.0.0
         *
         * @param string $loadingIcon this accepts html element
         */
        return apply_filters('fluent_auth/signup_loading_icon', $loadingIcon);
    }

    protected function getShortcodes($attributes)
    {
        /*
         * Filter shortcode behavior for agent
         *
         * @since v1.0.0
         *
         * @param array $shortCodeDefaults
         */
        $shortCodeDefaults = apply_filters('fluent_auth/auth_shortcode_defaults', [
            'auto-redirect'       => false,
            'redirect_to'         => '',
            'hide'                => false,
            'show-signup'         => false,
            'show-reset-password' => false,
        ]);

        if (Arr::get($attributes, 'redirect_to') == 'self') {
            $redirectTo = home_url(Arr::get($_SERVER, 'REQUEST_URI'));
            $attributes['redirect_to'] = $redirectTo;
        }

        return shortcode_atts($shortCodeDefaults, $attributes);
    }

    protected function handleAlreadyLoggedIn($attributes)
    {
        if (get_current_user_id() && !wp_is_json_request() && is_singular()) {
            if ($attributes['auto-redirect'] === 'true') {
                $redirect = $attributes['redirect_to'];

                if (!$redirect) {
                    return;
                }

                ?>
                <script type="text/javascript">
                    document.addEventListener("DOMContentLoaded", function () {
                        var redirect = "<?php echo esc_url($redirect); ?>";
                        window.location.replace(redirect);
                    });
                </script>
                <?php
            }
            die();
        }
    }

    public function loadAssets($hide = '')
    {
        if ($this->loaded) {
            return false;
        }

        wp_enqueue_script('fluent_auth_login_helper', FLUENT_AUTH_PLUGIN_URL . 'dist/public/login_helper.js', [], FLUENT_AUTH_VERSION);
        wp_localize_script('fluent_auth_login_helper', 'fluentAuthPublic', [
            'hide'              => $hide,
            'redirect_fallback' => site_url(),
            'fls_login_nonce'   => wp_create_nonce('fsecurity_login_nonce'),
            'ajax_url'          => admin_url('admin-ajax.php'),
            'i18n'              => [
                'Username_or_Email' => __('Username or Email', 'fluent-security'),
                'Password'          => __('Password', 'fluent-security')
            ]
        ]);

        $this->loaded = true;
    }

    public function isEnabled()
    {
        $settings = Helper::getAuthFormsSettings();
        return Arr::get($settings, 'enabled') === 'yes';
    }

    /**
     * @param $user \WP_User
     * @return false|string
     */
    private function getDefaultLoginRedirectUrl($user)
    {
        $settings = Helper::getAuthFormsSettings();

        if (Arr::get($settings, 'login_redirects') != 'yes') {
            return false;
        }

        $defaultLoginRedirect = Arr::get($settings, 'default_login_redirect', false);

        $rules = Arr::get($settings, 'redirect_rules', []);

        if (!$rules) {
            return $defaultLoginRedirect;
        }

        $caps = (array)$user->allcaps;
        $caps = array_filter(array_keys(array_filter($caps)));

        foreach ($rules as $rule) {
            $result = $this->isConditionsMatched($rule['conditions'], $user, $caps);
            if ($result && !empty($rule['login'])) {
                return $rule['login'];
            }
        }

        return $defaultLoginRedirect;
    }

    /**
     * @param $user \WP_User
     * @return false|string
     */
    private function getDefaultLogoutRedirectUrl($user)
    {
        $settings = Helper::getAuthFormsSettings();
        if (Arr::get($settings, 'login_redirects') != 'yes') {
            return false;
        }

        $defaultLogoutRedirect = Arr::get($settings, 'default_logout_redirect');

        $rules = Arr::get($settings, 'redirect_rules', []);

        if (!$rules) {
            return $defaultLogoutRedirect;
        }

        $caps = (array)$user->allcaps;
        $caps = array_filter(array_keys(array_filter($caps)));

        foreach ($rules as $rule) {
            $result = $this->isConditionsMatched($rule['conditions'], $user, $caps);
            if ($result && !empty($rule['logout'])) {
                return $rule['logout'];
            }
        }

        return $defaultLogoutRedirect;
    }

    /**
     * @param $conditions array
     * @param $user \WP_User
     * @param $caps array
     * @return boolean
     */
    private function isConditionsMatched($conditions, $user, $caps = [])
    {
        $isMatched = false;

        foreach ($conditions as $condition) {
            if (!$condition['values']) {
                continue;
            }
            $key = $condition['condition'];
            if ($key == 'user_role') {
                $isMatched = (bool)array_intersect((array)$condition['values'], (array)$user->roles);
            } else if ($key == 'user_capability') {
                $isMatched = (bool)array_intersect((array)$condition['values'], (array)$caps);
            }

            if (!$isMatched) {
                return false;
            }
        }

        return $isMatched;
    }

    /**
     * handleLogin method will perform login functionality and redirect
     */
    public function handleLoginAjax()
    {
        if (!$this->isEnabled()) {
            wp_send_json([
                'message' => __('Login is not enabled', 'fluent-security')
            ], 422);
        }

        $nonce = Arr::get($_REQUEST, '_nonce');

        if (!$nonce) {
            wp_send_json([
                'message' => __('Security nonce is required', 'fluent-security')
            ], 422);
        }

        if (!wp_verify_nonce(Arr::get($_REQUEST, '_nonce'), 'fsecurity_login_nonce')) {
            wp_send_json([
                'message' => __('Security verification failed', 'fluent-security')
            ], 422);
        }

        $data = $_REQUEST;
        if (empty($_REQUEST['_is_fls_form'])) {
            wp_send_json([
                'message' => __('Invalid request', 'fluent-security')
            ], 422);
        }

        if (empty($data['pwd']) || empty($data['log'])) {
            wp_send_json([
                'message' => __('Email and Password is required', 'fluent-security')
            ], 422);
        }

        $redirectUrl = admin_url();
        if (isset($data['redirect_to']) && filter_var($data['redirect_to'], FILTER_VALIDATE_URL)) {
            $userRedirect = sanitize_url($data['redirect_to']);
            $redirectUrl = Helper::getValidatedRedirectUrl($userRedirect, $redirectUrl);
        }

        $isForced = false;
        if (!empty($data['force_redirect_to']) && filter_var($data['force_redirect_to'], FILTER_VALIDATE_URL)) {
            $redirectUrl = Helper::getValidatedRedirectUrl(sanitize_url($data['force_redirect_to']), $redirectUrl);
            $isForced = true;
        }

        if ($currentUserId = get_current_user_id()) { // user already logged in
            $user = get_user_by('ID', $currentUserId);
            if (!$isForced) {
                $redirectUrl = apply_filters('login_redirect', $redirectUrl, false, $user);
            }
            wp_send_json([
                'redirect' => $redirectUrl
            ], 200);
        }

        $email = sanitize_user($data['log']);

        if (is_email($email)) {
            $user = get_user_by('email', $email);
        } else {
            $user = get_user_by('login', $email);
        }

        if (!$user) {
            $user = new \WP_Error('authentication_failed', __('<strong>Error</strong>: Invalid username, email address or incorrect password.', 'fluent-security'));

            do_action('wp_login_failed', $email, $user);

            wp_send_json([
                'message' => __('Email or Password is not valid. Please try again', 'fluent-security')
            ], 422);
        }


        $user = wp_signon();

        if (is_wp_error($user)) {
            wp_send_json([
                'message' => $user->get_error_message()
            ], 422);
        }

        if (!$isForced) {
            $filteredRedirectUrl = apply_filters('login_redirect', $redirectUrl, false, $user);
            $filteredRedirectUrl = apply_filters('fluent_auth/login_redirect_url', $filteredRedirectUrl, $user, $_REQUEST);
        } else {
            $filteredRedirectUrl = $redirectUrl;
        }

        wp_send_json([
            'redirect' => $filteredRedirectUrl
        ], 200);
    }

    public function handleSignupAjax()
    {
        $signupEnabled = $this->isEnabled() && get_option('users_can_register');
        $signupEnabled = apply_filters('fluent_auth/signup_enabled', $signupEnabled);
        if (!$signupEnabled) {
            wp_send_json([
                'message' => __('User registration is not enabled', 'fluent-security')
            ], 422);
        }

        if (!wp_verify_nonce(Arr::get($_REQUEST, '_fls_signup_nonce'), 'fluent_auth_signup_nonce')) {
            wp_send_json([
                'message' => __('Security verification failed. Please try again', 'fluent-security')
            ], 422);
        }

        /*
         * Filter user signup form data
         *
         * @since v1.0.0
         * @param array $formData
         */
        $formData = apply_filters('fluent_auth/signup_form_data', $_REQUEST);

        /*
         * Action before validate user signup
         *
         * @since v1.0.0
         * @param array $formData
         */
        do_action('fluent_auth/before_signup_validation', $formData);

        $errors = $this->validateSignUpData($formData);

        if ($errors) {
            wp_send_json([
                'message' => __('Form validation failed. Please provide the correct data', 'fluent-security'),
                'errors'  => $errors
            ], 422);
        }

        /*
         * Action After validate user signup validation success
         *
         * @since v1.0.0
         * @param array $formData
         */
        do_action('fluent_auth/after_signup_validation', $formData);

        if (empty($formData['username'])) {
            $formData['username'] = sanitize_user($formData['email']);
        }

        $errors = AuthService::checkUserRegDataErrors($formData['username'], $formData['email'], [
            '__validated' => true
        ]);

        if ($errors->has_errors()) {
            wp_send_json([
                'message' => $errors->get_error_message()
            ], 422);
        }

        // let's validate the name field
        $fullName = trim(Arr::get($formData, 'first_name') . ' ' . Arr::get($formData, 'last_name'));
        if (!empty($fullName)) {
            // check if the name is valid
            // Consider if there has any special characters like +, -, *, /, etc
            // only check the +,-,*,$,/,=,%,!,@,#,^,&,*,(,),_,{,},[,],:,;,',",<,>,?,|,`,~,,
            if (preg_match('/[\'^£$%&*()}{@#~?><>,|=_+¬-]/u', $fullName)) {
                return __('Please provide a valid name', 'fluent-security');
            }

            // check if there has any http or https
            if (preg_match('/http|https/', $fullName)) {
                return __('Please provide a valid name', 'fluent-security');
            }
        }

        if (apply_filters('fluent_auth/verify_signup_email', true, $formData)) {
            // Let's check for email verification token
            if (empty($formData['_email_verification_token'])) {
                $tokenHtml = $this->sendSignupEmailVerificationHtml($formData);
                wp_send_json([
                    'verifcation_html' => $tokenHtml
                ]);
            } else {
                $token = $formData['_email_verification_token'];
                $verificationHash = $formData['_email_verification_hash'];
                $isTokenValidated = AuthService::verifyTokenHash($verificationHash, $token);

                if (is_wp_error($isTokenValidated)) {
                    wp_send_json([
                        'message' => $isTokenValidated->get_error_message()
                    ], 422);
                }
            }
        }

        $userRole = apply_filters('fluent_auth/signup_default_role', get_option('default_role'), $formData);
        do_action('fluent_auth/before_creating_user', $formData);

        $userId = AuthService::registerNewUser($formData['username'], $formData['email'], $formData['password'], [
            'role'        => $userRole,
            'first_name'  => Arr::get($formData, 'first_name'),
            'last_name'   => Arr::get($formData, 'last_name'),
            '__validated' => true
        ]);


        if (is_wp_error($userId)) {
            wp_send_json([
                'message' => $userId->get_error_message()
            ], 422);
        }

        $user = get_user_by('ID', $userId);
        $isAutoLogin = apply_filters('fluent_auth/auto_login_after_signup', true, $user);
        $message = __('Registration has been completed. Please login now', 'fluent-security');

        $redirectUrl = false;
        if ($isAutoLogin) {
            $this->login($userId);
            $redirectUrl = Arr::get($formData, 'redirect_to', admin_url());
            $redirectUrl = Helper::getValidatedRedirectUrl($redirectUrl, admin_url());
            $redirectUrl = apply_filters('login_redirect', $redirectUrl, false, $user);
            $redirectUrl = apply_filters('fluent_auth/login_redirect_url', $redirectUrl, $user, $formData);
            $message = __('Successfully registered to the site.', 'fluent-security');
        }

        $response = [
            'message' => $message
        ];

        if ($redirectUrl) {
            $response['redirect'] = $redirectUrl;
        }

        /*
         * Filter for user signup complete message and redirect
         *
         * @since v1.0.0
         * @param array $response
         */
        $response = apply_filters('fluent_auth/signup_complete_response', $response, $user);

        wp_send_json($response, 200);
    }

    public function handlePasswordResentAjax()
    {
        if (!$this->isEnabled()) {
            return false;
        }

        $data = $_REQUEST;

        $errors = new \WP_Error();

        if (!wp_verify_nonce(Arr::get($_REQUEST, '_fls_reset_pass_nonce'), 'fluent_auth_reset_pass_nonce')) {

            wp_send_json([
                'message' => __('Security verification failed. Please try again', 'fluent-security')
            ], 422);

        }

        $usernameOrEmail = trim(wp_unslash(Arr::get($data, 'user_login')));

        if (!$usernameOrEmail) {
            wp_send_json([
                'message' => __('Username or email is required', 'fluent-security')
            ], 422);
        }

        $user_data = get_user_by('email', $usernameOrEmail);

        if (!$user_data) {
            $user_data = get_user_by('login', $usernameOrEmail);
        }

        if (!$user_data) {
            wp_send_json([
                'message' => __('Invalid username or email', 'fluent-security')
            ], 422);
        }

        $user_data = apply_filters('lostpassword_user_data', $user_data, $errors);

        do_action('lostpassword_post', $errors, $user_data);

        $errors = apply_filters('lostpassword_errors', $errors, $user_data);

        if ($errors->has_errors()) {
            wp_send_json([
                'message' => $errors->get_error_message()
            ], 422);
        }

        if (!$user_data) {
            wp_send_json([
                'message' => __('<strong>Error</strong>: There is no account with that username or email address.', 'fluent-security')
            ], 422);
        }

        if (is_multisite() && !is_user_member_of_blog($user_data->ID, get_current_blog_id())) {
            wp_send_json([
                'message' => __('<strong>Error</strong>: Invalid username or email', 'fluent-security')
            ], 422);
        }

        // Redefining user_login ensures we return the right case in the email.
        $user_login = $user_data->user_login;

        do_action('retrieve_password', $user_login);

        $allow = apply_filters('allow_password_reset', true, $user_data->ID);

        if (!$allow) {
            wp_send_json([
                'message' => __('Password reset is not allowed for this user', 'fluent-security')
            ], 422);
        }

        if (is_wp_error($allow)) {
            wp_send_json([
                'message' => $allow->get_error_message()
            ], 422);
        }


        /*
         * Filter reset password link text
         *
         * @since v1.5.7
         * @param string $linkText
         */
        $linkText = apply_filters("fluent_auth/reset_password_link", sprintf(__('Reset your password for %s', 'fluent-security'), get_bloginfo('name')));

        $resetKey = get_password_reset_key($user_data);

        $resetUrl = add_query_arg([
            'action' => 'rp',
            'key'    => $resetKey,
            'login'  => rawurlencode($user_data->user_login)
        ], wp_login_url());

        $resetLink = '<a href="' . esc_url($resetUrl) . '">' . esc_html($linkText) . '</a>';

        /*
         * Filter reset password email subject
         *
         * @since v1.5.7
         * @param string $mailSubject
         */
        $mailSubject = apply_filters('fluent_auth/reset_password_mail_subject', sprintf(__('Reset your password for %s', 'fluent-security'), get_bloginfo('name')));

        $message = \sprintf(__('<p>Hi %s,</p>', 'fluent-security'), $user_data->first_name) .
            __('<p>Someone has requested a new password for the following account on WordPress:</p>', 'fluent-security') .
            \sprintf(__('<p>Username: %s</p>', 'fluent-security'), $user_login) .
            \sprintf('<p>%s</p>', $resetLink) .
            \sprintf(__('<p>If you did not request to reset your password, please ignore this email.</p>', 'fluent-security'));

        /*
         * Filter reset password email body text
         *
         * @since v1.5.7
         * @param string $message
         * @param object $user
         * @param string $resetLink
         */
        $message = apply_filters('fluent_auth/reset_password_message', $message, $user_data, $resetLink);

        $data = [
            'body'        => $message,
            'pre_header'  => 'reset your password',
            'show_footer' => false
        ];

        $message = Helper::loadView('notification', $data);

        $defaults = array(
            'to'      => $user_data->user_email,
            'subject' => $mailSubject,
            'message' => $message,
            'headers' => array('Content-Type: text/html; charset=UTF-8')
        );

        $notification_email = apply_filters('retrieve_password_notification_email', $defaults, $resetKey, $user_login, $user_data);

        if (is_array($notification_email)) {
            // Force key order and merge defaults in case any value is missing in the filtered array.
            $notification_email = array_merge($defaults, $notification_email);
        } else {
            $notification_email = $defaults;
        }

        \wp_mail($user_data->user_email, $notification_email['subject'], $notification_email['message'], $notification_email['headers']);

        wp_send_json([
            'message' => __('Please check your email for the reset link', 'fluent-security')
        ]);
    }

    public function validateSignUpData($data)
    {
        $fields = $this->getSignupFields();

        $errors = [];

        foreach ($fields as $fieldName => $field) {
            if (!empty($field['required']) && empty($data[$fieldName])) {
                $errors[$fieldName] = sprintf(__('%s is required', 'fluent-security'), esc_html($field['label']));
            }

            if ($field['type'] === 'email') {
                if (!is_email(Arr::get($data, $fieldName))) {
                    $errors[$fieldName] = sprintf(__('Provided %s is not a valid email', 'fluent-security'), esc_html(strtolower($field['label'])));
                }
            }
        }

        if (isset($fields['password']) && apply_filters('fluent_auth/validate_password_length', true)) {
            $givenPassword = (string)Arr::get($data, 'password', '');
            if (empty($givenPassword) || strlen($givenPassword) < 6) {
                $errors['password'] = __('Password must be at least 6 characters long', 'fluent-security');
            }
        }

        return $errors;
    }

    public function login($userId)
    {
        /*
         * Action before login
         *
         * @since v1.0.0
         * @param integer $userId
         */
        do_action('fluent_auth/before_logging_in_user', $userId);

        wp_clear_auth_cookie();
        wp_set_current_user($userId);
        wp_set_auth_cookie($userId, true, is_ssl());

        /*
         * Action after login
         *
         * @since v1.0.0
         * @param integer $userId
         */
        do_action('fluent_auth/after_logging_in_user', $userId);
    }

    protected function nativeLoginForm($args = array())
    {
        $defaults = array(
            'echo'           => true,
            'redirect'       => (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
            'form_id'        => 'loginform',
            'label_username' => __('Username or Email Address', 'fluent-security'),
            'label_password' => __('Password', 'fluent-security'),
            'label_remember' => __('Remember Me', 'fluent-security'),
            'label_log_in'   => __('Log In', 'fluent-security'),
            'id_username'    => 'user_login',
            'id_password'    => 'user_pass',
            'id_remember'    => 'rememberme',
            'id_submit'      => 'wp-submit',
            'remember'       => true,
            'value_username' => '',
            'value_remember' => false,
        );

        $args = wp_parse_args($args, apply_filters('login_form_defaults', $defaults));

        $login_form_top = apply_filters('login_form_top', '', $args);

        $login_form_middle = apply_filters('login_form_middle', '', $args);

        $login_form_bottom = apply_filters('login_form_bottom', '', $args);

        $actionUrl = esc_url(site_url('wp-login.php', 'login_post'));

        if (isset($args['action_url'])) {
            $actionUrl = esc_url($args['action_url']);
        }

        if (!empty($args['force_redirect_to'])) {
            $login_form_top .= '<input type="hidden" name="force_redirect_to" value="' . esc_url($args['force_redirect_to']) . '" />';
        }

        $form = \sprintf(
                '<form name="%1$s" id="%1$s" action="%2$s" method="post">',
                esc_attr($args['form_id']),
                $actionUrl
            ) .
            $login_form_top .
            \sprintf(
                '<p class="login-username">
				<label for="%1$s">%2$s</label>
				<input type="text" name="log" id="%1$s" autocomplete="username" class="input" value="%3$s" size="20" />
			</p>',
                esc_attr($args['id_username']),
                esc_html($args['label_username']),
                esc_attr($args['value_username'])
            ) .
            \sprintf(
                '<p class="login-password">
				<label for="%1$s">%2$s</label>
				<input type="password" name="pwd" id="%1$s" autocomplete="current-password" class="input" value="" size="20" />
			</p>',
                esc_attr($args['id_password']),
                esc_html($args['label_password'])
            ) .
            $login_form_middle .
            ($args['remember'] ?
                \sprintf(
                    '<p class="login-remember"><label><input name="rememberme" type="checkbox" id="%1$s" value="forever"%2$s /> %3$s</label></p>',
                    esc_attr($args['id_remember']),
                    ($args['value_remember'] ? ' checked="checked"' : ''),
                    esc_html($args['label_remember'])
                ) : ''
            ) .
            \sprintf(
                '<p class="login-submit">
				<input type="submit" name="wp-submit" id="%1$s" class="button button-primary" value="%2$s" />
				<input type="hidden" name="redirect_to" value="%3$s" />
			</p>',
                esc_attr($args['id_submit']),
                esc_attr($args['label_log_in']),
                esc_url($args['redirect'])
            ) .
            $login_form_bottom .
            '</form>';

        if ($args['echo']) {
            echo $form; // @phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        } else {
            return $form;
        }
    }

    public function sendSignupEmailVerificationHtml($formData)
    {
        try {
            $verifcationCode = random_int(100123, 900987);
        } catch (\Exception $e) {
            $verifcationCode = mt_rand(100123, 900987);
        }

        $verifcationCode = (string)$verifcationCode;

        $ipAddress = Helper::getIp();

        $existingCount = flsDb()->table('fls_login_hashes')
            ->where('ip_address', $ipAddress)
            ->where('use_type', 'signup_verification')
            ->where('created_at', '>', date('Y-m-d H:i:s', current_time('timestamp') - 60 * 60))
            ->count();

        if ($existingCount > 5) {
            return __('Too many requests. Please try again later', 'fluent-security');
        }

        $hash = wp_hash_password($formData['email']) . time();
        $data = array(
            'login_hash'       => $hash,
            'status'           => 'issued',
            'ip_address'       => Helper::getIp(),
            'use_type'         => 'signup_verification',
            'two_fa_code_hash' => wp_hash_password($verifcationCode),
            'valid_till'       => date('Y-m-d H:i:s', current_time('timestamp') + 10 * 60),
            'created_at'       => current_time('mysql'),
            'updated_at'       => current_time('mysql')
        );

        flsDb()->table('fls_login_hashes')
            ->insert($data);

        $mailSubject = apply_filters("fluent_auth/signup_verification_mail_subject", sprintf(__('Your registration verification code for %s', 'fluent-security'), get_bloginfo('name')));

        $pStart = '<p style="font-family: Arial, sans-serif; font-size: 16px; font-weight: normal; margin: 0; margin-bottom: 16px;">';

        $message = $pStart . sprintf(__('Hello %s,', 'fluent-security'), Arr::get($formData, 'first_name')) . '</p>' .
            $pStart . __('Thank you for registering with us! To complete the setup of your account, please enter the verification code below on the registration page.', 'fluent-security') . '</p>' .
            $pStart . '<b>' . sprintf(__('Verification Code: %s', 'fluent-security'), $verifcationCode) . '</b></p>' .
            '<br />' .
            $pStart . __('This code is valid for 10 minutes and is meant to ensure the security of your account. If you did not initiate this request, please ignore this email.', 'fluent-security') . '</p>';

        $message = apply_filters('fluent_auth/signup_verification_email_body', $message, $verifcationCode, $formData);

        $data = [
            'body'        => $message,
            'pre_header'  => __('Activate your account', 'fluent-security'),
            'show_footer' => false
        ];

        $message = Helper::loadView('notification', $data);
        $headers = array('Content-Type: text/html; charset=UTF-8');

        \wp_mail($formData['email'], $mailSubject, $message, $headers);

        ob_start();
        ?>

        <div class="fls_signup_verification">
            <div class="fls_field_group fls_field_verification">
                <p class="fls_2fa_instruction"><?php echo esc_html(\sprintf(__('A verification code has been sent to %s. Please provide the code below: ', 'fluent-security'), $formData['email'])) ?></p>
                <input type="hidden" name="_email_verification_hash" value="<?php echo esc_attr($hash); ?>"/>
                <div class="fls_field_label is-required"><label
                        for="fls_field_verification"><?php _e('Verification Code', 'fluent-security'); ?></label></div>
                <div class="fs_input_wrap">
                    <input type="text" id="fls_field_verification" class="input"
                           placeholder="<?php _e('2FA Code', 'fluent-security'); ?>" name="_email_verification_token"
                           required></div>
            </div>
            <p class="submit">
                <button type="submit" class="button button-primary" id="fls_verification_submit">
                    <svg version="1.1" class="fls_loading_svg" x="0px" y="0px" width="40px" height="20px"
                         viewBox="0 0 50 50" style="enable-background:new 0 0 50 50;display: none;"
                         xml:space="preserve">
                    <path fill="currentColor"
                          d="M43.935,25.145c0-10.318-8.364-18.683-18.683-18.683c-10.318,0-18.683,8.365-18.683,18.683h4.068c0-8.071,6.543-14.615,14.615-14.615c8.072,0,14.615,6.543,14.615,14.615H43.935z">
                        <animateTransform attributeType="xml" attributeName="transform" type="rotate" from="0 25 25"
                                          to="360 25 25" dur="0.6s" repeatCount="indefinite"></animateTransform>
                    </path>
                </svg>
                    <span><?php _e('Complete Signup', 'fluent-security'); ?></span>
                </button>
            </p>
        </div>
        <?php
        return ob_get_clean();
    }

}
