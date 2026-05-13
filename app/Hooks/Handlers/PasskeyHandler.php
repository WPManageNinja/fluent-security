<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\PasskeyCredentialRepository;
use FluentAuth\App\Services\PasskeyService;

class PasskeyHandler
{
    protected $assetsLoaded = false;

    public function register()
    {
        add_shortcode('fluent_auth_passkeys', [$this, 'passkeyManagementShortcode']);

        add_filter('login_form_bottom', [$this, 'pushPasskeyButtonToLoginForm'], 20, 2);
        add_action('login_form', [$this, 'pushPasskeyButtonToWpLogin']);
        add_action('login_enqueue_scripts', [$this, 'loadAssets']);
        add_action('fls_load_login_helper', [$this, 'loadAssets']);

        add_action('wp_ajax_fls_passkey_register_options', [$this, 'registerOptions']);
        add_action('wp_ajax_fls_passkey_register_verify', [$this, 'registerVerify']);
        add_action('wp_ajax_fls_passkey_list', [$this, 'listCredentials']);
        add_action('wp_ajax_fls_passkey_delete', [$this, 'deleteCredential']);

        add_action('wp_ajax_fls_passkey_login_options', [$this, 'loginOptions']);
        add_action('wp_ajax_nopriv_fls_passkey_login_options', [$this, 'loginOptions']);
        add_action('wp_ajax_fls_passkey_login_verify', [$this, 'loginVerify']);
        add_action('wp_ajax_nopriv_fls_passkey_login_verify', [$this, 'loginVerify']);
    }

    public function pushPasskeyButtonToLoginForm($content, $args)
    {
        if (!$this->canShowLoginButton()) {
            return $content;
        }

        $this->loadAssets();

        return $content . $this->getLoginButtonHtml();
    }

    public function pushPasskeyButtonToWpLogin()
    {
        if (!$this->canShowLoginButton()) {
            return;
        }

        $this->loadAssets();
        echo $this->getLoginButtonHtml(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    public function passkeyManagementShortcode($atts = [])
    {
        if (!get_current_user_id()) {
            return '<p>' . esc_html__('Please login to manage your passkeys.', 'fluent-security') . '</p>';
        }

        if (!PasskeyService::isAvailable()) {
            return '<p>' . esc_html__('Passkeys are not available on this site. Please use HTTPS to manage passkeys.', 'fluent-security') . '</p>';
        }

        $this->loadAssets();

        return '<div class="fls_passkey_manager" data-loaded="no">'
            . '<div class="fls_passkey_manager_header">'
            . '<h3>' . esc_html__('Passkeys', 'fluent-security') . '</h3>'
            . '<button type="button" class="button button-primary fls_passkey_register">'
            . esc_html__('Add Passkey', 'fluent-security')
            . '</button>'
            . '</div>'
            . '<div class="fls_passkey_messages"></div>'
            . '<div class="fls_passkey_list"></div>'
            . '</div>';
    }

    public function registerOptions()
    {
        $this->verifyNonce();

        if (!PasskeyService::isAvailable()) {
            $this->sendError(__('Passkeys are not available on this site.', 'fluent-security'));
        }

        $user = wp_get_current_user();
        $options = PasskeyService::getRegistrationOptions($user);

        $this->sendResponse($options);
    }

    public function registerVerify()
    {
        $this->verifyNonce();

        if (!PasskeyService::isAvailable()) {
            $this->sendError(__('Passkeys are not available on this site.', 'fluent-security'));
        }

        $payload = $this->getPayload();
        $result = PasskeyService::verifyRegistration($payload, wp_get_current_user());

        if (is_wp_error($result)) {
            $this->sendResponse($result);
        }

        wp_send_json([
            'message'     => __('Passkey has been registered successfully.', 'fluent-security'),
            'credentials' => $this->getFormattedCredentials(get_current_user_id())
        ]);
    }

    public function loginOptions()
    {
        $this->verifyNonce();

        if (!PasskeyService::isAvailable()) {
            $this->sendError(__('Passkeys are not available on this site.', 'fluent-security'));
        }

        $login = sanitize_text_field(Arr::get($_REQUEST, 'login', ''));
        $options = PasskeyService::getAuthenticationOptions($login);

        $this->sendResponse($options);
    }

    public function loginVerify()
    {
        $this->verifyNonce();

        if (!PasskeyService::isAvailable()) {
            $this->sendError(__('Passkeys are not available on this site.', 'fluent-security'));
        }

        $payload = $this->getPayload();
        $user = PasskeyService::verifyAuthentication($payload);

        if (is_wp_error($user)) {
            $login = sanitize_text_field(Arr::get($_REQUEST, 'login', 'passkey'));
            do_action('wp_login_failed', $login, $user);
            $this->sendResponse($user);
        }

        $canBypass2Fa = !apply_filters('fluent_auth/passkey_requires_2fa', false, $user);
        if (!$canBypass2Fa) {
            $this->sendError(__('Passkey login requires additional verification.', 'fluent-security'));
        }

        Helper::setLoginMedia('passkey');
        $loggedInUser = AuthService::makeLogin($user, 'passkey');

        if (is_wp_error($loggedInUser)) {
            $this->sendResponse($loggedInUser);
        }

        $redirectUrl = admin_url();
        $requestedRedirect = sanitize_url(Arr::get($_REQUEST, 'redirect_to', ''));
        if ($requestedRedirect) {
            $redirectUrl = Helper::getValidatedRedirectUrl($requestedRedirect, $redirectUrl);
        }

        $redirectUrl = apply_filters('login_redirect', $redirectUrl, false, $loggedInUser);
        $redirectUrl = apply_filters('fluent_auth/login_redirect_url', $redirectUrl, $loggedInUser, $_REQUEST);
        $redirectUrl = apply_filters('fluent_auth/passkey_login_redirect_url', $redirectUrl, $loggedInUser, $_REQUEST);

        wp_send_json([
            'redirect' => $redirectUrl
        ]);
    }

    public function listCredentials()
    {
        $this->verifyNonce();

        if (!get_current_user_id()) {
            $this->sendError(__('Please login to manage your passkeys.', 'fluent-security'), 403);
        }

        wp_send_json([
            'credentials' => $this->getFormattedCredentials(get_current_user_id())
        ]);
    }

    public function deleteCredential()
    {
        $this->verifyNonce();

        if (!get_current_user_id()) {
            $this->sendError(__('Please login to manage your passkeys.', 'fluent-security'), 403);
        }

        $id = absint(Arr::get($_REQUEST, 'credential_id'));
        if (!$id) {
            $this->sendError(__('Invalid passkey.', 'fluent-security'));
        }

        PasskeyCredentialRepository::delete($id, get_current_user_id());

        wp_send_json([
            'message'     => __('Passkey has been removed.', 'fluent-security'),
            'credentials' => $this->getFormattedCredentials(get_current_user_id())
        ]);
    }

    public function loadAssets()
    {
        if ($this->assetsLoaded || Helper::getSetting('passkeys') !== 'yes') {
            return;
        }

        $this->assetsLoaded = true;

        wp_enqueue_script('fluent_auth_passkey', FLUENT_AUTH_PLUGIN_URL . 'dist/public/passkey.js', [], FLUENT_AUTH_VERSION, true);
        wp_localize_script('fluent_auth_passkey', 'fluentAuthPasskey', [
            'ajax_url'        => admin_url('admin-ajax.php'),
            'nonce'           => wp_create_nonce('fluent_auth_passkey_nonce'),
            'available'       => PasskeyService::isAvailable() ? 'yes' : 'no',
            'is_logged_in'    => get_current_user_id() ? 'yes' : 'no',
            'userVerification'=> PasskeyService::getUserVerification(),
            'i18n'            => [
                'notSupported'      => __('Your browser does not support passkeys.', 'fluent-security'),
                'notAvailable'      => __('Passkeys require HTTPS or localhost.', 'fluent-security'),
                'loginFailed'       => __('Passkey login failed. Please try again.', 'fluent-security'),
                'registerFailed'    => __('Passkey registration failed. Please try again.', 'fluent-security'),
                'confirmDelete'     => __('Are you sure you want to remove this passkey?', 'fluent-security'),
                'emptyPasskeys'     => __('No passkeys have been registered yet.', 'fluent-security'),
                'passkeyRegistered' => __('Passkey has been registered successfully.', 'fluent-security')
            ]
        ]);
    }

    private function getLoginButtonHtml()
    {
        return '<div class="fls_passkey_login_wrap">'
            . '<button type="button" class="button fls_passkey_login_btn">'
            . esc_html__('Login with passkey', 'fluent-security')
            . '</button>'
            . '<div class="fls_passkey_message" aria-live="polite"></div>'
            . '</div>';
    }

    private function canShowLoginButton()
    {
        if (get_current_user_id()) {
            return false;
        }

        return Helper::getSetting('passkeys') === 'yes'
            && Helper::getSetting('passkey_login_button') === 'yes'
            && apply_filters('fluent_auth/passkey_show_login_button', true);
    }

    private function getFormattedCredentials($userId)
    {
        $credentials = [];
        foreach (PasskeyCredentialRepository::getByUserId($userId) as $credential) {
            $credentials[] = PasskeyCredentialRepository::formatCredential($credential);
        }

        return $credentials;
    }

    private function verifyNonce()
    {
        if (!wp_verify_nonce(Arr::get($_REQUEST, '_nonce'), 'fluent_auth_passkey_nonce')) {
            $this->sendError(__('Security verification failed. Please refresh the page and try again.', 'fluent-security'), 403);
        }
    }

    private function getPayload()
    {
        $payload = Arr::get($_REQUEST, 'payload', '');
        if (is_string($payload)) {
            $payload = json_decode(wp_unslash($payload), true);
        }

        return is_array($payload) ? $payload : [];
    }

    private function sendResponse($response)
    {
        if (is_wp_error($response)) {
            $status = (int)Arr::get($response->get_error_data(), 'status', 422);
            wp_send_json([
                'message' => $response->get_error_message(),
                'code'    => $response->get_error_code()
            ], $status ?: 422);
        }

        wp_send_json($response);
    }

    private function sendError($message, $status = 422)
    {
        wp_send_json([
            'message' => $message
        ], $status);
    }
}
