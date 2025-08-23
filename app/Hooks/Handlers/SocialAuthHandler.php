<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\FacebookAuthService;
use FluentAuth\App\Services\GithubAuthService;
use FluentAuth\App\Services\GoogleAuthService;
use FluentAuth\App\Helpers\Arr;

class SocialAuthHandler
{
    private $cssLoaded = false;
    private $redirectIntent = '';

    public function register()
    {
        add_action('login_init', [$this, 'maybeSocialAuth'], 1);
        add_action('login_form', [$this, 'pushLoginWithButtons']);
        add_action('register_form', [$this, 'pushRegisterWithButtons']);
        add_shortcode('fs_auth_buttons', [$this, 'socialAuthShortcode']);

        add_filter('login_form_bottom', [$this, 'maybePushToCustomForm']);

        add_filter('fluent_support/before_registration_form_close', [$this, 'maybePushRegistrationField']);
        add_filter('fluent_auth/after_registration_form_close', [$this, 'maybePushRegistrationField']);
    }

    public function maybeSocialAuth()
    {
        $provider = false;

        if (!empty($_GET['fs_auth'])) {
            $provider = sanitize_text_field($_GET['fs_auth']);
        } elseif (!empty($_GET['state']) && !empty($_GET['code'])) {

            $provider = 'google';

            $referrer = wp_get_referer();
            if ($referrer && strpos($referrer, 'facebook.com') !== false) {
                $provider = 'facebook';
            }
        }


        if (!$provider) {
            return false;
        }

        if (!$this->isEnabled()) {
            return false;
        }

        if (isset($_GET['intent_redirect_to'])) {
            \setcookie('fs_intent_redirect', $_GET['intent_redirect_to'], time() + 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl());  /* expire in 1 hour */
        }

        $provider = Arr::get($_GET, 'fs_auth', $provider);

        switch ($provider) {
            case 'github':
                if (!$this->isEnabled('github')) {
                    return false;
                }
                return $this->handleGitHubActions($_REQUEST);

            case 'google':
                if (!$this->isEnabled('google')) {
                    return false;
                }
                return $this->handleGoogleActions($_REQUEST);

            case 'facebook':
                if (!$this->isEnabled('facebook')) {
                    return false;
                }
                return $this->handleFacebookActions($_REQUEST);
        }
        return false;

    }

    private function handleGitHubActions($data)
    {
        $actionType = Arr::get($data, 'fs_type');

        if ($actionType === 'redirect' || empty($data['code'])) {
            return $this->redirectToGithub();
        }

        if (isset($data['code'])) {
            $redirectUrl = $this->handleGithubConfirm($data);
            if ($redirectUrl && !is_wp_error($redirectUrl)) {
                wp_redirect($redirectUrl);
                exit();
            }

            add_filter('wp_login_errors', function ($errors) use ($redirectUrl) {
                return $redirectUrl;
            });
        }
    }

    private function handleGoogleActions($data)
    {
        $actionType = Arr::get($data, 'fs_type');

        if ($actionType === 'redirect') {
            return $this->redirectToGoogle();
        }

        if (!empty($data['code'])) {
            $redirectUrl = $this->handleGoogleConfirm($data);
            if ($redirectUrl && !is_wp_error($redirectUrl)) {
                wp_redirect($redirectUrl);
                exit();
            }

            // Handle the error here
            add_filter('wp_login_errors', function ($errors) use ($redirectUrl) {
                return $redirectUrl;
            });
        }
    }

    private function handleFacebookActions($data)
    {
        $actionType = Arr::get($data, 'fs_type');

        if ($actionType === 'redirect' || empty($data['code'])) {
            return $this->redirectToFacebook();
        }

        if (isset($data['code'])) {
            $redirectUrl = $this->handleFacebookConfirm($data);
            if ($redirectUrl && !is_wp_error($redirectUrl)) {
                wp_redirect($redirectUrl);
                exit();
            }

            add_filter('wp_login_errors', function ($errors) use ($redirectUrl) {
                return $redirectUrl;
            });
        }
    }

    private function redirectToGithub()
    {
        $url = GithubAuthService::getAuthRedirect(AuthService::setStateToken());
        wp_redirect($url);
        exit();
    }

    private function redirectToGoogle()
    {
        $url = GoogleAuthService::getAuthRedirect(AuthService::setStateToken());
        wp_redirect($url);
        exit();
    }

    private function redirectToFacebook()
    {
        $url = FacebookAuthService::getAuthRedirect(AuthService::setStateToken());
        wp_redirect($url);
        exit();
    }

    private function handleGithubConfirm($data)
    {
        $state = Arr::get($data, 'state');
        if (!$state || $state != AuthService::getStateToken()) {
            return new \WP_Error('state_mismatch', __('Sorry! we could not authenticate you via github', 'fluent-security'));
        }

        $token = GithubAuthService::getTokenByCode(Arr::get($data, 'code'));
        $userData = GithubAuthService::getDataByAccessToken($token);

        if (is_wp_error($userData)) {
            return $userData;
        }

        if (is_user_logged_in()) {
            $existingUser = get_user_by('ID', get_current_user_id());
            if ($existingUser->user_email !== $data['email']) {
                return new \WP_Error('email_mismatch', __('Your Github email address does not match with your current account email address. Please use the same email address', 'fluent-security'));
            }
        }

        if (empty($userData['email']) || !is_email($userData['email'])) {
            return new \WP_Error('email_error', __('Sorry! we could not find your valid email via github', 'fluent-security'));
        }

        $existingUser = get_user_by('email', $userData['email']);
        if ($existingUser) {
            $twoFaHandler = new TwoFaHandler();
            if ($redirectUrl = $twoFaHandler->sendAndGet2FaConfirmFormUrl($existingUser)) {
                wp_redirect($redirectUrl);
                exit();
            }
        }

        $user = AuthService::doUserAuth($userData, 'github');

        if (is_wp_error($user)) {
            return $user;
        }

        $intentRedirectTo = '';
        if (isset($_COOKIE['fs_intent_redirect'])) {
            $redirect_to = sanitize_url(urldecode($_COOKIE['fs_intent_redirect']));
            $intentRedirectTo = $redirect_to;
        } else {
            if (is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin($user->ID)) {
                $redirect_to = user_admin_url();
            } elseif (is_multisite() && !$user->has_cap('read')) {
                $redirect_to = get_dashboard_url($user->ID);
            } elseif (!$user->has_cap('edit_posts')) {
                $redirect_to = $user->has_cap('read') ? admin_url('profile.php') : home_url();
            } else {
                $redirect_to = admin_url();
            }
        }

        update_user_meta($user->ID, '_fls_login_github', $userData['username']);

        return apply_filters('login_redirect', $redirect_to, $intentRedirectTo, $user);
    }

    private function handleGoogleConfirm($data)
    {
        $state = Arr::get($data, 'state');
        if (!$state || $state != AuthService::getStateToken()) {
            return new \WP_Error('state_mismatch', __('Sorry! we could not authenticate you via google', 'fluent-security'));
        }

        $token = GoogleAuthService::getTokenByCode(Arr::get($data, 'code'));

        if (is_wp_error($token)) {
            return $token;
        }

        $userData = GoogleAuthService::getDataByIdToken($token);

        if (is_wp_error($userData)) {
            return $userData;
        }

        if (is_user_logged_in()) {
            $existingUser = get_user_by('ID', get_current_user_id());
            if ($existingUser->user_email !== $userData['email']) {
                return new \WP_Error('email_mismatch', __('Your Google email address does not match with your current account email address. Please use the same email address', 'fluent-security'));
            }
        }

        if (empty($userData['email']) || !is_email($userData['email'])) {
            return new \WP_Error('email_error', __('Sorry! we could not find your valid email from Google API', 'fluent-security'));
        }

        $existingUser = get_user_by('email', $userData['email']);
        if ($existingUser) {
            $twoFaHandler = new TwoFaHandler();
            if ($redirectUrl = $twoFaHandler->sendAndGet2FaConfirmFormUrl($existingUser)) {
                wp_redirect($redirectUrl);
                exit();
            }
        }

        $user = AuthService::doUserAuth($userData, 'google');

        if (is_wp_error($user)) {
            return $user;
        }

        $intentRedirectTo = '';
        if (isset($_COOKIE['fs_intent_redirect'])) {
            $redirect_to = esc_url($_COOKIE['fs_intent_redirect']);
            $intentRedirectTo = $redirect_to;
        } else {
            if (is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin($user->ID)) {
                $redirect_to = user_admin_url();
            } elseif (is_multisite() && !$user->has_cap('read')) {
                $redirect_to = get_dashboard_url($user->ID);
            } elseif (!$user->has_cap('edit_posts')) {
                $redirect_to = $user->has_cap('read') ? admin_url('profile.php') : home_url();
            } else {
                $redirect_to = admin_url();
            }
        }

        update_user_meta($user->ID, '_fls_login_google', $userData['email']);

        return apply_filters('login_redirect', $redirect_to, $intentRedirectTo, $user);
    }

    private function handleFacebookConfirm($data)
    {
        $state = Arr::get($data, 'state');
        if (!$state || $state != AuthService::getStateToken()) {
            return new \WP_Error('state_mismatch', __('Sorry! we could not authenticate you via Facebook', 'fluent-security'));
        }

        $token = FacebookAuthService::getTokenByCode(Arr::get($data, 'code'));

        if (is_wp_error($token)) {
            return $token;
        }

        $userData = FacebookAuthService::getDataByAccessToken($token);


        if (is_wp_error($userData)) {
            return $userData;
        }

        if (is_user_logged_in()) {
            $existingUser = get_user_by('ID', get_current_user_id());
            if ($existingUser->user_email !== $userData['email']) {
                return new \WP_Error('email_mismatch', __('Your Facebook email address does not match with your current account email address. Please use the same email address', 'fluent-security'));
            }
        }

        if (empty($userData['email']) || !is_email($userData['email'])) {
            return new \WP_Error('email_error', __('Sorry! we could not find your valid email from Facebook API', 'fluent-security'));
        }

        $existingUser = get_user_by('email', $userData['email']);
        if ($existingUser) {
            $twoFaHandler = new TwoFaHandler();
            if ($redirectUrl = $twoFaHandler->sendAndGet2FaConfirmFormUrl($existingUser)) {
                wp_redirect($redirectUrl);
                exit();
            }
        }

        $user = AuthService::doUserAuth($userData, 'facebook');

        if (is_wp_error($user)) {
            return $user;
        }

        $intentRedirectTo = '';
        if (isset($_COOKIE['fs_intent_redirect'])) {
            $redirect_to = esc_url($_COOKIE['fs_intent_redirect']);
            $intentRedirectTo = $redirect_to;
        } else {
            if (is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin($user->ID)) {
                $redirect_to = user_admin_url();
            } elseif (is_multisite() && !$user->has_cap('read')) {
                $redirect_to = get_dashboard_url($user->ID);
            } elseif (!$user->has_cap('edit_posts')) {
                $redirect_to = $user->has_cap('read') ? admin_url('profile.php') : home_url();
            } else {
                $redirect_to = admin_url();
            }
        }

        update_user_meta($user->ID, '_fls_login_facebook', $userData['email']);

        return apply_filters('login_redirect', $redirect_to, $intentRedirectTo, $user);
    }

    public function pushLoginWithButtons()
    {
        if (!$this->isEnabled()) {
            return '';
        }

        if ($this->redirectIntent) {
            $redirect_to = $this->redirectIntent;
        } else if (isset($_REQUEST['redirect_to'])) {
            $redirect_to = $_REQUEST['redirect_to'];
        } else {
            $redirect_to = admin_url();
        }

        $redirect_to = apply_filters('fluent_auth/social_redirect_to', $redirect_to);

        $buttons = [
            'google'   => [
                'link_class' => 'fs_auth_btn fs_auth_google',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg"  viewBox="0 0 48 48" width="24px" height="24px"><path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12c0-6.627,5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24c0,11.045,8.955,20,20,20c11.045,0,20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z"/><path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z"/><path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z"/><path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571c0.001-0.001,0.002-0.001,0.003-0.002l6.19,5.238C36.971,39.205,44,34,44,24C44,22.659,43.862,21.35,43.611,20.083z"/></svg>',
                'title'      => __('Login with Google', 'fluent-security'),
                'url'        => add_query_arg([
                    'fs_auth'            => 'google',
                    'fs_type'            => 'redirect',
                    'intent_redirect_to' => urlencode($redirect_to)
                ], wp_login_url())
            ],
            'github'   => [
                'link_class' => 'fs_auth_btn fs_auth_github',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" role="img" aria-labelledby="ahu5wq2nrtsicu3szbxaract8as7mhww" aria-hidden="true" class="crayons-icon"><title id="ahu5wq2nrtsicu3szbxaract8as7mhww">github</title><path d="M12 2C6.475 2 2 6.475 2 12a9.994 9.994 0 006.838 9.488c.5.087.687-.213.687-.476 0-.237-.013-1.024-.013-1.862-2.512.463-3.162-.612-3.362-1.175-.113-.288-.6-1.175-1.025-1.413-.35-.187-.85-.65-.013-.662.788-.013 1.35.725 1.538 1.025.9 1.512 2.338 1.087 2.912.825.088-.65.35-1.087.638-1.337-2.225-.25-4.55-1.113-4.55-4.938 0-1.088.387-1.987 1.025-2.688-.1-.25-.45-1.275.1-2.65 0 0 .837-.262 2.75 1.026a9.28 9.28 0 012.5-.338c.85 0 1.7.112 2.5.337 1.912-1.3 2.75-1.024 2.75-1.024.55 1.375.2 2.4.1 2.65.637.7 1.025 1.587 1.025 2.687 0 3.838-2.337 4.688-4.562 4.938.362.312.675.912.675 1.85 0 1.337-.013 2.412-.013 2.75 0 .262.188.574.688.474A10.016 10.016 0 0022 12c0-5.525-4.475-10-10-10z"></path></svg>',
                'title'      => __('Login with Github', 'fluent-security'),
                'url'        => add_query_arg([
                    'fs_auth'            => 'github',
                    'fs_type'            => 'redirect',
                    'intent_redirect_to' => urlencode($redirect_to)
                ], wp_login_url())
            ],
            'facebook' => [
                'link_class' => 'fs_auth_btn fs_auth_facebook',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="#4267B2"><path d="M22.675 0h-21.35c-.732 0-1.325.593-1.325 1.325v21.351c0 .731.593 1.324 1.325 1.324h11.495v-9.294h-3.128v-3.622h3.128v-2.671c0-3.1 1.893-4.788 4.659-4.788 1.325 0 2.463.099 2.795.143v3.24l-1.918.001c-1.504 0-1.795.715-1.795 1.763v2.313h3.587l-.467 3.622h-3.12v9.293h6.116c.73 0 1.323-.593 1.323-1.325v-21.35c0-.732-.593-1.325-1.325-1.325z"/></svg>',
                'title'      => __('Login with Facebook', 'fluent-security'),
                'url'        => add_query_arg([
                    'fs_auth'            => 'facebook',
                    'fs_type'            => 'redirect',
                    'intent_redirect_to' => urlencode($redirect_to)
                ], wp_login_url())
            ]
        ];

        if (!$this->isEnabled('google')) {
            unset($buttons['google']);
        }

        if (!$this->isEnabled('github')) {
            unset($buttons['github']);
        }
        if (!$this->isEnabled('facebook')) {
            unset($buttons['facebook']);
        }

        $this->loadButtons($buttons);
        $this->loadJs('loginform');
        $this->loadCss();
    }

    public function maybePushToCustomForm($html)
    {
        if (!$this->isEnabled()) {
            return $html;
        }

        ob_start();
        $this->pushLoginWithButtons();
        $newHtml = ob_get_clean();

        return $html . $newHtml;
    }

    public function pushRegisterWithButtons()
    {
        if (!$this->isEnabled()) {
            return '';
        }

        $this->initSignupButtonLoads('fm_login_with_wrap', 'none');

        $this->loadJs('registerform');
        $this->loadCss();
    }

    public function maybePushRegistrationField($html)
    {
        if (!$this->isEnabled()) {
            return $html;
        }

        ob_start();
        $this->initSignupButtonLoads();
        $content = ob_get_clean();

        return $html . $content;
    }

    private function initSignupButtonLoads($selector = 'fm_signup_with_wrap', $display = 'block')
    {
        $buttons = [
            'google'   => [
                'link_class' => 'fs_auth_btn fs_auth_google',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg"  viewBox="0 0 48 48" width="24px" height="24px"><path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12c0-6.627,5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24c0,11.045,8.955,20,20,20c11.045,0,20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z"/><path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z"/><path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z"/><path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571c0.001-0.001,0.002-0.001,0.003-0.002l6.19,5.238C36.971,39.205,44,34,44,24C44,22.659,43.862,21.35,43.611,20.083z"/></svg>',
                'title'      => __('Signup with Google', 'fluent-security'),
                'url'        => add_query_arg([
                    'fs_auth' => 'google',
                    'fs_type' => 'redirect'
                ], wp_login_url())
            ],
            'github'   => [
                'link_class' => 'fs_auth_btn fs_auth_github',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" role="img" aria-labelledby="ahu5wq2nrtsicu3szbxaract8as7mhww" aria-hidden="true" class="crayons-icon"><title id="ahu5wq2nrtsicu3szbxaract8as7mhww">github</title><path d="M12 2C6.475 2 2 6.475 2 12a9.994 9.994 0 006.838 9.488c.5.087.687-.213.687-.476 0-.237-.013-1.024-.013-1.862-2.512.463-3.162-.612-3.362-1.175-.113-.288-.6-1.175-1.025-1.413-.35-.187-.85-.65-.013-.662.788-.013 1.35.725 1.538 1.025.9 1.512 2.338 1.087 2.912.825.088-.65.35-1.087.638-1.337-2.225-.25-4.55-1.113-4.55-4.938 0-1.088.387-1.987 1.025-2.688-.1-.25-.45-1.275.1-2.65 0 0 .837-.262 2.75 1.026a9.28 9.28 0 012.5-.338c.85 0 1.7.112 2.5.337 1.912-1.3 2.75-1.024 2.75-1.024.55 1.375.2 2.4.1 2.65.637.7 1.025 1.587 1.025 2.687 0 3.838-2.337 4.688-4.562 4.938.362.312.675.912.675 1.85 0 1.337-.013 2.412-.013 2.75 0 .262.188.574.688.474A10.016 10.016 0 0022 12c0-5.525-4.475-10-10-10z"></path></svg>',
                'title'      => __('Signup with Github', 'fluent-security'),
                'url'        => add_query_arg([
                    'fs_auth' => 'github',
                    'fs_type' => 'redirect'
                ], wp_login_url())
            ],
            'facebook' => [
                'link_class' => 'fs_auth_btn fs_auth_facebook',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="#4267B2"><path d="M22.675 0h-21.35c-.732 0-1.325.593-1.325 1.325v21.351c0 .731.593 1.324 1.325 1.324h11.495v-9.294h-3.128v-3.622h3.128v-2.671c0-3.1 1.893-4.788 4.659-4.788 1.325 0 2.463.099 2.795.143v3.24l-1.918.001c-1.504 0-1.795.715-1.795 1.763v2.313h3.587l-.467 3.622h-3.12v9.293h6.116c.73 0 1.323-.593 1.323-1.325v-21.35c0-.732-.593-1.325-1.325-1.325z"/></svg>',
                'title'      => __('Signup with Facebook', 'fluent-security'),
                'url'        => add_query_arg([
                    'fs_auth' => 'facebook',
                    'fs_type' => 'redirect'
                ], wp_login_url())
            ]
        ];

        if (!$this->isEnabled('google')) {
            unset($buttons['google']);
        }

        if (!$this->isEnabled('github')) {
            unset($buttons['github']);
        }
        if (!$this->isEnabled('facebook')) {
            unset($buttons['facebook']);
        }

        $this->loadButtons($buttons, $selector, $display);

        $this->loadCss();
    }

    private function loadButtons($buttons, $selector = 'fm_login_with_wrap', $display = 'none')
    {
        ?>
        <div style="display: <?php echo esc_attr($display); ?>;" id="<?php echo esc_attr($selector); ?>"
             class="fm_login_with">
            <div class="fm_buttons_wrap">
                <?php foreach ($buttons as $button): ?>
                    <a class="<?php echo esc_attr($button['link_class']); ?>"
                       href="<?php echo esc_url($button['url']); ?>">
                        <?php echo Arr::get($button, 'icon'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                        <?php echo $button['title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
        <?php
    }

    private function loadJs($selector)
    {
        ?>
        <script type="text/javascript">
            document.addEventListener("DOMContentLoaded", () => {
                document.getElementById('<?php echo esc_attr($selector); ?>').append(document.getElementById("fm_login_with_wrap"));
                document.getElementById("fm_login_with_wrap").style.display = "";
            });
        </script>
        <?php
    }

    public function loadCss()
    {
        if ($this->cssLoaded) {
            return false;
        }
        $this->cssLoaded = true;
        ?>
        <style>
            #login form p.submit {
                overflow: hidden;
            }

            .fm_login_with {
                display: block;
                width: 100%;
                overflow: hidden;
                border-top: 1px solid #c3c4c7;
                margin-top: 20px;
                padding-top: 20px;
                clear: both;
            }

            .fs_auth_btn {
                white-space: nowrap !important;
                flex-grow: 1 !important;
                background-color: #24292e;
                color: #fff;
                text-decoration: none !important;
                padding: 5px 10px;
                line-height: 1;
                vertical-align: top;
                display: flex;
                align-items: center;
                border-radius: 5px;
                justify-content: center;
                margin-bottom: 10px;
            }

            a.fs_auth_btn.fs_auth_google {
                color: #24292e;
                background: white;
                border: 1px solid #23292f;
            }

            .fs_auth_btn svg {
                margin-right: 5px;
            }

            .fs_auth_btn.fs_auth_github svg {
                fill: white;
            }

            .fs_auth_btn.fs_auth_github:hover {
                background: black;
                color: white;
            }

            .fs_auth_btn.fs_auth_google:hover {
                background: white;
                color: black;
            }

            .fs_auth_btn.fs_auth_facebook {
                background-color: #4267B2;
                color: white;
                border: 1px solid #4267B2;
            }

            .fs_auth_btn.fs_auth_facebook:hover {
                background-color: white;
                color: #365899;
            }

            .fs_auth_btn.fs_auth_facebook svg {
                fill: white !important;
            }

            .fs_auth_btn.fs_auth_facebook:hover svg {
                fill: #4267B2 !important;
            }

        </style>
        <?php
    }

    public function socialAuthShortcode($atts, $content = '')
    {
        if (is_user_logged_in()) {
            return '';
        }

        if (!$this->isEnabled()) {
            return '';
        }

        $data = shortcode_atts(array(
            'title'        => __('Login or Signup', 'fluent-security'),
            'title_prefix' => __('Connect with', 'fluent-security'),
            'redirect'     => ''
        ), $atts);

        if (empty($data['redirect'])) {
            $data['redirect'] = get_permalink();
        }

        $buttons = [
            'google'   => [
                'link_class' => 'fs_auth_btn fs_auth_google',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg"  viewBox="0 0 48 48" width="24px" height="24px"><path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12c0-6.627,5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24c0,11.045,8.955,20,20,20c11.045,0,20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z"/><path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z"/><path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z"/><path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571c0.001-0.001,0.002-0.001,0.003-0.002l6.19,5.238C36.971,39.205,44,34,44,24C44,22.659,43.862,21.35,43.611,20.083z"/></svg>',
                'title'      => sprintf(__('%s Google', 'fluent-security'), $data['title_prefix']),
                'url'        => add_query_arg([
                    'fs_auth'            => 'google',
                    'fs_type'            => 'redirect',
                    'intent_redirect_to' => urlencode($data['redirect'])
                ], wp_login_url())
            ],
            'github'   => [
                'link_class' => 'fs_auth_btn fs_auth_github',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" role="img" aria-labelledby="ahu5wq2nrtsicu3szbxaract8as7mhww" aria-hidden="true" class="crayons-icon"><title id="ahu5wq2nrtsicu3szbxaract8as7mhww">github</title><path d="M12 2C6.475 2 2 6.475 2 12a9.994 9.994 0 006.838 9.488c.5.087.687-.213.687-.476 0-.237-.013-1.024-.013-1.862-2.512.463-3.162-.612-3.362-1.175-.113-.288-.6-1.175-1.025-1.413-.35-.187-.85-.65-.013-.662.788-.013 1.35.725 1.538 1.025.9 1.512 2.338 1.087 2.912.825.088-.65.35-1.087.638-1.337-2.225-.25-4.55-1.113-4.55-4.938 0-1.088.387-1.987 1.025-2.688-.1-.25-.45-1.275.1-2.65 0 0 .837-.262 2.75 1.026a9.28 9.28 0 012.5-.338c.85 0 1.7.112 2.5.337 1.912-1.3 2.75-1.024 2.75-1.024.55 1.375.2 2.4.1 2.65.637.7 1.025 1.587 1.025 2.687 0 3.838-2.337 4.688-4.562 4.938.362.312.675.912.675 1.85 0 1.337-.013 2.412-.013 2.75 0 .262.188.574.688.474A10.016 10.016 0 0022 12c0-5.525-4.475-10-10-10z"></path></svg>',
                'title'      => sprintf(__('%s Github', 'fluent-security'), $data['title_prefix']),
                'url'        => add_query_arg([
                    'fs_auth'            => 'github',
                    'fs_type'            => 'redirect',
                    'intent_redirect_to' => urlencode($data['redirect'])
                ], wp_login_url())
            ],
            'facebook' => [
                'link_class' => 'fs_auth_btn fs_auth_facebook',
                'icon'       => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M22.675 0h-21.35c-.732 0-1.325.593-1.325 1.325v21.351c0 .731.593 1.324 1.325 1.324h11.495v-9.294h-3.128v-3.622h3.128v-2.671c0-3.1 1.893-4.788 4.659-4.788 1.325 0 2.463.099 2.795.143v3.24l-1.918.001c-1.504 0-1.795.715-1.795 1.763v2.313h3.587l-.467 3.622h-3.12v9.293h6.116c.73 0 1.323-.593 1.323-1.325v-21.35c0-.732-.593-1.325-1.325-1.325z"/></svg>',
                'title'      => sprintf(__('%s Facebook', 'fluent-security'), $data['title_prefix']),
                'url'        => add_query_arg([
                    'fs_auth'            => 'facebook',
                    'fs_type'            => 'redirect',
                    'intent_redirect_to' => urlencode($data['redirect'])
                ], wp_login_url())
            ]
        ];

        if (!$this->isEnabled('google')) {
            unset($buttons['google']);
        }

        if (!$this->isEnabled('github')) {
            unset($buttons['github']);
        }
        if (!$this->isEnabled('facebook')) {
            unset($buttons['facebook']);
        }

        ?>

        <div class="fm_login_wrapper">
            <?php if ($data['title']): ?>
                <h3><?php echo esc_attr($data['title']); ?></h3>
            <?php endif; ?>
            <?php echo wp_kses_post($content); ?>
            <div class="fm_buttons_wrap">
                <?php foreach ($buttons as $button): ?>
                    <a class="<?php echo esc_attr($button['link_class']); ?>"
                       href="<?php echo esc_url($button['url']); ?>">
                        <?php echo Arr::get($button, 'icon'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped  ?>
                        <?php echo esc_html($button['title']); ?>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>

        <style>
            .fm_login_wrapper {
                padding: 20px;
                max-width: 600px !important;
                margin: 0 auto;
                text-align: center;
            }

            .fs_auth_btn {
                white-space: nowrap !important;
                flex-grow: 1 !important;
                background-color: #24292e;
                color: #fff;
                text-decoration: none;
                padding: 5px 10px;
                line-height: 1;
                vertical-align: top;
                display: flex;
                align-items: center;
                border-radius: 5px;
                justify-content: center;
                margin-bottom: 10px;
            }

            a.fs_auth_btn.fs_auth_google {
                color: #24292e;
                background: white;
                border: 1px solid #23292f;
            }

            .fs_auth_btn svg {
                margin-right: 5px;
            }

            .fs_auth_btn.fs_auth_github svg {
                fill: white;
            }

            .fs_auth_btn.fs_auth_github:hover {
                background: black;
                color: white;
            }

            .fs_auth_btn.fs_auth_google:hover {
                background: white;
                color: black;
            }

            .fs_buttons_wrap {
                display: flex;
            }

            .fs_buttons_wrap a {
                margin: 10px;
            }

            .fs_auth_btn.fs_auth_facebook {
                background-color: #4267B2;
                color: white;
            }

            .fs_auth_btn.fs_auth_facebook:hover {
                background-color: white;
                color: #365899;
            }

            .fs_auth_btn.fs_auth_facebook svg {
                fill: white !important;
            }

            .fs_auth_btn.fs_auth_facebook:hover svg {
                fill: #365899 !important;
            }

            @media only screen and (max-width: 600px) {
                .fs_buttons_wrap {
                    display: flex;
                    flex-wrap: wrap;
                    flex-direction: column;
                }
            }
        </style>

        <?php
    }

    private function isEnabled($module = '')
    {
        $settings = Helper::getSocialAuthSettings('edit');

        if ($settings['enabled'] !== 'yes') {
            return false;
        }

        if ($module && $settings['enable_' . $module] !== 'yes') {
            return false;
        }

        return true;
    }

}
