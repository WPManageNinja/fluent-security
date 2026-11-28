<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Services\Turnstile;

/**
 * Puts the Turnstile widget on wp-login.php, on `wp_login_form()` and on WooCommerce's
 * My Account forms, and checks the token when those forms come back.
 *
 * FluentAuth's own shortcode forms do the same from CustomAuthHandler, where they are
 * built and answered.
 *
 * Each check runs only for the form it belongs to. `authenticate`, `lostpassword_post`
 * and `register_post` also fire for XML-RPC, Application Passwords, an administrator
 * sending a reset link from the Users screen, and other plugins' code - none of which
 * has a widget to answer.
 */
class TurnstileHandler
{
    public function register()
    {
        add_action('register_form', [$this, 'renderOnLoginPage']);
        add_action('register_post', [$this, 'checkRegistration'], 5, 3);

        // Before the passkey, magic link and social buttons, which start at 9.
        add_action('login_form', [$this, 'renderOnLoginPage'], 5);
        add_filter('login_form_middle', [$this, 'addToLoginForm'], 10, 2);
        add_action('lostpassword_form', [$this, 'renderOnLoginPage']);
        // After core checks the password at 20, so a pass there cannot override this.
        add_filter('authenticate', [$this, 'checkLogin'], 30, 1);
        add_action('lostpassword_post', [$this, 'checkLostPassword'], 10, 1);

        add_action('woocommerce_login_form', [$this, 'renderOnWooForm']);
        add_action('woocommerce_register_form', [$this, 'renderOnWooForm']);
        add_filter('woocommerce_process_login_errors', [$this, 'checkWooForm'], 10, 1);
        add_filter('woocommerce_process_registration_errors', [$this, 'checkWooForm'], 10, 1);
    }

    /**
     * The login, lost password and register screens of wp-login.php.
     *
     * @return void
     */
    public function renderOnLoginPage()
    {
        if (!did_action('login_init')) {
            return;
        }

        $place = current_action() === 'register_form' ? Turnstile::SIGNUP : Turnstile::LOGIN;

        $widget = Turnstile::widget($place);

        if (!$widget) {
            return;
        }

        /*
         * Turnstile is never narrower than 300px and this box has 270px inside it, so the
         * widget is drawn at 90%.
         */
        echo '<style>.login form .fls_turnstile { transform: scale(0.9); transform-origin: 0 0; height: 58px; }</style>';
        echo $widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    /**
     * `wp_login_form()`, and the login shortcode, which is built the same way.
     *
     * @param string $html
     * @param array $args
     * @return string
     */
    public function addToLoginForm($html, $args = [])
    {
        return $html . Turnstile::widget(Turnstile::LOGIN);
    }

    /**
     * Any password post to wp-login.php, whatever its `action`. Core sends
     * `entered_recovery_mode`, and any action a plugin registers, to the same login code,
     * so asking for `login_form_login` let a bot post a password past the widget.
     *
     * @param \WP_User|\WP_Error|null $user
     * @return \WP_User|\WP_Error|null
     */
    public function checkLogin($user)
    {
        if (!did_action('login_init') || empty($_POST['log'])) {
            return $user;
        }

        $result = Turnstile::check(Turnstile::LOGIN);

        if (is_wp_error($result)) {
            return new \WP_Error($result->get_error_code(), $this->withErrorPrefix($result));
        }

        return $user;
    }

    /**
     * @param \WP_Error $errors
     * @return void
     */
    public function checkLostPassword($errors)
    {
        if (!did_action('login_form_lostpassword') && !did_action('login_form_retrievepassword')) {
            return;
        }

        $result = Turnstile::check(Turnstile::LOGIN);

        if (is_wp_error($result)) {
            $errors->add($result->get_error_code(), $this->withErrorPrefix($result));
        }
    }

    /**
     * wp-login.php registration, with or without the secure signup form.
     *
     * The secure form's second post carries the emailed code instead, and the code is
     * what proves that one. Skipped only while that form is on: without it a bot could
     * post a made-up hash and WordPress would create the account.
     *
     * @param string $login
     * @param string $email
     * @param \WP_Error $errors
     * @return void
     */
    public function checkRegistration($login, $email, $errors)
    {
        if (!did_action('login_form_register')) {
            return;
        }

        if (!empty($_POST['_email_verification_hash']) && (new LoginCustomizerHandler())->isSecureSignupForm()) {
            return;
        }

        $result = Turnstile::check(Turnstile::SIGNUP);

        if (is_wp_error($result)) {
            $errors->add($result->get_error_code(), $this->withErrorPrefix($result));
        }
    }

    /**
     * @return void
     */
    public function renderOnWooForm()
    {
        echo Turnstile::widget(Turnstile::WOO); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    /**
     * WooCommerce adds its own "Error:" in front of the message.
     *
     * @param \WP_Error $errors
     * @return \WP_Error
     */
    public function checkWooForm($errors)
    {
        $result = Turnstile::check(Turnstile::WOO);

        if (is_wp_error($result) && $errors instanceof \WP_Error) {
            $errors->add($result->get_error_code(), $result->get_error_message());
        }

        return $errors;
    }

    /**
     * @param \WP_Error $error
     * @return string
     */
    private function withErrorPrefix($error)
    {
        return '<strong>' . esc_html__('Error:', 'fluent-security') . '</strong> ' . esc_html($error->get_error_message());
    }
}
