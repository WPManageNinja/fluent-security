<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\PasskeyLogin;

/**
 * The passkey button on the login form, and the two calls behind it.
 *
 * Rendered with the other ways in - above the magic link, below the password form - so
 * the page reads as one form and then a list of alternatives to it, rather than as three
 * separate offers stacked on top of each other.
 *
 * Nothing here is posted with the form it sits inside: the button is type=button, the
 * ceremony runs over admin-ajax and the browser is redirected on success.
 */
class PasskeyLoginHandler
{
    const NONCE_ACTION = 'fluent_auth_passkey_login';

    const CHALLENGE_ACTION = 'fluent_auth_passkey_challenge';

    const VERIFY_ACTION = 'fluent_auth_passkey_verify';

    /**
     * Whether the block has already gone out in this request.
     *
     * A page can hold the wp-login.php form and a `wp_login_form()` shortcode at once,
     * and two copies would mean two elements sharing every id the script looks up.
     */
    private $rendered = false;

    public function register()
    {
        /*
         * Priority 9, which is what puts this above the magic link: MagicLoginHandler and
         * SocialAuthHandler both take these two hooks at the default 10, so anything
         * lower lands first and the alternatives keep the order the settings screen
         * lists them in.
         */
        add_action('login_form', [$this, 'maybeRenderOnLoginPage'], 9);
        add_filter('login_form_bottom', [$this, 'maybeRenderOnCustomForm'], 9, 2);

        add_action('wp_ajax_nopriv_' . self::CHALLENGE_ACTION, [$this, 'handleChallenge']);
        add_action('wp_ajax_nopriv_' . self::VERIFY_ACTION, [$this, 'handleVerify']);
    }

    /**
     * wp-login.php, in the run of alternatives under the password form.
     *
     * @return void
     */
    public function maybeRenderOnLoginPage()
    {
        if (!$this->isDefaultLoginScreen()) {
            return;
        }

        echo $this->render(true); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    /**
     * The same block for a `wp_login_form()` form, which has its own bottom hook.
     *
     * @param $html string
     * @param $args array
     * @return string
     */
    public function maybeRenderOnCustomForm($html, $args = [])
    {
        return $html . $this->render();
    }

    /**
     * Whether this request is the plain "sign in" screen.
     *
     * Every other screen login_header() serves - registration, a lost password, and in
     * particular the second factor challenge, which has a passkey form of its own -
     * would be the wrong place to offer a way of starting a login over.
     *
     * @return bool
     */
    private function isDefaultLoginScreen()
    {
        if (!did_action('login_init')) {
            return false;
        }

        $action = isset($_REQUEST['action']) ? sanitize_text_field(wp_unslash($_REQUEST['action'])) : 'login';

        if ($action === '') {
            $action = 'login';
        }

        if ($action !== 'login') {
            return false;
        }

        // `?checkemail=` and friends are still action=login, but nobody is signing in on them.
        return empty($_REQUEST['checkemail']) && empty($_REQUEST['interim-login']);
    }

    /**
     * @return string
     */
    private function render($move = false)
    {
        if ($this->rendered || !PasskeyLogin::isPrimaryLoginEnabled()) {
            return '';
        }

        $this->rendered = true;

        /*
         * The ceremony is in login_helper.js, so the button is useless without it. This
         * is the same action the second factor screen raises; CustomAuthHandler answers
         * it once per request, so asking again where the file is already on the page
         * costs nothing.
         *
         * Raised here rather than on `login_enqueue_scripts` because this block is also
         * rendered into a `wp_login_form()` form on an ordinary page, which never fires
         * that hook. Enqueuing this late lands the file in the footer, which is where
         * it wants to be anyway: magic login enqueues its own script on the hook after
         * this one, so ours is parsed first and its DOMContentLoaded listener runs
         * first, which is what keeps the magic link below the passkey button.
         */
        do_action('fls_load_login_helper');

        $redirectTo = isset($_REQUEST['redirect_to'])
            ? esc_url_raw(wp_unslash($_REQUEST['redirect_to']))
            : '';

        $strings = [
            'unsupported' => __('This browser cannot use passkeys. Sign in with your password below.', 'fluent-security'),
            'prompting'   => __('Waiting for your passkey…', 'fluent-security'),
            'verifying'   => __('Signing you in…', 'fluent-security'),
            'cancelled'   => __('That was cancelled. You can try again, or use your password.', 'fluent-security'),
            'failed'      => __('That passkey could not be used to sign in here.', 'fluent-security')
        ];

        $config = [
            'ajaxUrl'    => admin_url('admin-ajax.php'),
            'nonce'      => wp_create_nonce(self::NONCE_ACTION),
            'challenge'  => self::CHALLENGE_ACTION,
            'verify'     => self::VERIFY_ACTION,
            'redirectTo' => $redirectTo,
            /*
             * wp-login.php only. `login_form` fires between the password field and the
             * submit button, so on that page the block has to be moved down past it -
             * exactly as magic login moves its own, and for the same reason. A
             * `wp_login_form()` form gives us a hook that is already at the bottom, so
             * there is nothing to move and moving anyway would drop this below the magic
             * link instead of above it.
             */
            'move'       => (bool)$move,
            'messages'   => $strings
        ];

        ob_start();
        ?>
        <div class="fls_passkey_login" id="fls_passkey_login" style="display:none;margin:16px 0 0;">
            <?php
            /*
             * The separator that opens the alternatives, printed here because this block
             * is the first of them. Magic login prints one of its own for the case where
             * this button never appears; the script below removes that duplicate once
             * this one is on the page. Doing it in the browser rather than on the server
             * is what keeps the page right when the passkey button stays hidden - a
             * browser without WebAuthn then sees exactly what it saw before.
             */
            ?>
            <div class="fls_passkey_login__or"
                 style="display:flex;align-items:center;gap:10px;margin:0 0 16px;color:#646970;font-size:12px;text-transform:uppercase;letter-spacing:.4px;">
                <span style="flex:1;height:1px;background:#dcdcde;"></span>
                <span><?php esc_html_e('Or', 'fluent-security'); ?></span>
                <span style="flex:1;height:1px;background:#dcdcde;"></span>
            </div>

            <?php
            /*
             * The customiser publishes its palette as CSS variables on :root - see
             * LoginCustomizerHandler. Reading them here rather than picking a colour means
             * the button belongs to whatever the owner has designed, and falls back to
             * core's blue on a login page nobody has touched.
             */
            ?>
            <button type="button" id="fls_passkey_login_button" class="fls_passkey_login__button"
                    style="display:flex;align-items:center;justify-content:center;gap:8px;width:100%;cursor:pointer;border:1px solid var(--fls-form-button_color, #2271b1);background:var(--fls-form-button_color, #2271b1);color:var(--fls-form-button_label_color, #fff);text-shadow:none;min-height:40px;line-height:1.4;padding:8px 14px;font-size:14px;font-weight:600;border-radius:3px;">
                <?php
                /*
                 * The passkey mark - a person beside a key - rather than a key on its own.
                 * A bare key is what every site already draws next to an API token, and it
                 * says "a secret you hold"; the point of this one is that the credential
                 * *is* the account, checked by the device against a face or a fingerprint.
                 *
                 * Filled rather than stroked because it sits at 18px against bold text,
                 * where hairlines at this level of detail go muddy. currentColor so it
                 * follows the button's label through the customiser's palette.
                 */
                ?>
                <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"
                     focusable="false" aria-hidden="true" style="flex:0 0 auto;">
                    <circle cx="8" cy="6.6" r="4.3"/>
                    <path d="M8 12.6c-3.6 0-6.6 2.4-6.6 5.4V20a1 1 0 0 0 1 1h9.9a1 1 0 0 0 1-1v-2c0-3-3-5.4-6.6-5.4z"/>
                    <path d="M19.6 8.9a2.7 2.7 0 1 0-3.7 2.5V19l1.6 1.8 1.7-1.9-1.3-1.4 1.3-1.4-1.3-1.4 1.3-1.4-1.3-1.4v-.5a2.7 2.7 0 0 0 1.7-2.5z"/>
                </svg>
                <span><?php esc_html_e('Sign in with a passkey', 'fluent-security'); ?></span>
            </button>

            <div id="fls_passkey_login_status" role="status" aria-live="polite"
                 style="margin:10px 0 0;font-size:13px;color:#646970;text-align:center;"></div>
        </div>

        <script type="application/json" id="fls_passkey_login_config"><?php
            echo wp_json_encode($config); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        ?></script>

        <?php

        return ob_get_clean();
    }

    /**
     * Hands out a challenge. Anonymous by design - that is what passwordless means.
     *
     * @return void
     */
    public function handleChallenge()
    {
        $this->verifyNonce();

        $challenge = PasskeyLogin::issueChallenge();

        if (is_wp_error($challenge)) {
            wp_send_json_error(['message' => $challenge->get_error_message()], 403);
        }

        wp_send_json_success($challenge);
    }

    /**
     * Checks the assertion and, if it stands up, signs the user in.
     *
     * @return void
     */
    public function handleVerify()
    {
        $this->verifyNonce();

        /*
         * Not sanitize_text_field: this is JSON carrying base64url, and that filter
         * strips characters out of the middle rather than rejecting the document - it
         * would turn a good assertion into a malformed one. Decoded strictly instead,
         * with every field inside validated as base64url before it is used.
         */
        $raw = Arr::get($_POST, 'webauthn_response');
        $raw = is_string($raw) ? wp_unslash($raw) : '';
        $response = $raw === '' ? null : json_decode($raw, true);

        if (!is_array($response)) {
            wp_send_json_error([
                'message' => __('The passkey response could not be read. Please try again.', 'fluent-security')
            ], 422);
        }

        $token = Arr::get($_POST, 'token');
        $token = is_string($token) ? sanitize_text_field(wp_unslash($token)) : '';

        $user = PasskeyLogin::authenticate($token, $response);

        if (is_wp_error($user)) {
            wp_send_json_error(['message' => $user->get_error_message()], 401);
        }

        wp_send_json_success(['redirect' => $this->getRedirectUrl($user)]);
    }

    /**
     * @return void
     */
    private function verifyNonce()
    {
        $nonce = Arr::get($_POST, '_nonce');

        if (!is_string($nonce) || !wp_verify_nonce(sanitize_text_field(wp_unslash($nonce)), self::NONCE_ACTION)) {
            wp_send_json_error([
                'message' => __('This page has expired. Please reload it and try again.', 'fluent-security')
            ], 403);
        }
    }

    /**
     * Where to send the browser once it is signed in.
     *
     * @param $user \WP_User
     * @return string
     */
    private function getRedirectUrl($user)
    {
        $requested = Arr::get($_POST, 'redirect_to');
        $requested = is_string($requested) ? esc_url_raw(wp_unslash($requested)) : '';

        $fallback = user_can($user, 'read') ? admin_url() : home_url();

        // Validated, or the button becomes an open redirect anyone can point anywhere.
        $redirect = $requested ? Helper::getValidatedRedirectUrl($requested, $fallback) : $fallback;

        /*
         * The same filter core runs on a password login, so anything already deciding
         * where a user lands - a membership plugin, a role based landing page - keeps
         * deciding it when they arrive by passkey.
         */
        return apply_filters('login_redirect', $redirect, $requested, $user);
    }
}
