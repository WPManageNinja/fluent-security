<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Ceremony;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * Registering and removing passkeys, on the WordPress profile screen.
 *
 * The same asymmetry the authenticator app uses, and for the same reason: a user may
 * only add a passkey to their own account, while an administrator may remove one from
 * anybody's. Adding is a thing only the person holding the device can meaningfully do -
 * and an administrator who could add one would be adding their own device to someone
 * else's account, which is not recovery, it is a back door.
 *
 * What the user sees is drawn by TwoFaProfileHandler, which lists these credentials on
 * one card with the other second factors. This file is the ceremony and the rules.
 */
class PasskeyProfileHandler
{
    const NONCE_ACTION = 'fls_passkey_profile';

    /**
     * The outstanding registration challenge.
     *
     * A transient rather than the pending login row, because this ceremony happens
     * inside an existing session rather than during a login. Short lived: a challenge
     * that outlives the page it was drawn for is one an attacker has had time to work
     * with.
     */
    const CHALLENGE_TRANSIENT = 'fls_passkey_challenge_';

    const CHALLENGE_TTL = 300;

    public function register()
    {
        add_action('wp_ajax_fluent_auth_passkey_options', [$this, 'handleOptions']);
        add_action('wp_ajax_fluent_auth_passkey_register', [$this, 'handleRegister']);
        add_action('wp_ajax_fluent_auth_passkey_delete', [$this, 'handleDelete']);
        add_action('wp_ajax_fluent_auth_passkey_rename', [$this, 'handleRename']);

        // Nothing should outlive the account it belonged to.
        add_action('deleted_user', [$this, 'purgeForUser']);
    }

    /**
     * Hands the browser a fresh challenge to register against.
     *
     * @return void
     */
    public function handleOptions()
    {
        $user = $this->authorise(true);

        try {
            $challenge = Ceremony::createChallenge();
        } catch (WebAuthnException $e) {
            wp_send_json_error(['message' => __('This server cannot generate a secure challenge.', 'fluent-security')], 500);
        }

        set_transient(self::CHALLENGE_TRANSIENT . $user->ID, Base64Url::encode($challenge), self::CHALLENGE_TTL);

        $existing = [];

        foreach (PasskeyStore::getForUser($user) as $credential) {
            $existing[] = $credential->credential_id;
        }

        wp_send_json_success([
            'options' => Registration::getCreationOptions($user, $challenge, $existing)
        ]);
    }

    /**
     * @return void
     */
    public function handleRegister()
    {
        $user = $this->authorise(true);

        $stored = get_transient(self::CHALLENGE_TRANSIENT . $user->ID);
        $challenge = is_string($stored) ? Base64Url::decode($stored) : false;

        /*
         * Spent on sight, before the response is looked at. A challenge that survives a
         * failed attempt is a challenge that can be attempted repeatedly.
         */
        delete_transient(self::CHALLENGE_TRANSIENT . $user->ID);

        if ($challenge === false) {
            wp_send_json_error(['message' => __('That took too long. Please try again.', 'fluent-security')], 400);
        }

        $raw = Arr::get($_POST, 'response');
        $response = is_string($raw) ? json_decode(wp_unslash($raw), true) : null;

        if (!is_array($response)) {
            wp_send_json_error(['message' => __('The passkey response could not be read.', 'fluent-security')], 400);
        }

        try {
            $verified = Registration::verify($response, $challenge);
        } catch (WebAuthnException $e) {
            do_action('fluent_auth/passkey_registration_failed', $user, $e->getMessage());

            wp_send_json_error(['message' => __('That passkey could not be verified. Please try again.', 'fluent-security')], 400);
        }

        $transports = Arr::get($_POST, 'transports');
        $transports = is_string($transports) ? json_decode(wp_unslash($transports), true) : [];

        $added = PasskeyStore::add($user, $verified, Arr::get($_POST, 'label'), (array)$transports);

        if (is_wp_error($added)) {
            wp_send_json_error(['message' => $added->get_error_message()], 400);
        }

        wp_send_json_success([
            'message' => __('Passkey registered.', 'fluent-security')
        ]);
    }

    /**
     * @return void
     */
    public function handleDelete()
    {
        // Not self-only: removing a credential is how an administrator rescues an account.
        $user = $this->authorise(false);

        $id = (int)Arr::get($_POST, 'id');

        if (!PasskeyStore::delete($id, $user)) {
            wp_send_json_error(['message' => __('That passkey could not be removed.', 'fluent-security')], 400);
        }

        wp_send_json_success(['message' => __('Passkey removed.', 'fluent-security')]);
    }

    /**
     * @return void
     */
    public function handleRename()
    {
        $user = $this->authorise(false);

        $id = (int)Arr::get($_POST, 'id');

        if (!PasskeyStore::rename($id, $user, Arr::get($_POST, 'label'))) {
            wp_send_json_error(['message' => __('That passkey could not be renamed.', 'fluent-security')], 400);
        }

        wp_send_json_success(['message' => __('Passkey renamed.', 'fluent-security')]);
    }

    /**
     * @param $userId int
     * @return void
     */
    public function purgeForUser($userId)
    {
        PasskeyStore::deleteAllForUser($userId);
    }

    /**
     * Checks the nonce and the capability, and answers who is being acted on.
     *
     * Exits rather than returning a failure, so no caller can proceed past a refused
     * request by forgetting to check.
     *
     * @param $selfOnly bool whether the action may only be taken on one's own account
     * @return \WP_User
     */
    private function authorise($selfOnly)
    {
        check_ajax_referer(self::NONCE_ACTION, '_fls_passkey_nonce');

        $userId = (int)Arr::get($_POST, 'user_id');
        $userId = $userId ? $userId : get_current_user_id();

        if (!current_user_can('edit_user', $userId)) {
            wp_send_json_error(['message' => __('You cannot change this account.', 'fluent-security')], 403);
        }

        /*
         * Registering for somebody else would mean adding a device they do not hold to
         * an account that is not yours, which is not a thing an administrator should be
         * able to do even with every capability there is.
         */
        if ($selfOnly && $userId !== get_current_user_id()) {
            wp_send_json_error(['message' => __('A passkey can only be added to your own account.', 'fluent-security')], 403);
        }

        $user = get_user_by('ID', $userId);

        if (!$user instanceof \WP_User) {
            wp_send_json_error(['message' => __('Unknown user.', 'fluent-security')], 404);
        }

        if ($selfOnly && !PasskeyTwoFaMethod::isAllowedForUser($user)) {
            wp_send_json_error(['message' => __('Passkeys are not enabled for this account.', 'fluent-security')], 403);
        }

        return $user;
    }
}
