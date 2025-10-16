<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class AuthService
{
    public static function doUserAuth($userData, $provider = '')
    {
        if (get_current_user_id()) {
            return new \WP_Error('already_logged_in', 'You are already logged in. Please refresh the page');
        }

        if (empty($userData['email']) || !is_email($userData['email'])) {
            return new \WP_Error('invalid_email', 'Valid Email address is required');
        }

        Helper::setLoginMedia($provider);

        $email = $userData['email'];

        $userExist = get_user_by('email', $email);

        if ($userExist) {
            self::maybeUpdateUser($userExist, $userData);
            return self::makeLogin($userExist, $provider);
        }

        $signupEnabled = apply_filters('fluent_auth/signup_enabled', get_option('users_can_register'));
        if (!$signupEnabled) {
            return new \WP_Error('signup_disabled', __('User registration is disabled', 'fluent-security'));
        }

        // let's create the user here
        $createUserData = [
            'email'    => $userData['email'],
            'password' => wp_generate_password(8),
            'username' => sanitize_user($userData['email'])
        ];

        if (!empty($userData['username'])) {
            if (username_exists($userData['username'])) {
                $createUserData['username'] = sanitize_user($userData['username']);
            }
        }

        $defaultRole = get_option('default_role');
        if (!$defaultRole || $defaultRole === 'administrator') {
            $defaultRole = 'subscriber';
        }

        $setRole = apply_filters('fluent_auth/user_role', $defaultRole);

        $userId = self::registerNewUser($createUserData['username'], $createUserData['email'], $createUserData['password'], [
            'role'        => $setRole,
            'first_name'  => Arr::get($userData, 'first_name'),
            'last_name'   => Arr::get($userData, 'last_name'),
            'user_url'    => Arr::get($userData, 'user_url'),
            'full_name'   => Arr::get($userData, 'full_name'),
            'description' => Arr::get($userData, 'description'),
            '__validated' => true
        ]);

        if (is_wp_error($userId)) {
            return $userId;
        }

        $user = get_user_by('ID', $userId);

        return self::makeLogin($user, $provider);
    }

    private static function maybeUpdateUser($user, $userData)
    {
        $updateData = [];

        if (!empty($userData['user_url']) && !$user->user_url) {
            $updateData['user_url'] = $userData['user_url'];
        }

        if (!empty($userData['description']) && !$user->description) {
            $updateData['description'] = $userData['description'];
        }

        if (!$user->first_name || !$user->last_name) {
            if (!empty($userData['full_name'])) {
                // extract the names
                $fullNameArray = explode(' ', $userData['full_name']);
                $updateData['first_name'] = array_shift($fullNameArray);
                if ($fullNameArray) {
                    $updateData['last_name'] = implode(' ', $fullNameArray);
                } else {
                    $updateData['last_name'] = '';
                }
            }

            if (!empty($userData['first_name'])) {
                $updateData['first_name'] = $userData['first_name'];
            }

            if (!empty($userData['last_name'])) {
                $updateData['last_name'] = $userData['last_name'];
            }
        }

        if (!empty($userData)) {
            $updateData['ID'] = $user->ID;
            wp_update_user($updateData);
        }
    }

    public static function makeLogin($user, $provider = '')
    {
        if (is_numeric($user)) {
            $user = get_user_by('ID', $user);
        }

        if (!$user) {
            return new \WP_Error('user_not_found', __('User not found', 'fluent-security'));
        }

        $canLogin = apply_filters('fluent_auth/can_user_login', false, $user, $provider);

        if ($provider && is_wp_error($canLogin)) {
            return $canLogin;
        }

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID, $user->user_login);
        wp_set_auth_cookie($user->ID, true, is_ssl());

        $user = get_user_by('ID', $user->ID);

        if ($user) {
            do_action('wp_login', $user->user_login, $user);
        }

        return $user;
    }

    public static function setStateToken()
    {
        $state = md5(wp_generate_uuid4());
        setcookie('fs_auth_state', $state, time() + 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl());  /* expire in 1 hour */
        return $state;
    }

    public static function getStateToken()
    {
        return Arr::get($_COOKIE, 'fs_auth_state');
    }

    /**
     * Handles registering a new user.
     *
     * @param string $user_login User's username for logging in
     * @param string $user_email User's email address to send password and add
     * @return int|\WP_Error Either user's ID or error on failure.
     * @since 2.5.0
     *
     */
    public static function registerNewUser($user_login, $user_email, $user_pass = '', $extraData = [])
    {
        $user_email = apply_filters('user_registration_email', $user_email);

        $errors = new \WP_Error();
        if (empty($extraData['__validated'])) {
            $errors = self::checkUserRegDataErrors($user_login, $user_email);
            if ($errors->has_errors()) {
                return $errors;
            }
        } else {
            unset($extraData['__validated']);
        }

        $sanitized_user_login = sanitize_user($user_login);

        if (!$user_pass) {
            $user_pass = wp_generate_password(8, false);
        }

        $data = [
            'user_login' => wp_slash($sanitized_user_login),
            'user_email' => wp_slash($user_email),
            'user_pass'  => $user_pass
        ];

        if (!empty($extraData['first_name'])) {
            $data['first_name'] = sanitize_text_field($extraData['first_name']);
        }

        if (!empty($extraData['last_name'])) {
            $data['last_name'] = sanitize_text_field($extraData['last_name']);
        }

        if (!empty($extraData['full_name']) && empty($extraData['first_name']) && empty($extraData['last_name'])) {
            $extraData['full_name'] = sanitize_text_field($extraData['full_name']);
            // extract the names
            $fullNameArray = explode(' ', $extraData['full_name']);
            $data['first_name'] = array_shift($fullNameArray);
            if ($fullNameArray) {
                $data['last_name'] = implode(' ', $fullNameArray);
            } else {
                $data['last_name'] = '';
            }
        }

        if (!empty($extraData['description'])) {
            $data['description'] = sanitize_textarea_field($extraData['description']);
        }

        if (!empty($extraData['user_url']) && filter_var($extraData['user_url'], FILTER_VALIDATE_URL)) {
            $data['user_url'] = sanitize_url($extraData['user_url']);
        }

        if (!empty($extraData['role'])) {
            $data['role'] = $extraData['role'];
        }


        do_action('fluent_auth/before_creating_user', $data);

        $user_id = wp_insert_user($data);
        if (!$user_id || is_wp_error($user_id)) {
            $errors->add('registerfail', __('<strong>Error</strong>: Could not register you. Please contact the site admin!', 'fluent-security'));
            return $errors;
        }

        if (!empty($_COOKIE['wp_lang'])) {
            $wp_lang = sanitize_text_field($_COOKIE['wp_lang']);
            if (in_array($wp_lang, get_available_languages(), true)) {
                update_user_meta($user_id, 'locale', $wp_lang); // Set user locale if defined on registration.
            }
        }

        /*
         * Action After creating WP user from sign up form
         *
         * @since v1.0.0
         * @param int $user_id User ID of the created user
         * @param array $data User data array that was used to create the user
         */
        do_action('fluent_auth/after_creating_user', $user_id, $data);

        do_action('register_new_user', $user_id);

        return $user_id;
    }


    public static function checkUserRegDataErrors($user_login, $user_email, $extraArgs = [])
    {
        $errors = new \WP_Error();
        $sanitized_user_login = sanitize_user($user_login);
        // Check the username.
        if ('' === $sanitized_user_login) {
            $errors->add('empty_username', __('<strong>Error</strong>: Please enter a username.', 'fluent-security'));
        } elseif (!validate_username($user_login)) {
            $errors->add('invalid_username', __('<strong>Error</strong>: This username is invalid because it uses illegal characters. Please enter a valid username.', 'fluent-security'));
            $sanitized_user_login = '';
        } elseif (username_exists($sanitized_user_login)) {
            $errors->add('username_exists', __('<strong>Error</strong>: This username is already registered. Please choose another one.', 'fluent-security'));
        } else {
            /** This filter is documented in wp-includes/user.php */
            $illegal_user_logins = (array)apply_filters('illegal_user_logins', array());
            if (in_array(strtolower($sanitized_user_login), array_map('strtolower', $illegal_user_logins), true)) {
                $errors->add('invalid_username', __('<strong>Error</strong>: Sorry, that username is not allowed.', 'fluent-security'));
            }
        }

        // Check the email address.
        if ('' === $user_email) {
            $errors->add('empty_email', __('<strong>Error</strong>: Please type your email address.', 'fluent-security'));
        } elseif (!is_email($user_email)) {
            $errors->add('invalid_email', __('<strong>Error</strong>: The email address is not correct.', 'fluent-security'));
            $user_email = '';
        } elseif (email_exists($user_email)) {
            $errors->add(
                'email_exists',
                __('<strong>Error:</strong> This email address is already registered. Please login or try reset password', 'fluent-security')
            );
        }

        if (empty($extraArgs['__validated'])) {
            do_action('register_post', $sanitized_user_login, $user_email, $errors);
            $errors = apply_filters('registration_errors', $errors, $sanitized_user_login, $user_email);
        }

        return $errors;
    }

    public static function verifyTokenHash($verificationHash, $token)
    {
        $logHash = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $verificationHash)
            ->where('status', 'issued')
            ->where('use_type', 'signup_verification')
            ->first();

        if (!$logHash) {
            return new \WP_Error('invalid_verification_code', __('Please provide a valid vefification code that sent to your email address', 'fluent-security'));
        }

        // check if it got expired or not
        if ($logHash->used_count > 5 || strtotime($logHash->valid_till) < current_time('timestamp')) {
            return new \WP_Error('verification_code_expired', __('Your verification code has beeen expired. Please try again', 'fluent-security'));
        }

        if (!wp_check_password($token, $logHash->two_fa_code_hash)) {
            flsDb()->table('fls_login_hashes')->where('id', $logHash->id)
                ->update([
                    'used_count' => $logHash->used_count + 1
                ]);
            return new \WP_Error('invalid_verification_code', __('Please provide a valid vefification code that sent to your email address', 'fluent-security'));
        }

        flsDb()->table('fls_login_hashes')->where('id', $logHash->id)
            ->update([
                'used_count' => $logHash->used_count + 1,
                'status'     => 'used'
            ]);

        return true;
    }
}
