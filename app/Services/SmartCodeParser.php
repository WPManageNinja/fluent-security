<?php

namespace FluentAuth\App\Services;


use FluentAuth\App\Helpers\Arr;

class SmartCodeParser
{
    public function parse($templateString, $data)
    {

        if (!$templateString) {
            return $templateString;
        }

        $result = [];
        $isSingle = false;

        if (!is_array($templateString)) {
            $isSingle = true;
        }

        foreach ((array)$templateString as $key => $string) {
            $result[$key] = $this->parseShortcode($string, $data);
        }

        if ($isSingle) {
            return reset($result);
        }

        return $result;
    }


    public function parseShortcode($string, $data)
    {
        if (!$string) {
            return '';
        }

        // check if the string contains any smartcode
        if (strpos($string, '{{') === false && strpos($string, '##') === false) {
            return $string;
        }

        return preg_replace_callback('/({{|##)+(.*?)(}}|##)/', function ($matches) use ($data) {
            return $this->replace($matches, $data);
        }, $string);
    }

    protected function replace($matches, $user)
    {
        if (empty($matches[2])) {
            return apply_filters('fluent_auth/smartcode_fallback', $matches[0], $user);
        }

        $matches[2] = trim($matches[2]);

        $matched = explode('.', $matches[2]);

        if (count($matched) <= 1) {
            return apply_filters('fluent_auth/smartcode_fallback', $matches[0], $user);
        }

        $dataKey = trim(array_shift($matched));

        $valueKey = trim(implode('.', $matched));

        if (!$valueKey) {
            return apply_filters('fluent_auth/smartcode_fallback', $matches[0], $user);
        }

        $valueKeys = explode('|', $valueKey);

        $valueKey = $valueKeys[0];
        $defaultValue = '';
        $transformer = '';

        $valueCounts = count($valueKeys);

        if ($valueCounts >= 3) {
            $defaultValue = trim($valueKeys[1]);
            $transformer = trim($valueKeys[2]);
        } else if ($valueCounts === 2) {
            $defaultValue = trim($valueKeys[1]);
        }

        $value = '';

        switch ($dataKey) {
            case 'site':
                $value = $this->getWpValue($valueKey, $defaultValue, $user);
                break;
            case 'user':
                if (!$user) {
                    $value = $defaultValue;
                } else {
                    $value = $this->getUserValue($valueKey, $defaultValue, $user);
                }
                break;
            default:
                $value = apply_filters('fluent_auth/smartcode_group_callback_' . $dataKey, $matches[0], $valueKey, $defaultValue, $user);
        }

        if ($transformer && $value) {
            switch ($transformer) {
                case 'trim':
                    return trim($value);
                case 'ucfirst':
                    return ucfirst($value);
                case 'strtolower':
                    return strtolower($value);
                case 'strtoupper':
                    return strtoupper($value);
                case 'ucwords':
                    return ucwords($value);
                case 'concat_first': // usage: {{contact.first_name||concat_first|Hi
                    if (isset($valueKeys[3])) {
                        $value = trim($valueKeys[3] . ' ' . $value);
                    }
                    return $value;
                case 'concat_last': // usage: {{contact.first_name||concat_last|, => FIRST_NAME,
                    if (isset($valueKeys[3])) {
                        $value = trim($value . '' . $valueKeys[3]);
                    }
                    return $value;
                case 'show_if': // usage {{contact.first_name||show_if|First name exist
                    if (isset($valueKeys[3])) {
                        $value = $valueKeys[3];
                    }
                    return $value;
                default:
                    return $value;
            }
        }

        return $value;

    }

    protected function getWpValue($valueKey, $defaultValue, $wpUser = [])
    {
        if ($valueKey == 'login_url') {
            return network_site_url('wp-login.php', 'login');
        }

        if ($valueKey == 'name') {
            return wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
        }

        $value = get_bloginfo($valueKey);
        if (!$value) {
            return $defaultValue;
        }
        return $value;
    }


    protected function getUserValue($valueKey, $defaultValue, $wpUser = null)
    {
        if (!$wpUser || !$wpUser instanceof \WP_User) {
            return $defaultValue;
        }

        if ($valueKey == 'password_reset_url' || $valueKey == 'password_set_url') {
            if (defined('FLUENTAUTH_PREVIEWING_EMAIL')) {
                return '#pasword_reset_link_will_be_inserted_on_real_email';
            }

            if (!empty($wpUser->_password_reset_key_)) {
                $key = $wpUser->_password_reset_key_;
            } else {
                $key = get_password_reset_key($wpUser);
            }

            if (is_wp_error($key)) {
                return $defaultValue;
            }

            return network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($wpUser->user_login), 'login');
        }

        if ($valueKey == 'new_changing_email_id') {

            if (defined('FLUENTAUTH_PREVIEWING_EMAIL')) {
                return 'new_email_will_be_inserted_on_real_email';
            }

            $userMeta = get_user_meta($wpUser->ID, '_new_email', true);
            if ($userMeta) {
                return Arr::get($userMeta, 'newemail', $defaultValue);
            }

            return $defaultValue;
        }

        if ($valueKey == 'confirm_email_change_url') {
            $userMeta = get_user_meta($wpUser->ID, '_new_email', true);
            if ($userMeta) {
                $hash = Arr::get($userMeta, 'hash', $defaultValue);
            } else {
                $hash = '';
            }

            return esc_url(self_admin_url('profile.php?newuseremail=' . $hash));
        }

        if ($valueKey == 'profile_edit_url') {
            return admin_url('user-edit.php?user_id=' . $wpUser->ID);
        }

        if ($valueKey == 'roles') {
            $userRoles = (array)$wpUser->roles;
            $userRoles = array_map(function ($role) {
                return ucfirst($role);
            }, $userRoles);

            return implode(', ', $userRoles);
        }

        $valueKeys = explode('.', $valueKey);
        if (count($valueKeys) == 1) {
            $value = $wpUser->get($valueKey);
            if (!$value) {
                return $defaultValue;
            }

            if (!is_array($value) && !is_object($value)) {
                return $value;
            }

            return $defaultValue;
        }
        $customKey = $valueKeys[0];
        $customProperty = $valueKeys[1];

        if ($customKey == 'meta') {
            $metaValue = get_user_meta($wpUser->ID, $customProperty, true);
            if (!$metaValue) {
                return $defaultValue;
            }

            if (!is_array($metaValue) && !is_object($metaValue)) {
                return $metaValue;
            }

            return $defaultValue;
        }

        return $defaultValue;
    }
}
