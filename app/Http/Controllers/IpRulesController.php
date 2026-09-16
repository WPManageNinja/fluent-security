<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\IpRules;

class IpRulesController
{
    public static function getRules(\WP_REST_Request $request)
    {
        return IpRules::getState();
    }

    public static function saveRules(\WP_REST_Request $request)
    {
        $rules = $request->get_param('rules');

        if (!is_array($rules)) {
            $rules = [];
        }

        $rules['restricted_roles'] = $request->get_param('restricted_roles');

        $result = IpRules::save($rules);

        if (is_wp_error($result)) {
            return $result;
        }

        return $result + [
                'message' => self::savedMessage($result)
            ];
    }

    /**
     * Adds one address to a list, from the dashboard's attacking-IP card or a logs row.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function addIp(\WP_REST_Request $request)
    {
        $ip = sanitize_text_field((string)$request->get_param('ip'));
        $type = sanitize_text_field((string)$request->get_param('type'));

        $result = IpRules::add($type, $ip);

        if (is_wp_error($result)) {
            return $result;
        }

        $message = $type === 'allow'
            /* translators: %s: an IP address */
            ? sprintf(__('%s will no longer be locked out.', 'fluent-security'), $ip)
            /* translators: %s: an IP address */
            : sprintf(__('%s can no longer sign in to this site.', 'fluent-security'), $ip);

        return $result + ['message' => $message];
    }

    /**
     * Says what was saved, and mentions anything the save quietly resolved.
     *
     * @param array $result
     * @return string
     */
    private static function savedMessage($result)
    {
        $dropped = isset($result['dropped_blocks']) ? $result['dropped_blocks'] : [];

        if (!$dropped) {
            return __('The IP rules have been saved.', 'fluent-security');
        }

        return sprintf(
            /* translators: %s: a comma separated list of IP addresses */
            _n(
                'Saved. %s was removed from the block list because the allow list covers it.',
                'Saved. %s were removed from the block list because the allow list covers them.',
                count($dropped),
                'fluent-security'
            ),
            implode(', ', $dropped)
        );
    }
}
