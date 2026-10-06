<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

/**
 * Addresses that are never locked out, and addresses that are never let in.
 *
 * Each list is a plain set of addresses and ranges - no labels, no expiry dates, nothing
 * per entry to fill in. The screen is two text boxes, one address to a line, because the
 * question being answered ("which addresses?") is a list, and anything else on the row is
 * something to think about before you can answer it.
 *
 * The two lists are not mirror images, and the asymmetry is the whole design:
 *
 * - The block list refuses a login outright. Getting it wrong shuts somebody out, which
 *   is annoying and obvious, and it still writes a log entry so it can be seen and undone.
 * - The allow list exempts an address from the attempt limit. Getting *that* wrong hands
 *   somebody unlimited password guesses, silently. So it is the more dangerous of the two
 *   and it is the one hedged about with conditions.
 *
 * Three of those conditions are worth stating outright:
 *
 * 1. Being on the allow list skips the rate limit and nothing else. It is not a trusted
 *    network and it does not stand in for a second factor - an exemption from counting is
 *    not the same as proof of who is typing, and conflating the two is how an allow list
 *    turns into a back door with no audit trail.
 * 2. The allow list does not apply while the site's addresses are ambiguous - see
 *    ProxyDetection::isAmbiguous(). Behind an undeclared proxy every visitor arrives as
 *    the same address, so exempting it would exempt the entire internet.
 * 3. Nothing here suppresses logging. A skipped block is still a failed login and still
 *    belongs in the log, or the dashboard goes blind exactly where you would want to look.
 */
class IpRules
{
    const OPTION = '__fls_auth_ip_rules';

    /**
     * Each list is walked on every login attempt, so it is bounded. Anyone needing more
     * than this is describing a firewall rule, which belongs in front of PHP.
     */
    const MAX_ENTRIES = 200;

    /**
     * The narrowest prefix an allow list entry may use, per family.
     *
     * An office is a /24 and a data centre a /16; anything broader is not a place, and on
     * the allow list breadth is exactly what does the damage. The block list is left
     * unbounded below /0 because blocking a whole hosting range is a real thing to want.
     */
    const MIN_ALLOW_PREFIX_V4 = 16;
    const MIN_ALLOW_PREFIX_V6 = 32;

    /**
     * Roles that may only sign in from an allow list address.
     *
     * @return array
     */
    public static function getRestrictedRoles()
    {
        $stored = get_option(self::OPTION, []);

        if (!is_array($stored)) {
            return [];
        }

        return array_values((array)Arr::get($stored, 'restricted_roles', []));
    }

    /**
     * Whether the wp-config.php escape hatch is in force.
     *
     * The way back into a site whose own owner is on the block list, or whose allow list
     * no longer contains anywhere they can reach it from. A constant rather than a setting
     * for the reason the trusted proxies have one: it cannot be reached by whoever is
     * locked out, and it cannot be flipped by whoever locked them out.
     *
     * It stands down every address rule that can refuse a sign-in - the block list and the
     * role restriction alike. It deliberately does *not* stand down the allow list, which
     * only ever exempts: switching that off would make a locked out site stricter, which is
     * the opposite of what somebody editing wp-config.php to get back in is asking for.
     *
     * @return bool
     */
    public static function isRestrictionDisabled()
    {
        return defined('FLUENT_AUTH_DISABLE_IP_RESTRICTION') && FLUENT_AUTH_DISABLE_IP_RESTRICTION;
    }

    /**
     * Whether this sign-in has to be refused because of where it is coming from.
     *
     * The restriction reuses the allow list rather than keeping addresses of its own, so
     * one list means one thing: these are the places this site is administered from. Worth
     * knowing when adding to it - an address added to stop a monitoring service being rate
     * limited also becomes a place an administrator may sign in from.
     *
     * Every reason to *not* enforce is a reason where enforcing would lock out everybody
     * rather than the wrong body, which is why they all fail open. Saving refuses to create
     * any of these states in the first place - see save() - so they only arise when
     * something changed underneath, like a proxy being taken away.
     *
     * @param \WP_User|mixed $user
     * @return bool
     */
    public static function deniesSignIn($user)
    {
        if (!$user instanceof \WP_User) {
            return false;
        }

        if (self::isRestrictionDisabled()) {
            return false;
        }

        $roles = self::getRestrictedRoles();

        if (!$roles || !array_intersect($roles, (array)$user->roles)) {
            return false;
        }

        // Every visitor arrives as the same address, so this could only be all or nothing.
        if (ProxyDetection::isAmbiguous()) {
            return false;
        }

        $entries = self::getList('allow');

        // No addresses left to permit is not "refuse everyone".
        if (!$entries) {
            return false;
        }

        return !self::matchingRule(Helper::getIp(), $entries);
    }

    /**
     * Both lists, as addresses.
     *
     * @return array
     */
    public static function get()
    {
        return [
            'allow' => self::getList('allow'),
            'block' => self::getList('block')
        ];
    }

    /**
     * One stored list, normalised to a plain array of addresses.
     *
     * Reads the shape these lists used to have as well - a row per entry, carrying a label
     * and an expiry date - so an install that has not saved since keeps working, and its
     * first save quietly rewrites it. Nothing reads the label or the expiry any more.
     *
     * @param string $type
     * @return array
     */
    private static function getList($type)
    {
        $stored = get_option(self::OPTION, []);

        if (!is_array($stored)) {
            return [];
        }

        $entries = [];

        foreach (Arr::get($stored, $type, []) as $entry) {
            $ip = is_array($entry) ? (string)Arr::get($entry, 'ip', '') : (string)$entry;

            if ($ip !== '') {
                $entries[] = $ip;
            }
        }

        return array_values(array_unique($entries));
    }

    /**
     * Everything the settings screen needs in one call.
     *
     * @return array
     */
    public static function getState()
    {
        return [
            'rules'             => self::get(),
            'restricted_roles'  => self::getRestrictedRoles(),
            'roles'             => Helper::getUserRoles(),
            'current_ip'        => Helper::getIp(),
            /*
             * Worked out here rather than in the browser: deciding whether an address falls
             * inside a range is the one thing on this screen with an answer, and a second
             * implementation of CIDR matching in JavaScript is a second one to get wrong.
             */
            'current_ip_listed' => (bool)self::matchingRule(Helper::getIp(), self::getList('allow')),
            /*
             * Reported even when both lists are empty: it is the reason the allow list will
             * not work, and finding that out after adding an entry is finding it out late.
             */
            'allow_paused'      => ProxyDetection::isAmbiguous(),
            /*
             * Said on the screen that edits the lists, because a list that is not being
             * applied looks exactly like one that is. Somebody who used the constant to get
             * back in needs to be told it is still there before they wonder why their block
             * list stopped working.
             */
            'restrictions_off'  => self::isRestrictionDisabled(),
            'max_entries'       => self::MAX_ENTRIES
        ];
    }

    /**
     * Replaces both lists, or refuses the lot.
     *
     * All-or-nothing on purpose. A partial save would leave the screen showing something
     * different from what is stored, and on a list that decides who can log in, "some of
     * that worked" is not a state worth having.
     *
     * @param array $input
     * @return array|\WP_Error
     */
    public static function save($input)
    {
        $clean = [];

        foreach (['allow', 'block'] as $type) {
            $entries = self::readInput(Arr::get($input, $type, []));

            if (count($entries) > self::MAX_ENTRIES) {
                return new \WP_Error(
                    'too_many',
                    sprintf(
                    /* translators: %d: the maximum number of entries per list */
                        __('A list can hold at most %d addresses.', 'fluent-security'),
                        self::MAX_ENTRIES
                    ),
                    ['status' => 422]
                );
            }

            $clean[$type] = [];

            foreach ($entries as $entry) {
                $ip = self::validateIp($entry, $type);

                if (is_wp_error($ip)) {
                    return $ip;
                }

                /*
                 * The same address twice is a typo in a text box, not a decision - and the
                 * box is redrawn from what was stored, so collapsing them is visible rather
                 * than silent.
                 */
                if (!in_array($ip, $clean[$type], true)) {
                    $clean[$type][] = $ip;
                }
            }
        }

        /*
         * Checked after both lists are otherwise valid, so the message is about the one
         * mistake that actually locks the administrator out of their own site.
         */
        $selfBlock = self::matchingRule(Helper::getIp(), $clean['block']);

        if ($selfBlock) {
            return new \WP_Error(
                'self_block',
                sprintf(
                /* translators: %1$s: an IP address or CIDR range, %2$s: the current visitor's IP address */
                    __('%1$s covers your own address (%2$s), so saving it would lock you out.', 'fluent-security'),
                    $selfBlock,
                    Helper::getIp()
                ),
                ['status' => 422]
            );
        }

        /*
         * An address on both lists is a contradiction, and which side wins would depend on
         * the order the two are consulted - which is not something anyone should have to
         * know. The allow list is the deliberate one, so it takes precedence and the block
         * entry goes, with the caller told which ones so it does not look like a bug.
         */
        $dropped = [];

        $clean['block'] = array_values(array_filter($clean['block'], function ($ip) use ($clean, &$dropped) {
            if (!self::coveredByAny($ip, $clean['allow'])) {
                return true;
            }

            $dropped[] = $ip;

            return false;
        }));

        $restrictedRoles = self::validateRoles(Arr::get($input, 'restricted_roles', []), $clean['allow']);

        if (is_wp_error($restrictedRoles)) {
            return $restrictedRoles;
        }

        $clean['restricted_roles'] = $restrictedRoles;

        update_option(self::OPTION, $clean, false);

        return self::getState() + ['dropped_blocks' => $dropped];
    }

    /**
     * Whatever the caller sent for one list, as an array of one address per element.
     *
     * Takes the text box's own contents as well as an array, because a list typed one to a
     * line is what the screen has and turning it into an array on the way out only means
     * the server has to trust that it happened. Blank lines are what a trailing newline
     * looks like, so they are dropped rather than reported as an empty address.
     *
     * @param mixed $value
     * @return array
     */
    private static function readInput($value)
    {
        if (is_string($value)) {
            $value = preg_split('/[\r\n,]+/', $value);
        }

        if (!is_array($value)) {
            return [];
        }

        $entries = [];

        foreach ($value as $entry) {
            // The shape these lists used to have, in case an old screen is still open.
            $entry = is_array($entry) ? (string)Arr::get($entry, 'ip', '') : (string)$entry;
            $entry = trim($entry);

            if ($entry !== '') {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * The roles that may only sign in from an allow list address.
     *
     * Turning this on with the wrong addresses locks every one of those roles out of a site
     * they cannot log in to fix, so all three ways to get that wrong are refused here rather
     * than discovered afterwards.
     *
     * @param mixed $roles
     * @param array $allowEntries
     * @return array|\WP_Error
     */
    private static function validateRoles($roles, $allowEntries)
    {
        if (!is_array($roles)) {
            $roles = [];
        }

        $known = array_column(Helper::getUserRoles(), 'id');
        $roles = array_values(array_intersect(array_map('sanitize_text_field', $roles), $known));

        if (!$roles) {
            return [];
        }

        if (!$allowEntries) {
            return new \WP_Error(
                'no_allowed_addresses',
                __('Add at least one address to the allow list before restricting a role to it.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (ProxyDetection::isAmbiguous()) {
            return new \WP_Error(
                'addresses_ambiguous',
                __('Every visitor currently reaches this site as the same address, so restricting a role by address would either admit everyone or lock out everyone. Declare the proxy in front of this site first.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (!self::matchingRule(Helper::getIp(), $allowEntries)) {
            return new \WP_Error(
                'would_lock_you_out',
                sprintf(
                /* translators: %s: the current visitor's IP address */
                    __('Your own address (%s) is not on the allow list, so this would lock you out immediately. Add it first.', 'fluent-security'),
                    Helper::getIp()
                ),
                ['status' => 422]
            );
        }

        return $roles;
    }

    /**
     * Whether any entry covers the given address or range.
     *
     * A range is tested by its base address: 203.0.113.0/24 counts as covered by
     * 203.0.113.0/16, which is the reading that stops the two lists contradicting.
     *
     * @param string $ip
     * @param array $entries
     * @return bool
     */
    private static function coveredByAny($ip, $entries)
    {
        $base = strpos($ip, '/') === false ? $ip : substr($ip, 0, strpos($ip, '/'));

        return (bool)self::matchingRule($base, $entries);
    }

    /**
     * Appends one address to a list, for the one-click actions on the dashboard and the
     * logs table.
     *
     * Goes through save() rather than writing directly, so a one-click action is held to
     * every rule a hand-edited list is - including that it cannot block the address of
     * whoever clicked it.
     *
     * @param string $type
     * @param string $ip
     * @return array|\WP_Error
     */
    public static function add($type, $ip)
    {
        if (!in_array($type, ['allow', 'block'], true)) {
            return new \WP_Error(
                'unknown_list',
                __('There is no such list.', 'fluent-security'),
                ['status' => 404]
            );
        }

        /*
         * Validated here rather than left to save(), so the checks below compare a
         * normalised address against the lists - and so an empty one is refused instead of
         * being dropped as a blank line and reported as added.
         */
        $ip = self::validateIp($ip, $type);

        if (is_wp_error($ip)) {
            return $ip;
        }

        $input = [
            'allow'            => self::getList('allow'),
            'block'            => self::getList('block'),
            'restricted_roles' => self::getRestrictedRoles()
        ];

        // Already there, by an exact entry or a range that covers it: nothing to do.
        if (self::coveredByAny($ip, $input[$type])) {
            return new \WP_Error(
                'already_listed',
                sprintf(
                /* translators: %s: an IP address */
                    __('%s is already covered by this list.', 'fluent-security'),
                    $ip
                ),
                ['status' => 422]
            );
        }

        /*
         * Refused rather than added, because save() would drop it again a moment later -
         * the allow list wins - and the caller would be told the address was blocked while
         * nothing of the kind had happened. Editing both lists by hand still resolves the
         * overlap silently; a single button that says "block this" has to mean it.
         */
        if ($type === 'block' && self::coveredByAny($ip, $input['allow'])) {
            return new \WP_Error(
                'allow_list_conflict',
                sprintf(
                /* translators: %s: an IP address */
                    __('%s is on the allow list, so it cannot be blocked. Take it off the allow list first.', 'fluent-security'),
                    $ip
                ),
                ['status' => 422]
            );
        }

        $input[$type][] = $ip;

        return self::save($input);
    }

    /* ------------------------------------------------------------- enforcement */

    /**
     * @param string $ip
     * @return bool
     */
    public static function isBlocked($ip)
    {
        return (bool)self::blockingRule($ip);
    }

    /**
     * The block list entry refusing this address, if any.
     *
     * Returned rather than a bare true so the refusal can name the rule that caused it -
     * in the log, and to whoever is being refused. "Blocked by 45.148.0.0/16" is something
     * an administrator can act on; "blocked" is something they open a ticket about.
     *
     * @param string $ip
     * @return string
     */
    public static function blockingRule($ip)
    {
        if (self::isRestrictionDisabled()) {
            return '';
        }

        return self::matchingRule($ip, self::getList('block'));
    }

    /**
     * Whether this address has a block list entry, whether or not it is being enforced.
     *
     * The question a screen asks before offering a "block this" button, which is not the
     * same question the login asks. While the wp-config.php escape hatch is in force
     * nothing is refused, but the list is still there and still what the administrator is
     * about to edit - offering to add a row that is already in it would just fail.
     *
     * @param string $ip
     * @return bool
     */
    public static function isOnBlockList($ip)
    {
        return (bool)self::matchingRule($ip, self::getList('block'));
    }

    /**
     * @param string $ip
     * @return bool
     */
    public static function isAllowed($ip)
    {
        if (ProxyDetection::isAmbiguous()) {
            return false;
        }

        return (bool)self::matchingRule($ip, self::getList('allow'));
    }

    /**
     * The first entry covering this address, or an empty string.
     *
     * @param string $ip
     * @param array $entries
     * @return string
     */
    private static function matchingRule($ip, $entries)
    {
        if (!$ip) {
            return '';
        }

        foreach ($entries as $entry) {
            if (Helper::ipInRange($ip, (string)$entry)) {
                return (string)$entry;
            }
        }

        return '';
    }

    /* -------------------------------------------------------------- validation */

    /**
     * @param string $value
     * @param string $type
     * @return string|\WP_Error
     */
    private static function validateIp($value, $type)
    {
        $value = trim(sanitize_text_field((string)$value));

        if (!$value) {
            return new \WP_Error(
                'invalid_ip',
                __('Enter an IP address or a range.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $invalid = new \WP_Error(
            'invalid_ip',
            sprintf(
            /* translators: %s: whatever was typed into the address field */
                __('"%s" is not an IP address or a range like 203.0.113.0/24.', 'fluent-security'),
                $value
            ),
            ['status' => 422]
        );

        if (strpos($value, '/') === false) {
            return rest_is_ip_address($value) ? $value : $invalid;
        }

        list($subnet, $bits) = array_pad(explode('/', $value, 2), 2, '');

        if (!rest_is_ip_address($subnet) || !is_numeric($bits)) {
            return $invalid;
        }

        $isV6 = strpos($subnet, ':') !== false;
        $bits = (int)$bits;
        $maxBits = $isV6 ? 128 : 32;

        /*
         * A /0 matches every address there is. On the allow list it would switch the
         * attempt limit off for the internet; on the block list it would take the site
         * off the air. Neither is something anyone types on purpose.
         */
        if ($bits < 1 || $bits > $maxBits) {
            return $invalid;
        }

        if ($type === 'allow') {
            $minBits = $isV6 ? self::MIN_ALLOW_PREFIX_V6 : self::MIN_ALLOW_PREFIX_V4;

            if ($bits < $minBits) {
                return new \WP_Error(
                    'range_too_broad',
                    sprintf(
                    /* translators: %1$s: the range that was entered, %2$d: the narrowest allowed prefix */
                        __('%1$s covers too much of the internet to exempt. Use /%2$d or narrower.', 'fluent-security'),
                        $value,
                        $minBits
                    ),
                    ['status' => 422]
                );
            }
        }

        return $subnet . '/' . $bits;
    }
}
