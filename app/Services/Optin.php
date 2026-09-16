<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

defined('ABSPATH') || exit;

/**
 * The mailing list signup: who has been asked, who has answered, and what an answer sends.
 *
 * This is the one place in the plugin that collects an address for our own purposes rather
 * than the site's. Everything else that takes an email is transactional - the alerts relay
 * needs one to post the API key back (see IntegrityChecker\Api), the sign-in alerts need
 * one to send to. This does not: it is a list, and the only honest way to run one is to
 * ask, take no for an answer, and say exactly what leaves the site.
 *
 * Three rules follow from that, and they are the whole of this class:
 *
 * - Nobody is asked twice at once. The wizard's last screen and the dashboard card are two
 *   views of one question, and isRequired() is the single answer to whether it still needs
 *   asking, so dismissing it in one place closes it in the other.
 *
 * - Declining is durable but not permanent. A dismissal parks the card for a week rather
 *   than forever: an install that says no on day one is usually saying "not now", and an
 *   install that keeps saying no is one we should stop pestering - which is the same
 *   answer, so it is the same mechanism either way.
 *
 * - The optional half is optional. Subscribing sends a name, an address and this site's
 *   own address, which is what the form says on its face - the list is keyed on the pair,
 *   so a site cannot be counted twice and a signup can be traced back to where it was
 *   made. The environment details only leave when the box is ticked, and what they are is
 *   listed on the form rather than described - see essentials(), which is the whole set.
 */
class Optin
{
    /**
     * Empty until answered, then `yes`, or `shared` when the environment box was ticked.
     *
     * Its own option rather than a key in `__fls_auth_settings`: that array is replaced
     * wholesale on every settings save, so a flag kept inside it would be erased by the
     * first post that did not know to carry it.
     */
    const OPTION = '__fls_auth_optin';

    /** Unix timestamp of the last "not now". */
    const DISMISSED_OPTION = '__fls_auth_optin_dismissed';

    /** How long a dismissal holds, in days. */
    const DISMISS_DAYS = 7;

    /**
     * Where a signup goes.
     *
     * The alerts relay, which calls FluentCRM on our behalf - not FluentCRM directly. The
     * difference matters: posting straight to the CRM means a credential for it in a GPL
     * plugin that ships to every WordPress install, which is not a credential. One service
     * holds the key and every install talks to that.
     *
     * Unauthenticated by design, for the same reason. This form runs in the setup wizard,
     * before a site has registered for anything, so there is no key it could send. What
     * stands in for one is the confirmation email: the worst an abuser gets out of this
     * endpoint is one email to an address they do not own, which is the bound every signup
     * form on the internet already lives with. Rate limits at the relay do the rest.
     */
    const ENDPOINT = 'https://dash.fluentauth.com/api/v1/optin';

    /**
     * @return string
     */
    public static function getEndpoint()
    {
        return apply_filters('fluent_auth/optin_url', self::ENDPOINT);
    }

    /**
     * @return bool
     */
    public static function hasSubscribed()
    {
        return (bool)get_option(self::OPTION);
    }

    /**
     * Whether the question is still open on this site.
     *
     * Read by both screens that ask it, and by the admin bootstrap that tells them to.
     *
     * @return bool
     */
    public static function isRequired()
    {
        if (self::hasSubscribed()) {
            return false;
        }

        $dismissedAt = (int)get_option(self::DISMISSED_OPTION);

        if ($dismissedAt && (time() - $dismissedAt) < self::DISMISS_DAYS * DAY_IN_SECONDS) {
            return false;
        }

        if (self::hasRegisteredForAlerts()) {
            return false;
        }

        return (bool)apply_filters('fluent_auth/show_optin', true);
    }

    /**
     * Whether this site has already handed its administrator's details to the service.
     *
     * Connecting for scan alerts posts a name and an address to the relay and confirms the
     * address by email, which is a longer version of the same form - so asking again is
     * asking somebody for something they have already given. The card stays away.
     *
     * Read live rather than recorded, so a site that connects the scanner after seeing this
     * card stops being asked from that moment, without a flag of its own that could disagree
     * with the connection it describes.
     *
     * Note what this does *not* mean. The registration form promises the address will be used
     * for the API key and security alerts only; it is not consent to a release-notes list, and
     * nothing here adds anybody to one. All this decides is that we stop asking.
     *
     * @return bool
     */
    public static function hasRegisteredForAlerts()
    {
        $settings = IntegrityHelper::getSettings();

        /*
         * `self` is scanning with no service behind it, and `unregistered` never got that far -
         * neither has sent an address anywhere. A revoked site is put back to `unregistered`
         * with its account email cleared, so it is asked again, which is right: the relay no
         * longer holds anything about it.
         */
        if (in_array(Arr::get($settings, 'status'), ['pending', 'active', 'disabled'], true)) {
            return true;
        }

        /*
         * The belt to that brace. A site connected by pasting an account-level key never sets
         * `account_email_id`, and one could imagine the reverse too - so whichever of the two
         * says this site is known, it is known.
         */
        return (bool)Arr::get($settings, 'account_email_id');
    }

    /**
     * @param string $email
     * @param string $fullName
     * @param bool   $shareEssentials
     * @return array|\WP_Error
     */
    public static function subscribe($email, $fullName, $shareEssentials = false)
    {
        $email = sanitize_email($email);
        $fullName = sanitize_text_field($fullName);

        if (!$email || !is_email($email)) {
            return new \WP_Error(
                'invalid_email',
                __('That email address is not valid.', 'fluent-security'),
                ['status' => 422]
            );
        }

        /*
         * Sent before anything is recorded, unlike the plugin this pattern comes from. A
         * site that stored the answer first and failed to deliver it would stop asking and
         * never appear on the list, which is the one outcome nobody can detect afterwards.
         */
        $pushed = self::push($email, $fullName, $shareEssentials);

        if (is_wp_error($pushed)) {
            return $pushed;
        }

        update_option(self::OPTION, $shareEssentials ? 'shared' : 'yes', false);
        delete_option(self::DISMISSED_OPTION);

        /*
         * The relay reports the contact's status and the message follows it.
         *
         * Two outcomes worth telling apart. `subscribed` is somebody already confirmed -
         * telling them to go and check their inbox would send them looking for mail that is
         * never sent. `pending` is a fresh signup with a confirmation on its way, and that is
         * the one case where "check your inbox" is a true thing to say.
         *
         * Anything else, including a relay too old to say, is treated as pending: it is the
         * ordinary outcome, and the worst it costs a reader is being pointed at an inbox they
         * did not need to check.
         */
        $status = is_string($pushed) && $pushed ? $pushed : 'pending';
        $confirmed = in_array($status, ['subscribed', 'already_subscribed'], true);

        return [
            'optin_status' => $status,
            /*
             * Said once, and then never again. Whether they go on to click the link in that
             * email is between them and their inbox - this plugin does not find out, does not
             * ask again, and does not chase it. An unconfirmed address is the reader's to fix,
             * and a site that nagged about one would be a security plugin spending its
             * attention budget on a mailing list.
             */
            'message' => $confirmed
                ? __('You are subscribed. You will only get update notifications.', 'fluent-security')
                : __('Check your inbox to verify your email address.', 'fluent-security')
        ];
    }

    /**
     * Not now: parks the card for DISMISS_DAYS.
     *
     * @return array
     */
    public static function dismiss()
    {
        update_option(self::DISMISSED_OPTION, time(), false);

        return [
            'message' => __('Dismissed.', 'fluent-security')
        ];
    }

    /**
     * @param string $email
     * @param string $fullName
     * @param bool   $shareEssentials
     * @return string|\WP_Error the relay's `optin_status`; 'pending' when it does not say
     */
    private static function push($email, $fullName, $shareEssentials)
    {
        $payload = [
            'full_name'       => $fullName,
            'email'           => $email,
            'source'          => 'fluentauth',
            /* `site_url` rather than a name of its own: every other route this service has
               calls it that, and one field should not have two names across four endpoints. */
            'site_url'        => site_url(),
            'share_essential' => $shareEssentials ? 'yes' : 'no'
        ];

        /*
         * Only when asked for, and only what the checkbox names. The form lists these three
         * in full rather than summarising them, so this array and that sentence have to stay
         * the same length - anything added here is a promise broken on the screen.
         */
        if ($shareEssentials) {
            $payload['essentials'] = self::essentials();
        }

        $response = wp_remote_post(self::getEndpoint(), [
            'body'    => json_encode($payload),
            'headers' => [
                'Content-Type' => 'application/json'
            ],
            'timeout' => 20
        ]);

        if (is_wp_error($response)) {
            return new \WP_Error(
                'optin_failed',
                __('Could not reach the subscription service. Please try again.', 'fluent-security'),
                ['status' => 502]
            );
        }

        $code = (int)wp_remote_retrieve_response_code($response);
        $body = json_decode((string)wp_remote_retrieve_body($response), true);

        if ($code < 200 || $code > 299) {
            /*
             * Two different things come back from a refusal, and they are not interchangeable.
             *
             * `message` is display text. It gets reworded for clarity, softened after a
             * support ticket, or corrected for a typo - so it is shown to the reader and
             * nothing is ever decided on it. A CRM that refused an address knows why, and
             * "please try again later" is the wrong thing to tell somebody who mistyped it.
             *
             * `error_code` is the contract. It is carried here so that anything which needs
             * to tell one refusal from another has a stable thing to read - and so that the
             * tests can assert the contract rather than pinning somebody else's prose, which
             * would turn every improvement to their wording into a failure here.
             */
            $said = is_array($body) ? (string)Arr::get($body, 'message', '') : '';

            return new \WP_Error(
                'optin_failed',
                $said ?: __('The subscription service rejected the request. Please try again later.', 'fluent-security'),
                [
                    'status'           => 502,
                    'relay_error_code' => is_array($body) ? (string)Arr::get($body, 'error_code', '') : ''
                ]
            );
        }

        return is_array($body) ? (string)Arr::get($body, 'data.optin_status', 'pending') : 'pending';
    }

    /**
     * The environment details, and nothing beyond them.
     *
     * Three versions, and deliberately not the list of installed plugins. The versions
     * answer a question that changes what gets built - which PHP and WordPress minimums can
     * be raised, and when - so they earn the consent the checkbox asks for. A plugin
     * inventory does not: on a contact record it is not queryable in a way that decides
     * anything, it is a competitive-intelligence dataset sitting in a marketing system with
     * looser access control than the scan database, and a tooltip offering to help us test
     * releases is not consent to catalogue somebody's site.
     *
     * It would also be an inventory posted to an endpoint that needs no credentials. The
     * place that list is honestly collected is the scanner, where the site has explicitly
     * connected for exactly that purpose and the consent matches the use.
     *
     * @return array<string, string>
     */
    private static function essentials()
    {
        global $wpdb;

        return [
            'php_version'   => PHP_VERSION,
            'mysql_version' => $wpdb->db_version(),
            'wp_version'    => get_bloginfo('version')
        ];
    }
}
