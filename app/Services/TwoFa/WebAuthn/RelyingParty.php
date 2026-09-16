<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * Who this site says it is, in the two spellings WebAuthn needs.
 *
 * The relying party id is a bare domain and is what a credential is permanently bound
 * to - change it and every passkey on the site stops resolving, with no error the user
 * can act on. The origin is scheme, host and port, and is what the browser reports
 * having visited.
 *
 * Both are derived from the site address rather than from the incoming request. Reading
 * them from the request would let whoever sent it choose which site the credential was
 * being created for.
 */
class RelyingParty
{
    /**
     * The host, with no scheme, port or path.
     *
     * Defaults to the exact host rather than the registrable domain above it. A
     * credential registered for "example.com" is usable by every subdomain of it, so
     * widening this is a decision a site should have to make on purpose - on a
     * multisite or a site that moves users between subdomains, through the filter.
     *
     * @return string
     */
    public static function getId()
    {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $host = is_string($host) ? strtolower($host) : '';

        return (string)apply_filters('fluent_auth/webauthn_rp_id', $host);
    }

    /**
     * @return string
     */
    public static function getName()
    {
        return (string)apply_filters('fluent_auth/webauthn_rp_name', get_bloginfo('name'));
    }

    /**
     * sha256 of the relying party id, which is what authenticator data carries.
     *
     * @return string
     */
    public static function getIdHash()
    {
        return hash('sha256', self::getId(), true);
    }

    /**
     * Every origin a ceremony may legitimately have been run from.
     *
     * One entry by default. A site reachable at both www and the bare domain has two
     * origins and only one set of credentials, so the second has to be added through
     * the filter - the alternative, accepting any host that ends in the relying party
     * id, is how an origin check stops being a check.
     *
     * @return array
     */
    public static function getAllowedOrigins()
    {
        $parts = wp_parse_url(home_url());

        if (!is_array($parts) || empty($parts['host']) || empty($parts['scheme'])) {
            return [];
        }

        $origin = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);

        /*
         * The default ports are implicit in an origin and must not be written out;
         * anything else is part of it and must be.
         */
        if (!empty($parts['port'])) {
            $port = (int)$parts['port'];
            $isDefault = ($parts['scheme'] === 'https' && $port === 443)
                || ($parts['scheme'] === 'http' && $port === 80);

            if (!$isDefault) {
                $origin .= ':' . $port;
            }
        }

        $origins = apply_filters('fluent_auth/webauthn_allowed_origins', [$origin]);

        return array_values(array_filter((array)$origins, 'is_string'));
    }

    /**
     * Whether this site can run a ceremony at all.
     *
     * Browsers refuse WebAuthn outside a secure context, so on a plain http site the
     * feature cannot work and should not be offered. localhost is the exception every
     * browser makes, which is what keeps this usable in development.
     *
     * @return bool
     */
    public static function isSecureContext()
    {
        $parts = wp_parse_url(home_url());
        $scheme = is_array($parts) && !empty($parts['scheme']) ? $parts['scheme'] : '';
        $host = is_array($parts) && !empty($parts['host']) ? strtolower($parts['host']) : '';

        if ($scheme === 'https') {
            return true;
        }

        return $host === 'localhost' || $host === '127.0.0.1' || substr($host, -10) === '.localhost';
    }

    /**
     * Whether the server can verify a signature at all.
     *
     * @return bool
     */
    public static function isSupported()
    {
        return function_exists('openssl_verify') && self::isSecureContext() && self::getId() !== '';
    }
}
