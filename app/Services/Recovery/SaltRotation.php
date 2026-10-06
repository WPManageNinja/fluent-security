<?php

namespace FluentAuth\App\Services\Recovery;

use FluentAuth\App\Services\ConfigWriter;

/**
 * Changing the eight security keys in wp-config.php.
 *
 * The one thing on the recovery screen that destroys something belonging to software this
 * plugin did not write, which is why it is opt-in, never the default, and never bundled
 * into another action. Rotating the keys signs out every cookie on the site, which is the
 * reason people are told to do it after a break-in. It also makes unreadable anything any
 * *other* plugin encrypted with a key derived from them - an SMTP password, a payment
 * gateway secret, a stored API token - and there is no way to enumerate which plugins did
 * that. The site owner finds out the next time something tries to send an email.
 *
 * So the warning next to the checkbox is the feature. The rotation itself is a file edit.
 *
 * FluentAuth is deliberately not among the casualties, and the screen says so, because a
 * warning with nothing on the other side of it just makes people abandon a recovery halfway
 * through. The relay credentials are stored as they were minted, not encrypted against
 * anything - see IntegrityHelper::getSettings() - and authenticator secrets refuse to derive
 * their key from AUTH_SALT for exactly this reason, which is written out at SecretKey.php:14.
 * Both of those were decisions taken before this class existed; this is the case they were
 * anticipating.
 *
 * What it will not do is guess. Where the keys are not plain values in wp-config.php - a
 * Bedrock install reading .env, a host that keeps them in an include, or a site where the
 * constants were never defined at all and wp_salt() has been inventing them into the options
 * table - this refuses and says where they really live. Rewriting the file on those installs
 * would change nothing while reporting success, which on a screen somebody is using to
 * recover a compromised site is the worst answer available.
 */
class SaltRotation
{
    /**
     * The eight, in the order WordPress writes them.
     *
     * All of them or none. Four of the eight are what signs cookies and four are what salts
     * the hashes; a site left with half the set rotated boots, refuses every cookie, and
     * gives its owner a false account of what was changed.
     */
    const KEYS = [
        'AUTH_KEY',
        'SECURE_AUTH_KEY',
        'LOGGED_IN_KEY',
        'NONCE_KEY',
        'AUTH_SALT',
        'SECURE_AUTH_SALT',
        'LOGGED_IN_SALT',
        'NONCE_SALT'
    ];

    /**
     * Whether the checkbox can be offered here, and what to say instead when it cannot.
     *
     * Answered on page load rather than after a failed attempt. A person who has just been
     * broken into should not discover that this was never going to work at the moment they
     * confirm it.
     *
     * @return array
     */
    public static function state()
    {
        $config = ConfigWriter::state();

        if (!$config['found']) {
            return self::unavailable(
                __('Your wp-config.php could not be found, so the keys cannot be changed from here.', 'fluent-security')
            );
        }

        if ($config['blocked']) {
            return self::unavailable(
                __('This site is set up so that plugins cannot edit its files, so the keys have to be changed by hand.', 'fluent-security')
            );
        }

        if ($config['linked']) {
            return self::unavailable(
                __('Your wp-config.php is a symbolic link to a file something else maintains, so the keys have to be changed there.', 'fluent-security')
            );
        }

        if (!$config['writable']) {
            return self::unavailable(
                __('Your wp-config.php is not writable, which is usual on managed hosting, so the keys have to be changed by hand.', 'fluent-security')
            );
        }

        if (!self::keysAreLiteral()) {
            return self::unavailable(
                __('This site does not keep its security keys as plain values in wp-config.php - they come from somewhere else, such as an environment file - so they have to be changed there.', 'fluent-security')
            );
        }

        return [
            'available' => true,
            'reason'    => '',
            'path'      => $config['path']
        ];
    }

    /**
     * Replace all eight with new random values.
     *
     * Returns the error rather than throwing it, because the caller has already signed
     * everybody out by the time this runs and needs to report both halves: the eviction
     * happened, the key change did not.
     *
     * @return true|\WP_Error
     */
    public static function rotate()
    {
        $state = self::state();

        if (!$state['available']) {
            return new \WP_Error('salts_unavailable', $state['reason'], ['status' => 422]);
        }

        $values = [];

        foreach (self::KEYS as $key) {
            $values[$key] = self::generate();
        }

        $result = ConfigWriter::replaceConstants($values);

        if (is_wp_error($result)) {
            return $result;
        }

        RecoveryService::log(
            'salts_rotated',
            __('Replaced the eight security keys in wp-config.php. Every cookie on the site stopped being valid.', 'fluent-security')
        );

        return true;
    }

    /**
     * Whether all eight are plain quoted values in the file, which is what makes them
     * replaceable. Asked by trying the replacement's own rule rather than a looser one, so
     * the checkbox is never offered for a rotation that would then refuse.
     *
     * @return bool
     */
    protected static function keysAreLiteral()
    {
        $path = ConfigWriter::path();
        $contents = $path ? file_get_contents($path) : '';

        if (!is_string($contents) || $contents === '') {
            return false;
        }

        foreach (self::KEYS as $key) {
            $pattern = '/define\s*\(\s*[\'"]' . preg_quote($key, '/') . '[\'"]\s*,\s*([\'"])[^\'"]*\1\s*\)/i';

            if (preg_match_all($pattern, $contents) !== 1) {
                return false;
            }
        }

        return true;
    }

    /**
     * One key's worth of random.
     *
     * Not wp_generate_password(), and not the wordpress.org secret-key service. The first
     * draws from a character set that includes things which cannot be written into a
     * single-quoted PHP string without escaping, and escaping into a file that is executed
     * as code is not a thing to be clever about. The second is a network call, made by a
     * site in the middle of recovering from a compromise, whose answer would be trusted to
     * become the thing that signs its cookies.
     *
     * Sixty-four characters from an alphabet of sixty-eight is about three hundred and
     * ninety bits, which is a long way past the point where more would mean anything.
     *
     * @return string
     */
    protected static function generate()
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/+=_-';
        $limit = strlen($alphabet) - 1;
        $value = '';

        for ($i = 0; $i < 64; $i++) {
            $value .= $alphabet[random_int(0, $limit)];
        }

        return $value;
    }

    /**
     * @param string $reason
     * @return array
     */
    protected static function unavailable($reason)
    {
        return [
            'available' => false,
            'reason'    => $reason,
            'path'      => ''
        ];
    }
}
