<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * Base64url, which is how WebAuthn spells every binary field that crosses into JSON.
 *
 * Decoding is strict on purpose. PHP's tolerant mode silently discards anything it
 * does not recognise, so a malformed challenge would come back as a shorter string
 * rather than as a failure - and two different malformed challenges can decode to the
 * same shorter string. Every comparison in this package is against a value that came
 * through here, so a tolerant decoder would be a way to make unequal things compare
 * equal.
 */
class Base64Url
{
    /**
     * @param $bytes string
     * @return string
     */
    public static function encode($bytes)
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @param $text string
     * @return string|false false when the input is not valid base64url
     */
    public static function decode($text)
    {
        if (!is_string($text) || $text === '') {
            return false;
        }

        if (!preg_match('/^[A-Za-z0-9\-_]+$/', $text)) {
            return false;
        }

        $padded = strtr($text, '-_', '+/');

        // A base64 quantum is four characters; a remainder of one is never valid.
        $remainder = strlen($padded) % 4;

        if ($remainder === 1) {
            return false;
        }

        if ($remainder) {
            $padded .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode($padded, true);
    }
}
