<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * The slice of CBOR that WebAuthn actually uses.
 *
 * An authenticator emits two CBOR structures - the attestation object and the COSE
 * public key inside it - and between them they use six major types: unsigned and
 * negative integers, byte and text strings, arrays and maps. No tags, no floats, no
 * indefinite lengths, no bignums. Everything outside that is rejected rather than
 * interpreted, because this decoder only ever runs on bytes an attacker chose, and a
 * type we do not need is a type we cannot be wrong about.
 *
 * Two rules here are security properties rather than tidiness:
 *
 *   - A duplicate map key is refused. Left alone, the last one wins, so a hostile
 *     attestation object could carry one authData for anything that inspects it and
 *     another for the code that verifies it.
 *   - Nesting is capped. The structures we parse are two deep; a deeply nested input
 *     is nobody's authenticator, and without a cap it is a way to exhaust the stack
 *     from an unauthenticated request.
 *
 * Integers come back as PHP ints. A COSE label or length that needed 64 bits would be
 * meaningless in both structures, so the 8-byte length form is refused too rather
 * than risking a silent float conversion on a 32-bit build.
 */
class Cbor
{
    const MAX_DEPTH = 8;

    /** @var string */
    private $data;

    /** @var int */
    private $pos = 0;

    /**
     * Decodes one item and requires it to be the whole input.
     *
     * @param $bytes string
     * @return mixed
     * @throws WebAuthnException
     */
    public static function decode($bytes)
    {
        $value = self::decodeFirst($bytes, $consumed);

        if ($consumed !== strlen($bytes)) {
            throw new WebAuthnException('Trailing bytes after CBOR value');
        }

        return $value;
    }

    /**
     * Decodes one item and reports how many bytes it used.
     *
     * Needed because a COSE key sits in the middle of authenticator data rather than
     * at the end of it: where the key stops is the only thing that says where the
     * extension block starts.
     *
     * @param $bytes string
     * @param $consumed int
     * @return mixed
     * @throws WebAuthnException
     */
    public static function decodeFirst($bytes, &$consumed = null)
    {
        if (!is_string($bytes) || $bytes === '') {
            throw new WebAuthnException('Empty CBOR input');
        }

        $decoder = new self();
        $decoder->data = $bytes;

        $value = $decoder->readValue(0);
        $consumed = $decoder->pos;

        return $value;
    }

    /**
     * @param $depth int
     * @return mixed
     * @throws WebAuthnException
     */
    private function readValue($depth)
    {
        if ($depth > self::MAX_DEPTH) {
            throw new WebAuthnException('CBOR nesting too deep');
        }

        $initial = ord($this->take(1));
        $major = $initial >> 5;
        $argument = $this->readArgument($initial & 0x1f);

        switch ($major) {
            case 0:
                return $argument;
            case 1:
                return -1 - $argument;
            case 2:
            case 3:
                return $this->take($argument);
            case 4:
                return $this->readArray($argument, $depth);
            case 5:
                return $this->readMap($argument, $depth);
        }

        throw new WebAuthnException('Unsupported CBOR major type ' . $major);
    }

    /**
     * @param $count int
     * @param $depth int
     * @return array
     * @throws WebAuthnException
     */
    private function readArray($count, $depth)
    {
        $items = [];

        for ($i = 0; $i < $count; $i++) {
            $items[] = $this->readValue($depth + 1);
        }

        return $items;
    }

    /**
     * @param $count int
     * @param $depth int
     * @return array
     * @throws WebAuthnException
     */
    private function readMap($count, $depth)
    {
        $map = [];

        for ($i = 0; $i < $count; $i++) {
            $key = $this->readValue($depth + 1);

            if (!is_int($key) && !is_string($key)) {
                throw new WebAuthnException('CBOR map key must be an integer or a string');
            }

            /*
             * array_key_exists rather than isset: a key whose value is null is still a
             * key that has been seen, and isset() would wave the second one through.
             */
            if (array_key_exists($key, $map)) {
                throw new WebAuthnException('Duplicate CBOR map key');
            }

            $map[$key] = $this->readValue($depth + 1);
        }

        return $map;
    }

    /**
     * The length or immediate value carried by the initial byte.
     *
     * @param $additional int
     * @return int
     * @throws WebAuthnException
     */
    private function readArgument($additional)
    {
        if ($additional < 24) {
            return $additional;
        }

        if ($additional === 24) {
            return ord($this->take(1));
        }

        if ($additional === 25) {
            $parts = unpack('n', $this->take(2));
            return $parts[1];
        }

        if ($additional === 26) {
            $parts = unpack('N', $this->take(4));
            return $parts[1];
        }

        // 27 is the 64-bit form; 28-30 are reserved; 31 is the indefinite length marker.
        throw new WebAuthnException('Unsupported CBOR argument ' . $additional);
    }

    /**
     * @param $length int
     * @return string
     * @throws WebAuthnException
     */
    private function take($length)
    {
        if ($length < 0 || $this->pos + $length > strlen($this->data)) {
            throw new WebAuthnException('Truncated CBOR input');
        }

        $slice = substr($this->data, $this->pos, $length);
        $this->pos += $length;

        return $slice;
    }
}
