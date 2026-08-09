<?php

namespace FluentAuth\App\Services\Checks;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * Files the site has vouched for, and what they looked like when it did.
 *
 * "Ignore this path" and "this file is fine as it is" are different promises, and only the
 * second one is worth making. A path on the old ignore list is never mentioned again however
 * it changes - which is the wrong answer for exactly the files this is used on, since a
 * backdoor that replaces an accepted mu-plugin is the case the check exists to catch. So
 * accepting records the hash, and a second change speaks up again.
 *
 * Kept in the ignore list option the scan screen already owns, under its own key, so there is
 * one place a site's "yes, I know" lives and one Reset button that clears it. It is a handful
 * of mu-plugins and drop-ins rather than a hashed wp-content, so it fits in an option row -
 * the full baseline, when it comes, needs a table and does not belong here.
 *
 * Paths are root-relative with a leading slash, the way the rest of the ignore list names
 * things, so the two halves cannot disagree about what a path is.
 */
class AcceptedFiles
{
    /**
     * @return array path => hash
     */
    public static function all()
    {
        $hashes = Arr::get(IntegrityHelper::getIgnoreLists(), 'hashes', []);

        return is_array($hashes) ? $hashes : [];
    }

    /**
     * Whether this file is exactly what was vouched for.
     *
     * @param string $path root-relative, leading slash
     * @param string $hash
     * @return bool
     */
    public static function isAccepted($path, $hash)
    {
        $accepted = self::all();

        if (isset($accepted[$path])) {
            return $accepted[$path] === $hash;
        }

        /*
         * An entry on the old unconditional list still means what it always meant. Sites that
         * silenced a path before this existed should not have it come back as a finding.
         */
        return in_array($path, Arr::get(IntegrityHelper::getIgnoreLists(), 'files', []), true);
    }

    /**
     * Whether this file was vouched for and is no longer what it was.
     *
     * The alarming case, and the reason accepting stores a hash at all.
     *
     * @param string $path
     * @param string $hash
     * @return bool
     */
    public static function hasChanged($path, $hash)
    {
        $accepted = self::all();

        return isset($accepted[$path]) && $accepted[$path] !== $hash;
    }

    /**
     * @param array $hashes path => hash
     * @return void
     */
    public static function acceptMany($hashes)
    {
        $lists = IntegrityHelper::getIgnoreLists();
        $lists['hashes'] = array_merge(self::all(), $hashes);

        IntegrityHelper::updateIgnoreLists($lists);
    }

    /**
     * Drop anything no longer on disk, so a removed file cannot sit in the list for ever.
     *
     * @param array $known paths currently present in the scopes this covers
     * @param string $prefix only forget within this part of the tree
     * @return void
     */
    public static function forgetMissing($known, $prefix)
    {
        $accepted = self::all();
        $kept = [];

        foreach ($accepted as $path => $hash) {
            if (strpos($path, $prefix) !== 0 || in_array($path, $known, true)) {
                $kept[$path] = $hash;
            }
        }

        if (count($kept) === count($accepted)) {
            return;
        }

        $lists = IntegrityHelper::getIgnoreLists();
        $lists['hashes'] = $kept;

        IntegrityHelper::updateIgnoreLists($lists);
    }

    /**
     * Take back every acceptance in one part of the tree.
     *
     * @param string $prefix
     * @return void
     */
    public static function forgetMany($prefix)
    {
        $accepted = self::all();

        $kept = array_filter($accepted, function ($path) use ($prefix) {
            return strpos($path, $prefix) !== 0;
        }, ARRAY_FILTER_USE_KEY);

        if (count($kept) === count($accepted)) {
            return;
        }

        $lists = IntegrityHelper::getIgnoreLists();
        $lists['hashes'] = $kept;

        IntegrityHelper::updateIgnoreLists($lists);
    }

    /**
     * @param string $absolutePath
     * @return string
     */
    public static function hash($absolutePath)
    {
        $hash = @md5_file($absolutePath);

        return $hash ? $hash : '';
    }

    /**
     * @param string $absolutePath
     * @return string root-relative, leading slash
     */
    public static function toRelative($absolutePath)
    {
        $root = wp_normalize_path(untrailingslashit(ABSPATH));
        $path = wp_normalize_path($absolutePath);

        if (strpos($path, $root) === 0) {
            $path = substr($path, strlen($root));
        }

        return '/' . ltrim($path, '/');
    }
}
