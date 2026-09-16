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
 * A scope is recorded once, on first sight, without asking. The alternative was to open with
 * "4 files are running that WordPress did not put there" on a site whose host put them there,
 * and being wrong on the first day is how a security tool teaches people to ignore it. What
 * is given up is the day this plugin was installed: a site already broken into when it
 * arrives records the backdoor as normal. Every tool that learns a baseline makes that trade,
 * and the alternative here was not making it - it was asking a question most readers cannot
 * answer.
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
     * Whether this part of the tree has ever been recorded.
     *
     * Its own flag rather than "are there any hashes here", because those are two different
     * facts and only one of them is safe to act on. A site whose mu-plugins were all removed
     * and replaced has no hashes under that prefix - and treating that as never-recorded is
     * how a directory emptied and refilled gets silently blessed, which is a thing an
     * attacker can arrange and a host cannot.
     *
     * @param string $scope
     * @return bool
     */
    public static function hasBaseline($scope)
    {
        $baselined = Arr::get(IntegrityHelper::getIgnoreLists(), 'baselined', []);

        return is_array($baselined) && isset($baselined[$scope]);
    }

    /**
     * @param string $scope
     * @return int|null unix time it was first recorded, or null
     */
    public static function baselinedAt($scope)
    {
        $baselined = Arr::get(IntegrityHelper::getIgnoreLists(), 'baselined', []);

        return isset($baselined[$scope]) ? (int)$baselined[$scope] : null;
    }

    /**
     * Record everything in a scope as it stands, and remember that we did.
     *
     * @param string $scope
     * @param array $hashes path => hash
     * @return void
     */
    public static function baseline($scope, $hashes)
    {
        $lists = IntegrityHelper::getIgnoreLists();

        $lists['hashes'] = array_merge(self::all(), $hashes);
        $baselined = Arr::get($lists, 'baselined', []);
        $baselined[$scope] = time();
        $lists['baselined'] = is_array($baselined) ? $baselined : [$scope => time()];

        IntegrityHelper::updateIgnoreLists($lists);
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
     * Takes a predicate rather than a path prefix, because the two checks that use this do not
     * both own a subtree. The drop-ins are a fixed set of filenames sitting loose in
     * wp-content, and "everything under /wp-content/" is a prefix that swallows the
     * mu-plugins record as well - which is a check quietly forgetting another check's work,
     * and it forgets it in the direction that makes a planted file read as expected.
     *
     * @param array $known paths currently present
     * @param callable $owns whether a recorded path belongs to the caller
     * @return void
     */
    public static function forgetMissing($known, $owns)
    {
        $accepted = self::all();
        $kept = [];

        foreach ($accepted as $path => $hash) {
            if (!call_user_func($owns, $path) || in_array($path, $known, true)) {
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
