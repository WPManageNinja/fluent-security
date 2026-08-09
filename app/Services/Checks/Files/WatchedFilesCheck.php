<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Somewhere small that runs code, watched by hash.
 *
 * mu-plugins and the drop-ins share a shape: a short list of files WordPress executes without
 * anybody having activated them, no official copy to compare against, and no way to tell a
 * legitimate one from a planted one by looking at it. What can be told is whether it is the
 * same file as last time you looked.
 *
 * Which is why the first sight of these is not an alarm. Plenty of hosts ship mu-plugins, and
 * plenty of caching plugins install a drop-in; a plugin that opened with "4 files are running
 * that WordPress did not put there - fix this" would be wrong on most sites on its first day,
 * and being wrong once is how a security tool teaches people to ignore it. So the first sight
 * is an invitation to look, and once looked at, anything new or changed is the alarm - which
 * is the claim this can actually stand behind.
 */
abstract class WatchedFilesCheck extends Check
{
    public function group()
    {
        return 'files';
    }

    /**
     * The files to watch.
     *
     * @return array absolute paths
     */
    abstract protected function paths();

    /**
     * The part of the tree this check owns, root-relative, so accepting here cannot forget
     * an entry another check made.
     *
     * @return string
     */
    abstract protected function scope();

    /**
     * Copy, keyed: first_why, alert_title, alert_why, none_title.
     *
     * @return array
     */
    abstract protected function words();

    /**
     * The heading for files nobody has vouched for yet.
     *
     * Its own method rather than a format string in words(), because it counts things and so
     * needs _n() - and _n() has to be written where a translator can see both forms and the
     * sentence they belong to.
     *
     * @param int $count
     * @return string
     */
    abstract protected function firstTitle($count);

    public function run()
    {
        $current = [];

        foreach ($this->paths() as $path) {
            $hash = AcceptedFiles::hash($path);

            if ($hash) {
                $current[AcceptedFiles::toRelative($path)] = $hash;
            }
        }

        AcceptedFiles::forgetMissing(array_keys($current), $this->scope());

        $words = $this->words();

        if (!$current) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => $words['none_title'],
                'scored' => true
            ])];
        }

        $unaccounted = [];
        $changed = [];

        foreach ($current as $path => $hash) {
            if (AcceptedFiles::hasChanged($path, $hash)) {
                $changed[] = $path;
                continue;
            }

            if (!AcceptedFiles::isAccepted($path, $hash)) {
                $unaccounted[] = $path;
            }
        }

        if (!$unaccounted && !$changed) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => $words['none_title'],
                'scored' => true
            ])];
        }

        /*
         * A file that was vouched for and is no longer what it was outranks one that has
         * simply never been looked at - the first is a change somebody made to code that runs
         * on every request, the second is most likely the host's.
         */
        $isAlarm = !empty($changed);

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => $isAlarm ? Finding::SEVERITY_FIX : Finding::SEVERITY_LOOK,
            'title'    => $isAlarm ? $words['alert_title'] : $this->firstTitle(count($unaccounted)),
            'why'      => $isAlarm ? $words['alert_why'] : $words['first_why'],
            'details'  => $this->details($changed, $unaccounted),
            'action'   => 'none',
            'dismiss'  => 'expected',
            'scored'   => true
        ])];
    }

    /**
     * Vouch for everything as it stands right now.
     *
     * Deliberately whole-scope rather than per file: the reader is answering one question -
     * "yes, I have looked at these" - and asking it once per file would be asking them to do
     * the sorting the check is meant to do.
     *
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
        }

        $hashes = [];

        foreach ($this->paths() as $path) {
            $hash = AcceptedFiles::hash($path);

            if ($hash) {
                $hashes[AcceptedFiles::toRelative($path)] = $hash;
            }
        }

        AcceptedFiles::acceptMany($hashes);

        return [
            'message' => __('Noted. You will hear about these again only if they change.', 'fluent-security')
        ];
    }

    /**
     * @param array $changed
     * @param array $unaccounted
     * @return array
     */
    protected function details($changed, $unaccounted)
    {
        $details = [];

        foreach ($changed as $path) {
            /* translators: %s: a file path */
            $details[] = sprintf(__('%s — changed since you accepted it', 'fluent-security'), $path);
        }

        foreach ($unaccounted as $path) {
            $details[] = $path;
        }

        return $details;
    }

    /**
     * @param string $directory
     * @return array absolute paths
     */
    protected function phpFilesIn($directory)
    {
        if (!is_dir($directory)) {
            return [];
        }

        $found = [];

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                    $found[] = $file->getPathname();
                }
            }
        } catch (\Exception $exception) {
            return [];
        }

        sort($found);

        return $found;
    }
}
