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
 * Which is why the first sight of these says nothing at all. Plenty of hosts ship mu-plugins,
 * and plenty of caching plugins install a drop-in; a plugin that opened with "4 files are
 * running that WordPress did not put there - fix this" would be wrong on most sites on its
 * first day, and being wrong once is how a security tool teaches people to ignore it.
 *
 * It used to open with an invitation to look instead, which was gentler and still wrong: the
 * row was scored, so a site sat below full marks until somebody clicked a button about their
 * host's own files. A score that is gated on an acknowledgement is not measuring the site.
 *
 * So what is there on the first run is recorded silently, and from then on anything new or
 * changed is the alarm - which is the only claim here that can actually be stood behind. The
 * files themselves are listed on the scan screen, where somebody can read them at their own
 * pace rather than because a row asked them to.
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
     * Copy, keyed: appeared_why, alert_title, alert_why, none_title.
     *
     * @return array
     */
    abstract protected function words();

    /**
     * The heading when everything here is as it was.
     *
     * Its own method rather than a format string in words(), because it counts things and so
     * needs _n() - and _n() has to be written where a translator can see both forms and the
     * sentence they belong to.
     *
     * @param int $count
     * @return string
     */
    abstract protected function watchedTitle($count);

    /**
     * The heading when files are here that were not here before.
     *
     * @param int $count
     * @return string
     */
    abstract protected function appearedTitle($count);

    public function run()
    {
        $current = $this->currentHashes();

        AcceptedFiles::forgetMissing(array_keys($current), function ($path) {
            return $this->owns($path);
        });

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

        /*
         * First run. Recorded without a word, because nothing has been learned about this site
         * yet - only about its host. Reported as passed rather than as nothing so the check
         * still appears in the list of what was looked at, with a title that says what was
         * actually done rather than implying somebody read them.
         */
        if (!AcceptedFiles::hasBaseline($this->scope())) {
            AcceptedFiles::baseline($this->scope(), $current);

            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => $this->watchedTitle(count($current)),
                'scored' => true
            ])];
        }

        $appeared = [];
        $changed = [];

        foreach ($current as $path => $hash) {
            if (AcceptedFiles::hasChanged($path, $hash)) {
                $changed[] = $path;
                continue;
            }

            if (!AcceptedFiles::isAccepted($path, $hash)) {
                $appeared[] = $path;
            }
        }

        if (!$appeared && !$changed) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => $this->watchedTitle(count($current)),
                'scored' => true
            ])];
        }

        /*
         * Both outcomes are the alarm, and neither outranks the other. A file that was here
         * and is no longer what it was, and a file that was not here at all, are the two
         * shapes the same event takes - and dropping something into mu-plugins is the more
         * common of the two, not the milder one.
         */
        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $changed ? $words['alert_title'] : $this->appearedTitle(count($appeared)),
            'why'      => $changed ? $words['alert_why'] : $words['appeared_why'],
            'details'  => $this->details($changed, $appeared),
            'action'   => 'none',
            'dismiss'  => 'expected',
            'scored'   => true
        ])];
    }

    /**
     * Whether a recorded path is this check's to forget.
     *
     * A subtree by default, which is what mu-plugins is. Overridden where it is not - see
     * DropInsCheck, whose files sit loose in wp-content beside everything else.
     *
     * @param string $path root-relative
     * @return bool
     */
    protected function owns($path)
    {
        return strpos($path, $this->scope()) === 0;
    }

    /**
     * @return array path => hash
     */
    protected function currentHashes()
    {
        $current = [];

        foreach ($this->paths() as $path) {
            $hash = AcceptedFiles::hash($path);

            if ($hash) {
                $current[AcceptedFiles::toRelative($path)] = $hash;
            }
        }

        return $current;
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
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
        }

        AcceptedFiles::forgetMany($this->scope());

        return [
            'message' => __('These are no longer marked as expected, so they are back on the list.', 'fluent-security')
        ];
    }

    /**
     * @param array $changed
     * @param array $appeared
     * @return array
     */
    protected function details($changed, $appeared)
    {
        $details = [];

        foreach ($changed as $path) {
            /* translators: %s: a file path */
            $details[] = sprintf(__('%s (changed)', 'fluent-security'), $path);
        }

        foreach ($appeared as $path) {
            /* translators: %s: a file path */
            $details[] = sprintf(__('%s (new)', 'fluent-security'), $path);
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
