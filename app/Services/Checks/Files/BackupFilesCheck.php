<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\IntegrityChecker\RootExpectations;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Archives and database dumps sitting in the web root.
 *
 * A file left beside index.php can be downloaded by anyone who guesses its name, and the
 * things people leave there are the whole site and the whole database. No break-in is needed:
 * a database dump contains every password hash and the keys in wp-config, and a site archive
 * contains wp-config itself.
 *
 * Only the root is looked at, and only names that are unambiguously a copy of something. The
 * point is to have almost no false positives - a check that flags ordinary files is one whose
 * findings get skipped, and this is a finding nobody should skip.
 */
class BackupFilesCheck extends Check
{
    public function id()
    {
        return 'backup_files';
    }

    public function group()
    {
        return 'files';
    }

    public function run()
    {
        $found = $this->find();

        if (!$found) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('No downloadable copies of your site are lying about', 'fluent-security'),
                'scored' => true
            ])];
        }

        if (Dismissals::has($this->id())) {
            return [new Finding([
                'id'      => $this->id(),
                'check'   => $this->id(),
                'group'   => $this->group(),
                'state'   => Finding::STATE_ACCEPTED,
                'title'   => __('Backup files in your site\'s folder', 'fluent-security'),
                'why'     => __('You have said this one is not for your site.', 'fluent-security'),
                'details' => $found,
                'scored'  => false
            ])];
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $this->title(count($found)),
            'why'      => __('Anyone who guesses the name can download these. A database dump holds every password on your site; a site archive holds your database details.', 'fluent-security'),
            'details'  => array_merge($found, [
                __('Move these somewhere outside your website\'s folder, or delete them.', 'fluent-security')
            ]),
            /*
             * Reported, never deleted. These are somebody's own files and they may be the only
             * copy of something - this plugin is not going to be the reason a backup vanishes.
             */
            'action'   => 'none',
            'dismiss'  => 'ignore',
            'scored'   => true
        ])];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('That is not something this plugin knows how to check.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::add($this->id());

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error('unknown_check', __('There is nothing to undo for this one.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::remove($this->id());

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }

    /**
     * @return array file names, relative to the site root
     */
    protected function find()
    {
        /*
         * Deliberately narrow. Every one of these is a copy of something rather than a file a
         * site needs to run - .zip and .sql have no business in a web root, and the wp-config
         * variants are the exact names people leave behind while editing it.
         */
        $patterns = apply_filters('fluent_auth/backup_file_patterns', [
            '/\.(sql|sql\.gz|zip|tar|tar\.gz|tgz|rar|7z|bak|old|orig|save|swp)$/i',
            '/^wp-config\.php\.[a-z0-9~]+$/i',
            '/^wp-config\.(bak|old|orig|save|txt)$/i'
        ]);

        /*
         * The same list the integrity scan silences by, which is why it is read from there
         * rather than restated here.
         *
         * The scan drops a kept copy on purpose - an `index.php~` is not a changed core file
         * and reporting it there would be noise. But the two lists had drifted, so the
         * suffixes the scan silenced and this check never learned about (.bk, .back, .backup,
         * .tmp, .copy, ~, _bak, _old, _backup) were reported by neither: a readable copy of
         * wp-login.php or .htaccess sitting in the web root, which is exactly the kind of file
         * this check exists for, and the server hands it over as plain text because only the
         * exact name `.htaccess` is protected.
         *
         * Silence in the scan is now a report here, and one list decides both.
         */
        $suffixes = RootExpectations::backupSuffixes();

        $root = untrailingslashit(ABSPATH);
        $entries = @scandir($root);

        if (!$entries) {
            return [];
        }

        $found = [];

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || !is_file($root . '/' . $entry)) {
                continue;
            }

            if ($this->looksKept($entry, $patterns, $suffixes)) {
                $size = @filesize($root . '/' . $entry);

                $found[] = $size
                    ? sprintf('/%s (%s)', $entry, size_format($size))
                    : '/' . $entry;
            }
        }

        return $found;
    }

    /**
     * Whether a root entry is an archive, a dump, or somebody's kept copy of a file.
     *
     * @param string $entry
     * @param array  $patterns
     * @param array  $suffixes
     * @return bool
     */
    protected function looksKept($entry, $patterns, $suffixes)
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $entry)) {
                return true;
            }
        }

        $lower = strtolower($entry);

        foreach ($suffixes as $suffix) {
            if (substr($lower, -strlen($suffix)) === $suffix) {
                return true;
            }
        }

        /*
         * `.htaccess.bk`, `.htaccess_old`, `.htaccess-2024`. Named separately because the
         * suffix rule cannot see them - the distinguishing part is in the middle - and
         * because this is the copy with the most to give away: the rules protecting
         * everything else on the site, served as text.
         */
        return strpos($lower, '.htaccess.') === 0
            || strpos($lower, '.htaccess_') === 0
            || strpos($lower, '.htaccess-') === 0;
    }

    /**
     * @param int $count
     * @return string
     */
    protected function title($count)
    {
        return sprintf(
            /* translators: %s: number of files */
            _n(
                'A file in your site\'s folder can be downloaded by anyone',
                '%s files in your site\'s folder can be downloaded by anyone',
                $count,
                'fluent-security'
            ),
            number_format_i18n($count)
        );
    }
}
