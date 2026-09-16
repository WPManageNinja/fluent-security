<?php

namespace FluentAuth\App\Services\IntegrityChecker;

defined('ABSPATH') || exit;

/**
 * What belongs in a WordPress root that WordPress did not put there.
 *
 * The core scan compares the root against WP.org's checksums, so anything the checksums have
 * never heard of reads as a finding. That is right for a stray `wp-lo4in.php` and wrong for
 * the half-dozen things every host drops beside it: an `error_log` PHP wrote, an
 * `.htaccess.bk` somebody left behind, a `.well-known` the TLS certificate needs. None of
 * those can ever appear in a checksum list, so they are not weak signals - they are
 * guaranteed false positives, and a scan that opens with six of them is a scan people learn
 * to close.
 *
 * The distinction this class exists to make is that "expected" means two different things:
 *
 * - For a file, it means say nothing. An `error_log` is a log; there is no version of it
 *   that is interesting to an integrity check, so it is dropped outright.
 *
 * - For a directory, it means say nothing *about the directory*, and then go and look
 *   inside it. `.well-known` and `cgi-bin` are expected on most hosts and are also two of
 *   the best places on the filesystem to leave a web shell - `.well-known` because it is
 *   world-readable by design and written to by ACME clients, `cgi-bin` because executing
 *   things is what it is for. Both are good hiding places precisely because every scanner
 *   skips them.
 *
 * That second half is why this is not just a longer ignore list. Before it, the root scan
 * never walked any directory except wp-admin and wp-includes: a directory's *name* went on
 * the unknown-folders list and nothing inside it was ever hashed. So the noisy row was also
 * the only thing the scanner had to say about that subtree, and silencing it alone would
 * have turned the two likeliest drop spots into blind spots. Walking them for files that can
 * run code gives up the noise and gains the signal - a `.txt` challenge file is invisible,
 * a `.php` beside it is a finding.
 */
class RootExpectations
{
    /**
     * Directories that are expected beside WordPress, and are searched rather than listed.
     *
     * Deliberately short. Every name here is one whose contents stop being announced, so it
     * earns its place by being near-universal - not by being merely common.
     */
    const EXPECTED_DIRS = [
        '.well-known',
        'cgi-bin'
    ];

    /**
     * Files that can be made to run, wherever they are found.
     *
     * `.htaccess` is on the list because inside one of these directories it is not
     * configuration, it is the thing that decides what else in there executes.
     */
    const RUNNABLE = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht',
        'cgi', 'pl', 'py', 'sh', 'htaccess'
    ];

    /**
     * Names that are never worth reporting from the root.
     *
     * `.htaccess` itself is here for the reason it always was: WordPress rewrites it
     * whenever permalinks change, so it cannot be diffed against anything. That is a
     * statement about the integrity check only - whether its *contents* are suspicious is a
     * different question, and one this check was never able to answer.
     */
    const NOISE_NAMES = [
        '.git',
        '.gitignore',
        '.gitattributes',
        '.DS_Store',
        '.idea',
        '.env',
        '.htaccess',
        'error_log',
        'error.log',
        'php_errorlog',
        'php_error.log',
        'debug.log'
    ];

    /**
     * Suffixes that mean somebody kept a copy.
     *
     * `.bk` and the underscored forms were the gap: `.htaccess.bak` was already dropped and
     * `.htaccess.bk` was reported, which is the same leftover file reported or not on the
     * strength of how its author abbreviated.
     */
    const BACKUP_SUFFIXES = [
        '.bak', '.bk', '.back', '.backup', '.old', '.orig', '.save', '.swp',
        '.tmp', '.copy', '_bak', '_old', '_backup', '~'
    ];

    /**
     * The kept-copy suffixes, filterable, and read by the checklist as well as by the scan.
     *
     * Two surfaces, one list, deliberately: what the integrity scan drops as noise is what
     * the backup-files check reports as a finding. Adding a suffix here silences it in one
     * place and raises it in the other, which is the only arrangement where the two cannot
     * leave a kind of file unmentioned by both. See Checks\Files\BackupFilesCheck.
     *
     * @return array<int, string>
     */
    public static function backupSuffixes()
    {
        return array_map('strtolower', (array)apply_filters(
            'fluent_auth/scan_backup_suffixes',
            self::BACKUP_SUFFIXES
        ));
    }

    /**
     * @return array<int, string>
     */
    public static function expectedDirs()
    {
        return (array)apply_filters('fluent_auth/scan_expected_root_dirs', self::EXPECTED_DIRS);
    }

    /**
     * @return array<int, string>
     */
    public static function runnableExtensions()
    {
        return array_map('strtolower', (array)apply_filters(
            'fluent_auth/scan_runnable_extensions',
            self::RUNNABLE
        ));
    }

    /**
     * @param string $name a single root entry, no path
     * @return bool
     */
    public static function isExpectedDir($name)
    {
        return in_array($name, self::expectedDirs(), true);
    }

    /**
     * Whether a root file is one the integrity check should never mention.
     *
     * @param string $name a single root entry, no path
     * @return bool
     */
    public static function isNoise($name)
    {
        $lower = strtolower($name);

        if (in_array($lower, array_map('strtolower', self::NOISE_NAMES), true)) {
            return true;
        }

        /* `.htaccess.bk`, `.htaccess_old`, `.htaccess-2024` - a kept copy, however spelt. */
        if (strpos($lower, '.htaccess.') === 0 || strpos($lower, '.htaccess_') === 0
            || strpos($lower, '.htaccess-') === 0) {
            return true;
        }

        foreach (self::backupSuffixes() as $suffix) {
            if (substr($lower, -strlen($suffix)) === $suffix) {
                return true;
            }
        }

        return (bool)apply_filters('fluent_auth/scan_root_file_is_noise', false, $name);
    }

    /**
     * Everything under an expected directory that could be executed.
     *
     * Symlinks are not followed. A link in `.well-known` pointing at `/` would otherwise
     * walk the whole disk, and a link is not a file this directory holds anyway.
     *
     * @param string $absoluteDir
     * @param string $relativeDir root-relative, no leading slash
     * @return array<string, string> root-relative path => md5
     */
    public static function executablesIn($absoluteDir, $relativeDir)
    {
        if (!is_dir($absoluteDir)) {
            return [];
        }

        $runnable = self::runnableExtensions();
        $limit = (int)apply_filters('fluent_auth/scan_expected_dir_max_files', 2000);
        $found = [];
        $seen = 0;

        try {
            $iterator = new \RecursiveIteratorIterator(
                /* SKIP_DOTS only: without FOLLOW_SYMLINKS the iterator does not descend
                   through links, which is what keeps a link to / out of this walk. */
                new \RecursiveDirectoryIterator($absoluteDir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );
        } catch (\Exception $e) {
            return [];
        }

        foreach ($iterator as $file) {
            if (++$seen > $limit) {
                break;
            }

            if (!$file->isFile() || $file->isLink()) {
                continue;
            }

            if (!in_array(strtolower($file->getExtension()), $runnable, true)) {
                continue;
            }

            $relative = $relativeDir . '/' . str_replace(
                '\\',
                '/',
                ltrim(substr($file->getPathname(), strlen($absoluteDir)), '/\\')
            );

            $hash = @md5_file($file->getPathname());

            if ($hash) {
                $found[$relative] = $hash;
            }
        }

        return $found;
    }
}
