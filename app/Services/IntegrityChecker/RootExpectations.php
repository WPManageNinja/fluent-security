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
        '.idea',
        '.env',
        '.htaccess'
    ];

    /**
     * Logs and desktop litter, which are noise in any directory rather than only the root.
     *
     * Kept apart from the list above because this is the half that also applies inside
     * wp-admin and wp-includes: a PHP `error_log` lands wherever the code that errored was,
     * and the core walk was reporting `wp-admin/error_log` as a new file on every scan
     * because it only ever excluded names ending in `.log`.
     *
     * The other half deliberately does not travel with it. A kept copy - `wp-login.php.bak`
     * inside wp-admin - is silenced in the root only because BackupFilesCheck reports it
     * there instead, and that check looks at the root alone. Silencing those in core
     * directories too would mean a readable copy of a core file mentioned by neither.
     */
    const SYSTEM_NOISE_NAMES = [
        '.DS_Store',
        'error_log',
        'error.log',
        'php_errorlog',
        'php_error.log',
        'debug.log'
    ];

    /**
     * Files the web generates about itself, matched by the shape of their names.
     *
     * None of these can be in a checksum list and none of them can be made to run: they are
     * sitemaps an SEO plugin rewrites on every publish, the verification file a search
     * console asked somebody to upload, the icon a browser asks for. A root holding a dozen
     * of them produced the report that prompted this - eighteen lines of which seventeen
     * were furniture, and the one that mattered was a readable `wp-config.php.bkk` sitting
     * in the middle of them.
     *
     * Matched by name rather than by extension, and that is the whole care taken here. "Any
     * .xml is boring" also silences an .xml an attacker chose to leave; `sitemap_index.xml`
     * and `BingSiteAuth.xml` are names with an owner. Nothing that can execute is on this
     * list, and nothing on it is matched loosely enough to cover a name somebody picked.
     */
    const GENERATED_PATTERNS = [
        /* Sitemaps: core's own, Yoast's, Rank Math's, All in One SEO's. */
        '/^sitemap(_index)?\.xml(\.gz)?$/i',
        '/^[a-z0-9_-]+-sitemap\d*\.xml(\.gz)?$/i',
        '/^sitemap[a-z0-9_-]*\.xsl$/i',
        '/^wp-sitemap[a-z0-9_-]*\.(xml|xsl)$/i',
        '/^(main|local|video|news|image)-sitemap\.(xml|xsl)$/i',

        /* Ownership proofs. Each is a fixed shape a console handed somebody. */
        '/^google[0-9a-f]{8,}\.html$/i',
        '/^BingSiteAuth\.xml$/i',
        '/^yandex_[0-9a-f]{8,}\.(html|txt)$/i',
        '/^pinterest-[0-9a-z]+\.html$/i',
        '/^[a-z0-9]{32}\.txt$/i',

        /* Furniture a browser or a crawler asks for by name. */
        '/^favicon\.(ico|png|svg)$/i',
        '/^apple-touch-icon(-precomposed)?(-\d+x\d+)?\.png$/i',
        '/^(android-chrome|mstile)-\d+x\d+\.png$/i',
        '/^(robots|ads|app-ads|humans|security)\.txt$/i',
        '/^(browserconfig|opensearch)\.xml$/i',
        '/^(site\.webmanifest|manifest\.json)$/i',
        '/^[a-z0-9_-]*\.kml$/i'
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
     * Every name silenced anywhere in the root, both halves together.
     *
     * @return array<int, string>
     */
    public static function noiseNames()
    {
        return array_map(
            'strtolower',
            array_merge(self::NOISE_NAMES, self::SYSTEM_NOISE_NAMES)
        );
    }

    /**
     * @return array<int, string>
     */
    public static function generatedPatterns()
    {
        return (array)apply_filters(
            'fluent_auth/scan_generated_file_patterns',
            self::GENERATED_PATTERNS
        );
    }

    /**
     * A log or a piece of desktop litter, wherever it turned up.
     *
     * Asked of core directories as well as the root, which is the difference between this
     * and isNoise() - see SYSTEM_NOISE_NAMES for why only this half travels.
     *
     * @param string $name a single entry, no path
     * @return bool
     */
    public static function isSystemNoise($name)
    {
        $lower = strtolower($name);

        $names = array_map('strtolower', (array)apply_filters(
            'fluent_auth/scan_system_noise_names',
            self::SYSTEM_NOISE_NAMES
        ));

        return in_array($lower, $names, true);
    }

    /**
     * A file the site generated about itself rather than one somebody put there.
     *
     * @param string $name a single entry, no path
     * @return bool
     */
    public static function isGenerated($name)
    {
        foreach (self::generatedPatterns() as $pattern) {
            if (preg_match($pattern, $name)) {
                return true;
            }
        }

        return false;
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

        if (in_array($lower, self::noiseNames(), true)) {
            return true;
        }

        if (self::isGenerated($name)) {
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
     * Whether an `.htaccess` asks the server to run something.
     *
     * Deliberately a keyword test rather than a parse. Apache's grammar is large and the
     * question here is small - does this file mention any of the handful of directives that
     * can turn a file into a program - and a test that errs is better erring towards
     * reporting, which is why every directive that could is on the list and nothing is
     * excluded by context.
     *
     * A file too large to be a directory's own config is reported without being read: at
     * that size it is not what a host drops in `cgi-bin`.
     *
     * @param string $path
     * @return bool
     */
    public static function htaccessEnablesExecution($path)
    {
        $size = @filesize($path);

        if ($size === false || $size > 64 * 1024) {
            return true;
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            return true;
        }

        /*
         * Handlers and types map an extension onto an interpreter, `Action` and `Script`
         * hand a request to one, `ExecCGI` is the switch CGI needs, and the `php_` pair
         * carries `auto_prepend_file`, which runs code without any request naming it.
         */
        $directives = (array)apply_filters('fluent_auth/scan_htaccess_exec_directives', [
            'addhandler', 'sethandler', 'addtype', 'action', 'script',
            'execcgi', 'php_value', 'php_flag', 'php_admin_value', 'php_admin_flag',
            'auto_prepend_file', 'auto_append_file', 'cgi-script', 'fcgid', 'wsgi'
        ]);

        $lower = strtolower($contents);

        foreach ($directives as $directive) {
            if (strpos($lower, $directive) !== false) {
                return true;
            }
        }

        return false;
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

            /*
             * An `.htaccess` here is only interesting for what it turns on. Hosts ship one
             * in `cgi-bin` as a matter of course and ACME clients write one beside a
             * challenge, so hashing every `.htaccess` in these two directories reported a
             * file the host put there on every scan, forever - which is the noise this
             * class exists to refuse.
             *
             * Reading it is what keeps the signal the RUNNABLE list was after: the reason
             * `.htaccess` is on that list is that in a directory like this it decides what
             * else executes, and that intent is written in the file. One that says nothing
             * about handlers, CGI or prepended files cannot switch execution on, so it is
             * furniture; one that does is reported whatever else it contains.
             */
            if (strtolower($file->getExtension()) === 'htaccess'
                && !self::htaccessEnablesExecution($file->getPathname())) {
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
