<?php

namespace FluentAuth\App\Services;

/**
 * Adding a constant to wp-config.php.
 *
 * This plugin will not edit wp-config.php to *fix* anything - see ConfigConstantCheck,
 * where the recommendations deliberately have no button. The distinction is consent: there
 * the plugin would be deciding to rewrite the file that boots the site on somebody's behalf,
 * off the back of advice they did not ask for. Here an administrator has asked for a key,
 * has been shown the exact line, and has pressed a button that says to add it. That is a
 * different act, and it is the only one this class exists for.
 *
 * Everything below is arranged around one rule: the original file is never in a partial
 * state. The new contents are written to a temporary file beside it and moved into place
 * with rename(), which is atomic within a filesystem - so a request that dies halfway
 * leaves a stray temp file, never a half-written wp-config.php. There is deliberately no
 * backup copy: a `wp-config.php.bak` in the web root is readable as plain text by anyone
 * who guesses the name, which this plugin's own BackupFilesCheck exists to report.
 *
 * It refuses far more often than it writes, and every refusal falls back to showing the
 * line for somebody to paste. Refusing is the safe outcome; writing is the convenience.
 */
class ConfigWriter
{
    /**
     * Where the line goes: above the marker WordPress has put in its own sample config for
     * years, and failing that, above the require that loads WordPress.
     *
     * Order matters. A constant defined *after* wp-settings.php is loaded is defined after
     * every plugin has already run, which for this purpose is the same as not defining it
     * at all - so appending to the end of the file is not a fallback, it is a silent
     * failure. Where neither anchor is found this class refuses rather than guesses.
     */
    const ANCHORS = [
        "/\\*\\s*That's all, stop editing/i",
        '/\\/\\*\\s*That is all, stop editing/i',
        '/require_once\\s*\\(?\\s*ABSPATH\\s*\\.\\s*[\'"]wp-settings\\.php[\'"]/i',
        '/require\\s*\\(?\\s*ABSPATH\\s*\\.\\s*[\'"]wp-settings\\.php[\'"]/i'
    ];

    /**
     * wp-config.php, which is not always where you would expect.
     *
     * WordPress supports keeping it one directory above the install so that it sits outside
     * the web root, and honours that only when the directory above is not itself another
     * install - the same condition wp-load.php applies. Filtered so a test can point this
     * somewhere harmless, and so an unusual layout can say where its file really is.
     *
     * @return string empty when it cannot be located
     */
    public static function path()
    {
        $path = '';

        if (file_exists(ABSPATH . 'wp-config.php')) {
            $path = ABSPATH . 'wp-config.php';
        } elseif (
            file_exists(dirname(ABSPATH) . '/wp-config.php')
            && !file_exists(dirname(ABSPATH) . '/wp-settings.php')
        ) {
            $path = dirname(ABSPATH) . '/wp-config.php';
        }

        $path = apply_filters('fluent_auth/wp_config_path', $path);

        return is_string($path) ? $path : '';
    }

    /**
     * Whether the site has told us not to touch its files.
     *
     * Both constants are honoured, though only the first is strictly about this.
     * DISALLOW_FILE_MODS is the signal hosts set to mean "nothing here writes to disk".
     * DISALLOW_FILE_EDIT is narrower - it turns off the built-in code editor - but a site
     * that set it has said it does not want PHP edited from the dashboard, and this is
     * exactly that. Anyone who disagrees can still paste the line in themselves, which
     * costs them a minute; guessing wrong the other way costs them their site.
     *
     * @return bool
     */
    public static function isBlocked()
    {
        $blocked = (defined('DISALLOW_FILE_MODS') && constant('DISALLOW_FILE_MODS'))
            || (defined('DISALLOW_FILE_EDIT') && constant('DISALLOW_FILE_EDIT'));

        /*
         * Filtered in both directions, because the two constants are a blunt instrument for
         * this. A platform that manages wp-config.php itself may want to refuse even where
         * neither is set; a Bedrock or CI-deployed site that sets DISALLOW_FILE_MODS as a
         * matter of course may still want this one line written. Whoever set up the site
         * knows which, and this plugin does not.
         */
        return (bool)apply_filters('fluent_auth/wp_config_write_blocked', $blocked);
    }

    /**
     * What the screen needs to know before it offers a button.
     *
     * Asked on load rather than after a failed attempt, so the copy can say "we will give
     * you a line to paste" up front. On managed hosting that is the normal answer.
     *
     * @return array
     */
    public static function state()
    {
        $path = self::path();
        $blocked = self::isBlocked();

        /*
         * A symlinked wp-config.php belongs to something else - a Bedrock layout, a shared
         * config across installs - and rename() would replace the link with a regular
         * file, quietly detaching it from whatever maintains it.
         */
        $linked = $path && is_link($path);

        return [
            // Relative, because an absolute server path in an admin screen is noise.
            'path'     => $path ? ltrim(str_replace(ABSPATH, '', $path), '/') : '',
            'found'    => (bool)$path,
            'writable' => (bool)$path && !$blocked && !$linked && is_writable($path),
            'blocked'  => $blocked,
            'linked'   => $linked
        ];
    }

    /**
     * Adds `define( 'NAME', 'value' );` above the anchor.
     *
     * @param string $name
     * @param string $value
     * @return true|\WP_Error
     */
    public static function addConstant($name, $value)
    {
        if (!preg_match('/^[A-Z][A-Z0-9_]*$/', (string)$name)) {
            return new \WP_Error('bad_name', __('That is not a valid constant name.', 'fluent-security'));
        }

        /*
         * The value is written into single quotes, so anything that could end the string or
         * open a new statement is refused rather than escaped. This is generated key
         * material - hex, in practice - so nothing legitimate is being turned away, and
         * escaping into a file that is executed as code is not a thing to be clever about.
         */
        if (!preg_match('/^[A-Za-z0-9_\-.:\/+=]{8,512}$/', (string)$value)) {
            return new \WP_Error('bad_value', __('That key contains characters that will not be written to a PHP file.', 'fluent-security'));
        }

        if (self::isBlocked()) {
            return new \WP_Error(
                'file_mods_disallowed',
                __('This site is configured so that plugins cannot edit its files, so the line has to be added by hand.', 'fluent-security')
            );
        }

        $path = self::path();

        if (!$path || !file_exists($path)) {
            return new \WP_Error(
                'not_found',
                __('Your wp-config.php could not be found, so the line has to be added by hand.', 'fluent-security')
            );
        }

        if (is_link($path)) {
            return new \WP_Error(
                'symlinked',
                __('Your wp-config.php is a symbolic link, which this will not replace. The line has to be added by hand.', 'fluent-security')
            );
        }

        if (!is_writable($path)) {
            return new \WP_Error(
                'not_writable',
                __('Your wp-config.php is not writable, which is usual on managed hosting. The line has to be added by hand.', 'fluent-security')
            );
        }

        $contents = file_get_contents($path);

        if ($contents === false || $contents === '') {
            return new \WP_Error(
                'not_readable',
                __('Your wp-config.php could not be read, so nothing has been changed.', 'fluent-security')
            );
        }

        /*
         * Already there. Never overwritten: a value on file is either the one this site is
         * already keyed to, or somebody else's - and replacing either is how a table full of
         * ciphertext stops being readable.
         */
        if (preg_match(self::definePattern($name), $contents)) {
            return new \WP_Error(
                'already_defined',
                sprintf(
                    /* translators: %s: the constant name */
                    __('%s is already in your wp-config.php. It has been left exactly as it is.', 'fluent-security'),
                    $name
                )
            );
        }

        $position = self::anchorPosition($contents);

        if ($position === false) {
            return new \WP_Error(
                'no_anchor',
                __('Your wp-config.php is laid out in a way this does not recognise, so the line has to be added by hand.', 'fluent-security')
            );
        }

        // Whatever the file already uses, so a Windows-edited config stays consistent.
        $newline = strpos($contents, "\r\n") !== false ? "\r\n" : "\n";

        $line = "define( '" . $name . "', '" . $value . "' );" . $newline . $newline;

        $updated = substr($contents, 0, $position) . $line . substr($contents, $position);

        return self::replaceFile($path, $contents, $updated, [self::definePattern($name)]);
    }

    /**
     * Replaces the value of constants that are already defined, all of them or none.
     *
     * The opposite of addConstant() in every way that matters, and the reason it is a
     * separate method rather than a flag. addConstant() will not overwrite a value because
     * a value on file is either the one the site is keyed to or somebody else's. This one
     * exists solely for the case where destroying the old value is the entire point - the
     * security keys, on a site being recovered - and the caller has said so.
     *
     * All or nothing, across every constant named. Half a rotated set of salts is worse
     * than none: WordPress would boot, cookies would be invalid, and the half that had not
     * moved would give a false sense of what had been changed. So the whole new file is
     * built in memory and only swapped in once every replacement has been made.
     *
     * Every constant must already be there, exactly once, with a literal quoted value.
     * Anything else - a name that appears twice, a value read from getenv() or a PHP
     * constant, a name not in the file at all - is refused without touching anything. That
     * refusal is what a Bedrock install and most managed hosting get, correctly: their keys
     * do not live in this file, and rewriting it would change nothing while claiming to.
     *
     * @param array $values name => new value
     * @return true|\WP_Error
     */
    public static function replaceConstants($values)
    {
        if (!is_array($values) || !$values) {
            return new \WP_Error('nothing_to_do', __('No constants were given to replace.', 'fluent-security'));
        }

        foreach ($values as $name => $value) {
            if (!preg_match('/^[A-Z][A-Z0-9_]*$/', (string)$name)) {
                return new \WP_Error('bad_name', __('That is not a valid constant name.', 'fluent-security'));
            }

            /* The same rule addConstant() applies, and for the same reason: this is written
             * into single quotes in a file that is executed as code, so a value that could
             * end the string is refused rather than escaped. */
            if (!preg_match('/^[A-Za-z0-9_\-.:\/+=]{8,512}$/', (string)$value)) {
                return new \WP_Error('bad_value', __('That key contains characters that will not be written to a PHP file.', 'fluent-security'));
            }
        }

        if (self::isBlocked()) {
            return new \WP_Error(
                'file_mods_disallowed',
                __('This site is configured so that plugins cannot edit its files, so the keys have to be changed by hand.', 'fluent-security')
            );
        }

        $path = self::path();

        if (!$path || !file_exists($path)) {
            return new \WP_Error(
                'not_found',
                __('Your wp-config.php could not be found, so the keys have to be changed by hand.', 'fluent-security')
            );
        }

        if (is_link($path)) {
            return new \WP_Error(
                'symlinked',
                __('Your wp-config.php is a symbolic link, which this will not replace. The keys have to be changed by hand.', 'fluent-security')
            );
        }

        if (!is_writable($path)) {
            return new \WP_Error(
                'not_writable',
                __('Your wp-config.php is not writable, which is usual on managed hosting. The keys have to be changed by hand.', 'fluent-security')
            );
        }

        $contents = file_get_contents($path);

        if ($contents === false || $contents === '') {
            return new \WP_Error(
                'not_readable',
                __('Your wp-config.php could not be read, so nothing has been changed.', 'fluent-security')
            );
        }

        $updated = $contents;
        $confirm = [];

        foreach ($values as $name => $value) {
            $pattern = self::literalDefinePattern($name);

            if (preg_match_all($pattern, $updated) !== 1) {
                return new \WP_Error(
                    'not_a_literal',
                    sprintf(
                        /* translators: %s: the constant name */
                        __('%s is not written in your wp-config.php as a plain value, so it cannot be changed from here.', 'fluent-security'),
                        $name
                    )
                );
            }

            /*
             * The replacement keeps whatever the line already looked like - the spacing and
             * the quote style around the name - and swaps only what is between the quotes of
             * the value. A file somebody has formatted their own way stays formatted that way.
             */
            $updated = preg_replace_callback(
                $pattern,
                function ($matches) use ($value) {
                    return $matches[1] . $value . $matches[4];
                },
                $updated,
                1
            );

            if ($updated === null) {
                return new \WP_Error(
                    'replace_failed',
                    __('The new wp-config.php could not be prepared, so nothing has been changed.', 'fluent-security')
                );
            }

            $confirm[] = '/define\s*\(\s*[\'"]' . preg_quote($name, '/') . '[\'"]\s*,\s*[\'"]' . preg_quote($value, '/') . '[\'"]\s*\)/';
        }

        return self::replaceFile($path, $contents, $updated, $confirm);
    }

    /**
     * Matches a whole `define( 'NAME', 'value' );` whose value is a quoted literal.
     *
     * Captured in three parts - everything up to the opening quote of the value, the value,
     * and everything after it - so a replacement can put a new value in without disturbing
     * how the line was written. A define whose value is anything other than a literal (a
     * getenv() call, another constant, a concatenation) does not match at all, which is the
     * point: those are managed somewhere else and this must not pretend to change them.
     *
     * @param string $name
     * @return string
     */
    protected static function literalDefinePattern($name)
    {
        return '/(define\s*\(\s*[\'"]' . preg_quote($name, '/') . '[\'"]\s*,\s*([\'"]))([^\'"]*)(\2\s*\))/i';
    }

    /**
     * Matches `define( 'NAME',` however it has been spaced or quoted.
     *
     * @param string $name
     * @return string
     */
    protected static function definePattern($name)
    {
        return '/define\s*\(\s*[\'"]' . preg_quote($name, '/') . '[\'"]/i';
    }

    /**
     * Where the new line starts, being the beginning of the anchor's own line.
     *
     * @param string $contents
     * @return int|false
     */
    protected static function anchorPosition($contents)
    {
        foreach (self::ANCHORS as $pattern) {
            if (!preg_match($pattern, $contents, $matches, PREG_OFFSET_CAPTURE)) {
                continue;
            }

            $offset = $matches[0][1];

            /*
             * Back up to the start of the line the anchor sits on, so the new define lands
             * above it rather than inside the comment that introduces it.
             */
            $lineStart = strrpos(substr($contents, 0, $offset), "\n");

            return $lineStart === false ? 0 : $lineStart + 1;
        }

        return false;
    }

    /**
     * Swaps the file's contents for new ones, atomically, or changes nothing.
     *
     * @param string $path
     * @param string $original
     * @param string $updated
     * @param array $confirm regexes that must all match the file afterwards, so the result
     *                       is confirmed rather than assumed
     * @return true|\WP_Error
     */
    protected static function replaceFile($path, $original, $updated, $confirm)
    {
        $directory = dirname($path);

        /*
         * Beside the file rather than in the system temp directory: rename() is only atomic
         * within one filesystem, and /tmp is frequently not the same one. A leading dot
         * keeps it from being served if it is ever left behind.
         */
        $temp = tempnam($directory, '.fls-cfg');

        if ($temp === false) {
            return new \WP_Error(
                'no_temp_file',
                __('A temporary file could not be created next to your wp-config.php, so nothing has been changed.', 'fluent-security')
            );
        }

        $written = file_put_contents($temp, $updated);

        /*
         * Length checked as well as the return value. A disk that fills up mid-write returns
         * the number of bytes it managed rather than false, and renaming that over
         * wp-config.php is the one outcome this whole class exists to avoid.
         */
        if ($written === false || $written !== strlen($updated)) {
            @unlink($temp);

            return new \WP_Error(
                'write_failed',
                __('The new wp-config.php could not be written in full, so nothing has been changed.', 'fluent-security')
            );
        }

        // Read back before it goes anywhere near the real path.
        if (file_get_contents($temp) !== $updated) {
            @unlink($temp);

            return new \WP_Error(
                'verify_failed',
                __('The new wp-config.php did not read back as expected, so nothing has been changed.', 'fluent-security')
            );
        }

        // tempnam() makes a file readable only by the owner; wp-config.php keeps its own.
        $permissions = @fileperms($path);

        if ($permissions !== false) {
            @chmod($temp, $permissions & 0777);
        }

        if (!@rename($temp, $path)) {
            @unlink($temp);

            return new \WP_Error(
                'rename_failed',
                __('The updated wp-config.php could not be moved into place, so nothing has been changed.', 'fluent-security')
            );
        }

        /*
         * Confirmed by reading the real file, never reported from the success of the write.
         * A rename that worked and a rename that was undone by something else a moment
         * later are indistinguishable from the return value of rename().
         */
        $now = file_get_contents($path);

        foreach ((array)$confirm as $pattern) {
            if ($now === false || !preg_match($pattern, $now)) {
                return new \WP_Error(
                    'not_confirmed',
                    __('Your wp-config.php does not read back as expected after writing it, so it will have to be changed by hand.', 'fluent-security')
                );
            }
        }

        return true;
    }
}
