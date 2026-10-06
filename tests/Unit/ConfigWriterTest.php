<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\ConfigWriter;

/**
 * Writing a constant into wp-config.php.
 *
 * Almost every test here is a refusal, and that is the right proportion. The file this
 * class edits is the one a WordPress install cannot survive being wrong, so the question
 * worth answering repeatedly is not "does it write" but "does it leave the file alone when
 * anything is off" - a value it cannot quote safely, an existing definition, a layout it
 * does not recognise, a write that only half completes.
 *
 * Every test works on a copy in a temporary directory, pointed at through the filter that
 * exists for exactly this. Nothing here goes anywhere near the real wp-config.php.
 */
class ConfigWriterTest extends BaseTestCase
{
    protected $dir = '';

    protected $path = '';

    const SAMPLE = <<<'PHP'
<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'root' );

$table_prefix = 'wp_';

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
PHP;

    public function setUp(): void
    {
        parent::setUp();

        $this->dir = get_temp_dir() . 'fls-config-test-' . wp_generate_password(8, false);

        mkdir($this->dir);

        $this->path = $this->dir . '/wp-config.php';

        file_put_contents($this->path, self::SAMPLE);

        add_filter('fluent_auth/wp_config_path', [$this, 'supplyPath']);
    }

    public function tearDown(): void
    {
        remove_filter('fluent_auth/wp_config_path', [$this, 'supplyPath']);

        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        foreach (glob($this->dir . '/.*') ?: [] as $file) {
            if (!is_dir($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->dir);

        parent::tearDown();
    }

    public function supplyPath()
    {
        return $this->path;
    }

    protected function contents()
    {
        return file_get_contents($this->path);
    }

    /** @test */
    public function it_adds_the_line_above_the_stop_editing_marker()
    {
        $this->assertTrue(ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'));

        $contents = $this->contents();

        $this->assertStringContainsString("define( 'FLUENT_AUTH_SECURITY_KEY', 'abc123def456' );", $contents);

        // Above the marker, which is what makes it defined before WordPress loads.
        $this->assertLessThan(
            strpos($contents, "That's all, stop editing"),
            strpos($contents, 'FLUENT_AUTH_SECURITY_KEY')
        );

        // And before the require, which is the reason the position matters at all.
        $this->assertLessThan(
            strpos($contents, 'wp-settings.php'),
            strpos($contents, 'FLUENT_AUTH_SECURITY_KEY')
        );
    }

    /** @test */
    public function it_leaves_everything_that_was_already_in_the_file()
    {
        ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456');

        $contents = $this->contents();

        $expectations = [
            'define( \'DB_NAME\', \'wordpress\' );',
            '$table_prefix = \'wp_\';',
            'require_once ABSPATH . \'wp-settings.php\';'
        ];

        foreach ($expectations as $expected) {
            $this->assertStringContainsString($expected, $contents);
        }

        // Still one statement per line, and still opening with the tag.
        $this->assertStringStartsWith('<?php', $contents);
    }

    /**
     * The result has to be valid PHP. Checked by actually parsing it rather than by
     * eyeballing the string, because a file that does not parse is a white screen.
     *
     * @test
     */
    public function the_file_still_parses_afterwards()
    {
        ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456');

        $this->assertNotFalse(
            @token_get_all($this->contents(), TOKEN_PARSE),
            'wp-config.php no longer parses as PHP after the write'
        );
    }

    /**
     * Never overwritten. A value on file is either the one this site is keyed to or
     * somebody else's, and replacing either makes a table of ciphertext unreadable.
     *
     * @test
     */
    public function it_refuses_when_the_constant_is_already_defined()
    {
        ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'the-original-value');

        $before = $this->contents();

        $again = ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'a-different-value');

        $this->assertWpErrorWithCode($again, 'already_defined');
        $this->assertEquals($before, $this->contents());
        $this->assertStringNotContainsString('a-different-value', $this->contents());
    }

    /**
     * Written into single quotes, so a value that could close the string or start another
     * statement is refused rather than escaped. Escaping into a file that is executed is
     * not something to be clever about.
     *
     * @test
     */
    public function it_refuses_a_value_it_cannot_quote_safely()
    {
        $before = $this->contents();

        foreach (["it's", "a'); system('rm -rf /'); //", 'back\\slash', "new\nline", 'short'] as $value) {
            $result = ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', $value);

            $this->assertWPError($result, 'Accepted a value it should have refused: ' . $value);
            $this->assertEquals($before, $this->contents());
        }
    }

    /** @test */
    public function it_refuses_a_constant_name_that_is_not_one()
    {
        $before = $this->contents();

        foreach (['lowercase', "OK'); evil(", 'has spaces', '1STARTS_WITH_DIGIT'] as $name) {
            $this->assertWPError(ConfigWriter::addConstant($name, 'abc123def456'));
            $this->assertEquals($before, $this->contents());
        }
    }

    /**
     * There is no anchor to insert above, and appending to the end would define the
     * constant after every plugin has run - which is indistinguishable from not defining
     * it, except that the screen would report success.
     *
     * @test
     */
    public function it_refuses_a_layout_it_does_not_recognise()
    {
        file_put_contents($this->path, "<?php\ndefine( 'DB_NAME', 'wordpress' );\n");

        $before = $this->contents();

        $this->assertWpErrorWithCode(
            ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'),
            'no_anchor'
        );

        $this->assertEquals($before, $this->contents());
    }

    /** @test */
    public function it_falls_back_to_the_wp_settings_require_when_the_marker_is_gone()
    {
        file_put_contents($this->path, "<?php\ndefine( 'DB_NAME', 'wordpress' );\n\nrequire_once ABSPATH . 'wp-settings.php';\n");

        $this->assertTrue(ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'));

        $contents = $this->contents();

        $this->assertLessThan(
            strpos($contents, 'wp-settings.php'),
            strpos($contents, 'FLUENT_AUTH_SECURITY_KEY')
        );
    }

    /** @test */
    public function it_refuses_when_the_file_is_not_writable()
    {
        chmod($this->path, 0444);

        $before = $this->contents();

        $result = ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456');

        chmod($this->path, 0644);

        $this->assertWpErrorWithCode($result, 'not_writable');
        $this->assertEquals($before, $this->contents());
    }

    /** @test */
    public function it_refuses_when_the_file_cannot_be_found()
    {
        unlink($this->path);

        $this->assertWpErrorWithCode(
            ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'),
            'not_found'
        );
    }

    /**
     * A symlinked wp-config.php belongs to something else - a Bedrock layout, a config
     * shared between installs - and rename() would quietly replace the link with a file.
     *
     * @test
     */
    public function it_refuses_to_replace_a_symlinked_config()
    {
        $real = $this->dir . '/real-config.php';

        rename($this->path, $real);

        if (!@symlink($real, $this->path)) {
            $this->markTestSkipped('This filesystem does not allow symlinks');
        }

        $before = file_get_contents($real);

        $this->assertWpErrorWithCode(
            ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'),
            'symlinked'
        );

        $this->assertEquals($before, file_get_contents($real));
        $this->assertTrue(is_link($this->path));
        $this->assertFalse(ConfigWriter::state()['writable']);
    }

    /**
     * The host's own way of saying "nothing here writes to disk". Honoured without even
     * testing whether the write would have worked.
     *
     * Exercised through the filter rather than by defining DISALLOW_FILE_MODS, because a
     * constant cannot be undefined again and would silently block every test that ran
     * after this one - which is precisely what it did the first time this was written.
     *
     * @test
     */
    public function it_honours_a_site_that_forbids_file_changes()
    {
        $before = $this->contents();

        add_filter('fluent_auth/wp_config_write_blocked', '__return_true');

        $this->assertTrue(ConfigWriter::isBlocked());
        $this->assertFalse(ConfigWriter::state()['writable']);
        $this->assertWpErrorWithCode(
            ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'),
            'file_mods_disallowed'
        );
        $this->assertEquals($before, $this->contents());

        remove_filter('fluent_auth/wp_config_write_blocked', '__return_true');
    }

    /** @test */
    public function it_reports_what_the_screen_needs_before_offering_a_button()
    {
        $state = ConfigWriter::state();

        $this->assertTrue($state['found']);
        $this->assertTrue($state['writable']);
        $this->assertFalse($state['linked']);

        // A server path is noise in an admin screen; only the relative one is reported.
        $this->assertStringNotContainsString(ABSPATH, $state['path']);
    }

    /**
     * The temporary file is written beside wp-config.php, because rename() is only atomic
     * within one filesystem. What must not happen is one being left behind on success.
     *
     * @test
     */
    public function it_leaves_no_temporary_file_behind()
    {
        ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456');

        $strays = array_merge(
            glob($this->dir . '/.fls-cfg*') ?: [],
            glob($this->dir . '/fls-cfg*') ?: []
        );

        $this->assertSame([], $strays);
    }

    /** @test */
    public function it_keeps_the_files_permissions()
    {
        chmod($this->path, 0640);

        $this->assertTrue(ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'));

        clearstatcache(true, $this->path);

        $this->assertEquals(0640, fileperms($this->path) & 0777);
    }

    /** @test */
    public function it_keeps_windows_line_endings_where_the_file_uses_them()
    {
        file_put_contents($this->path, str_replace("\n", "\r\n", self::SAMPLE));

        $this->assertTrue(ConfigWriter::addConstant('FLUENT_AUTH_SECURITY_KEY', 'abc123def456'));

        $contents = $this->contents();

        $this->assertStringContainsString("define( 'FLUENT_AUTH_SECURITY_KEY', 'abc123def456' );\r\n", $contents);
        // No lone \n introduced into a file that uses \r\n throughout.
        $this->assertSame(0, preg_match('/(?<!\r)\n/', $contents));
    }
}
