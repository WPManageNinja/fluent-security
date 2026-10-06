<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\ConfigWriter;
use FluentAuth\App\Services\Recovery\SaltRotation;

/**
 * Replacing the eight security keys in wp-config.php.
 *
 * Like ConfigWriterTest, most of this is refusals, and for a stronger reason: this is the
 * only thing in the plugin that deliberately destroys a value other software may be relying
 * on. The tests worth having are the ones that prove it will not do that by accident - on a
 * file where the keys are not really there, on a file it would only half rewrite, or on a
 * site that has said its files are not to be touched.
 *
 * Everything runs against a copy in a temporary directory, pointed at through the same
 * filter ConfigWriter exposes for this. Nothing here can reach the real wp-config.php.
 */
class SaltRotationTest extends BaseTestCase
{
    protected $dir = '';

    protected $path = '';

    /* A config with all eight, written the several ways people actually write them. */
    const SAMPLE = <<<'PHP'
<?php
define( 'DB_NAME', 'wordpress' );

define( 'AUTH_KEY',         'old-auth-key' );
define( 'SECURE_AUTH_KEY',  'old-secure-auth-key' );
define( 'LOGGED_IN_KEY',    'old-logged-in-key' );
define( 'NONCE_KEY',        'old-nonce-key' );
define('AUTH_SALT','old-auth-salt');
define( "SECURE_AUTH_SALT", "old-secure-auth-salt" );
define( 'LOGGED_IN_SALT',   'old-logged-in-salt' );
define( 'NONCE_SALT',       'old-nonce-salt' );

$table_prefix = 'wp_';

/* That's all, stop editing! Happy publishing. */

require_once ABSPATH . 'wp-settings.php';
PHP;

    public function setUp(): void
    {
        parent::setUp();

        $this->dir = get_temp_dir() . 'fls-salt-test-' . wp_generate_password(8, false);

        mkdir($this->dir);

        $this->path = $this->dir . '/wp-config.php';

        $this->write(self::SAMPLE);

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

    protected function write($contents)
    {
        file_put_contents($this->path, $contents);
    }

    protected function read()
    {
        return file_get_contents($this->path);
    }

    public function test_it_offers_itself_on_an_ordinary_config()
    {
        $state = SaltRotation::state();

        $this->assertTrue($state['available']);
        $this->assertSame('', $state['reason']);
    }

    public function test_it_replaces_every_key_with_something_new()
    {
        $before = $this->read();

        $this->assertTrue(SaltRotation::rotate());

        $after = $this->read();

        foreach (SaltRotation::KEYS as $key) {
            $this->assertStringNotContainsString(
                'old-' . strtolower(str_replace('_', '-', $key)),
                $after,
                $key . ' still holds its old value'
            );
        }

        $this->assertNotSame($before, $after);
    }

    /* Eight keys, eight different values - one value reused across all of them would pass a
     * naive "it changed" test while being the weakest possible outcome. */
    public function test_every_key_gets_its_own_value()
    {
        SaltRotation::rotate();

        $values = $this->currentValues();

        $this->assertCount(count(SaltRotation::KEYS), $values);
        $this->assertCount(count(SaltRotation::KEYS), array_unique($values));

        foreach ($values as $key => $value) {
            $this->assertSame(64, strlen($value), $key . ' is not 64 characters');
            /* Nothing that could end the string it is written into. */
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9_\-.:\/+=]{64}$/', $value, $key);
        }
    }

    public function test_two_rotations_do_not_repeat_themselves()
    {
        SaltRotation::rotate();
        $first = $this->currentValues();

        SaltRotation::rotate();
        $second = $this->currentValues();

        foreach ($first as $key => $value) {
            $this->assertNotSame($value, $second[$key], $key . ' was rotated to the same value twice');
        }
    }

    /* The lines keep the shape somebody wrote them in - single or double quotes, aligned or
     * not - because a config people maintain by hand should still look like theirs. */
    public function test_it_leaves_the_rest_of_the_file_alone()
    {
        SaltRotation::rotate();

        $after = $this->read();

        $this->assertStringContainsString("define( 'DB_NAME', 'wordpress' );", $after);
        $this->assertStringContainsString("\$table_prefix = 'wp_';", $after);
        $this->assertStringContainsString("require_once ABSPATH . 'wp-settings.php';", $after);
        $this->assertMatchesRegularExpression('/define\(\'AUTH_SALT\',\'[^\']+\'\);/', $after);
        $this->assertMatchesRegularExpression('/define\( "SECURE_AUTH_SALT", "[^"]+" \);/', $after);
    }

    /*
     * The Bedrock and managed-hosting case, and the most important refusal here: the keys are
     * defined from somewhere else, so rewriting this file would change nothing at all while
     * telling somebody recovering from a break-in that their keys had been replaced.
     */
    public function test_it_refuses_when_a_key_is_not_a_literal()
    {
        $this->write(str_replace(
            "define( 'NONCE_SALT',       'old-nonce-salt' );",
            "define( 'NONCE_SALT', getenv('NONCE_SALT') );",
            self::SAMPLE
        ));

        $state = SaltRotation::state();

        $this->assertFalse($state['available']);
        $this->assertStringContainsString('environment file', $state['reason']);

        $before = $this->read();
        $result = SaltRotation::rotate();

        $this->assertWPError($result);
        $this->assertSame('salts_unavailable', $result->get_error_code());
        $this->assertSame($before, $this->read(), 'the file was changed despite the refusal');
    }

    public function test_it_refuses_when_a_key_is_missing_altogether()
    {
        $this->write(str_replace(
            "define( 'LOGGED_IN_SALT',   'old-logged-in-salt' );\n",
            '',
            self::SAMPLE
        ));

        $before = $this->read();

        $this->assertFalse(SaltRotation::state()['available']);
        $this->assertWPError(SaltRotation::rotate());
        $this->assertSame($before, $this->read());
    }

    /* Two definitions means one of them is the live one and nothing here can tell which. */
    public function test_it_refuses_when_a_key_is_defined_twice()
    {
        $this->write(self::SAMPLE . "\ndefine( 'NONCE_KEY', 'somewhere-else' );\n");

        $before = $this->read();

        $this->assertFalse(SaltRotation::state()['available']);
        $this->assertWPError(SaltRotation::rotate());
        $this->assertSame($before, $this->read());
    }

    public function test_it_refuses_when_the_site_says_its_files_are_not_to_be_touched()
    {
        add_filter('fluent_auth/wp_config_write_blocked', '__return_true');

        $before = $this->read();
        $state = SaltRotation::state();

        $this->assertFalse($state['available']);
        $this->assertStringContainsString('cannot edit its files', $state['reason']);
        $this->assertWPError(SaltRotation::rotate());
        $this->assertSame($before, $this->read());

        remove_filter('fluent_auth/wp_config_write_blocked', '__return_true');
    }

    /*
     * All or nothing. A set where seven moved and one did not is worse than none: the site
     * boots, every cookie is refused, and its owner has been told the keys were replaced.
     */
    public function test_a_refusal_part_way_through_writes_nothing()
    {
        $before = $this->read();

        /* Valid names, but the last value cannot be written into a quoted string. */
        $values = [];

        foreach (SaltRotation::KEYS as $key) {
            $values[$key] = str_repeat('a', 64);
        }

        $values['NONCE_SALT'] = "not' a; safe value";

        $this->assertWPError(ConfigWriter::replaceConstants($values));
        $this->assertSame($before, $this->read());
    }

    public function test_it_refuses_a_constant_that_is_not_in_the_file()
    {
        $before = $this->read();

        $result = ConfigWriter::replaceConstants(['NOT_IN_THERE' => str_repeat('b', 64)]);

        $this->assertWPError($result);
        $this->assertSame('not_a_literal', $result->get_error_code());
        $this->assertSame($before, $this->read());
    }

    /**
     * @return array name => value, as the file currently has them
     */
    protected function currentValues()
    {
        $contents = $this->read();
        $values = [];

        foreach (SaltRotation::KEYS as $key) {
            $pattern = '/define\s*\(\s*[\'"]' . $key . '[\'"]\s*,\s*([\'"])([^\'"]*)\1\s*\)/';

            if (preg_match($pattern, $contents, $matches)) {
                $values[$key] = $matches[2];
            }
        }

        return $values;
    }
}
