<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Baseline\BaselineStore;

/**
 * A site with premium plugins on it, without needing any.
 *
 * The units come through `fluent_auth/integrity_plugin_targets` rather than from real
 * directories in wp-content: what these tests are about is what the snapshot does with a unit
 * it cannot check against WordPress.org, and whether a given plugin counts as that depends on
 * an update transient and a network call. Injecting the targets makes the tests deterministic
 * and lets them describe the awkward cases - a version bump, an uninstall - in two lines.
 *
 * The files under them are real, because hashing them is the thing being tested.
 */
class BaselineTestCase extends BaseTestCase
{
    /** @var string the primary unit's directory */
    protected $unitPath;

    /** @var array scope => [path, version, label] */
    protected $units = [];

    protected $root;

    public function setUp(): void
    {
        parent::setUp();

        $this->root = trailingslashit(get_temp_dir()) . 'fls-baseline-test';

        $this->removeTree($this->root);
        wp_mkdir_p($this->root);

        $this->units = [];
        $this->unitPath = $this->addUnit('my-premium-plugin');

        /*
         * The inventory asks WordPress which plugins the directory knows, and an empty update
         * transient makes it go and find out - a network call, in the middle of a unit test,
         * before the filters below get a look in. Answered here so these run in milliseconds
         * and give the same answer on a machine with no internet.
         */
        add_filter('pre_site_transient_update_plugins', [$this, 'stubUpdateTransient']);
        add_filter('pre_site_transient_update_themes', [$this, 'stubUpdateTransient']);

        add_filter('fluent_auth/integrity_plugin_targets', [$this, 'injectTargets']);
        add_filter('fluent_auth/integrity_theme_targets', '__return_empty_array');

        $this->resetBaseline();
    }

    /**
     * @return object
     */
    public function stubUpdateTransient()
    {
        return (object)[
            'last_checked' => time(),
            'response'     => [],
            'no_update'    => ['a-plugin/a-plugin.php' => (object)['slug' => 'a-plugin']]
        ];
    }

    public function tearDown(): void
    {
        remove_filter('pre_site_transient_update_plugins', [$this, 'stubUpdateTransient']);
        remove_filter('pre_site_transient_update_themes', [$this, 'stubUpdateTransient']);
        remove_filter('fluent_auth/integrity_plugin_targets', [$this, 'injectTargets']);
        remove_filter('fluent_auth/integrity_theme_targets', '__return_empty_array');

        $this->removeTree($this->root);

        parent::tearDown();
    }

    public static function wpTearDownAfterClass()
    {
        global $wpdb;

        $wpdb->query('DROP TABLE IF EXISTS ' . BaselineStore::table());
        delete_option(BaselineStore::VERSION_OPTION);

        parent::wpTearDownAfterClass();
    }

    /**
     * @param array $targets
     * @return array
     */
    public function injectTargets($targets)
    {
        $injected = [];

        foreach ($this->units as $scope => $unit) {
            $injected[] = [
                'type'        => 'plugin',
                'key'         => substr($scope, strlen('plugin:')),
                'slug'        => $unit['slug'],
                'name'        => $unit['label'],
                'version'     => $unit['version'],
                'path'        => $unit['path'],
                'rel_path'    => 'wp-content/plugins/' . $unit['slug'],
                'single_file' => false,
                /* The whole point: nothing official to compare these against. */
                'verifiable'  => false,
                'reason'      => 'not_on_wp_org'
            ];
        }

        return $injected;
    }

    /**
     * @param string $slug
     * @return string the unit's path
     */
    protected function addUnit($slug)
    {
        $path = $this->root . '/' . $slug;
        wp_mkdir_p($path);

        $this->units['plugin:' . $slug . '/' . $slug . '.php'] = [
            'slug'    => $slug,
            'label'   => ucwords(str_replace('-', ' ', $slug)),
            'version' => '1.0.0',
            'path'    => $path
        ];

        return $path;
    }

    /**
     * @param string $path
     * @return void
     */
    protected function removeUnit($path)
    {
        foreach ($this->units as $scope => $unit) {
            if ($unit['path'] === $path) {
                unset($this->units[$scope]);
            }
        }

        $this->removeTree($path);
    }

    /**
     * @return string
     */
    protected function unitScope()
    {
        return 'plugin:my-premium-plugin/my-premium-plugin.php';
    }

    /**
     * @param string $version
     * @return void
     */
    protected function setUnitVersion($version)
    {
        $this->units[$this->unitScope()]['version'] = $version;
    }

    /**
     * @param string $name
     * @param string $contents
     * @return void
     */
    protected function writeUnitFile($name, $contents)
    {
        file_put_contents($this->unitPath . '/' . $name, $contents);
    }

    /**
     * Rows only - no DDL, so the transaction each test runs inside still rolls back.
     *
     * @return void
     */
    protected function resetBaseline()
    {
        if (BaselineStore::hasTable()) {
            BaselineStore::clear();
        }
    }

    /**
     * For the one test that has to prove the table is not there until it is needed.
     *
     * @return void
     */
    protected function dropBaselineTable()
    {
        global $wpdb;

        $wpdb->query('DROP TABLE IF EXISTS ' . BaselineStore::table());
        delete_option(BaselineStore::VERSION_OPTION);
    }

    /**
     * @param string $path
     * @return void
     */
    protected function removeTree($path)
    {
        if (!is_dir($path)) {
            if (file_exists($path)) {
                unlink($path);
            }

            return;
        }

        foreach (array_diff(scandir($path), ['.', '..']) as $entry) {
            $this->removeTree($path . '/' . $entry);
        }

        rmdir($path);
    }
}
