<?php
/**
 * PHPUnit bootstrap file for FluentAuth plugin.
 *
 * Uses the official WordPress test suite (WP_UnitTestCase).
 */

// Composer autoloader
require_once __DIR__ . '/vendor/autoload.php';

// Locate the WordPress test library
$_tests_dir = getenv('WP_TESTS_DIR');

if (!$_tests_dir) {
    $_tests_dir = __DIR__ . '/vendor/wordpress-tests-lib';
}

if (!file_exists($_tests_dir . '/includes/functions.php')) {
    echo "Could not find {$_tests_dir}/includes/functions.php\n";
    echo "Run: bash bin/install-wp-tests.sh fluent_security_test root '' 127.0.0.1 latest\n";
    exit(1);
}

// Load WordPress test functions
require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin before WordPress initializes.
 */
function _manually_load_plugin()
{
    require dirname(__DIR__) . '/fluent-security.php';
}

tests_add_filter('muplugins_loaded', '_manually_load_plugin');

// Boot WordPress test environment
require $_tests_dir . '/includes/bootstrap.php';
