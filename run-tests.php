#!/usr/bin/env php
<?php
/**
 * Test runner script for FluentAuth plugin
 */

if (PHP_SAPI !== 'cli') {
    echo "This script must be run from the command line\n";
    exit(1);
}

echo "FluentAuth Plugin Test Runner\n";
echo "=============================\n\n";

// Check if composer is installed
if (!file_exists('tests/vendor/autoload.php')) {
    echo "Error: Composer dependencies not found.\n";
    echo "Please run: composer install --dev\n";
    exit(1);
}

// Load composer autoloader
require_once 'tests/vendor/autoload.php';

// Check if PHPUnit is available
if (!class_exists('PHPUnit\TextUI\Command')) {
    echo "Error: PHPUnit not found.\n";
    echo "Please install PHPUnit via composer:\n";
    echo "composer require --dev phpunit/phpunit\n";
    exit(1);
}

// Set up environment
define('WP_TESTS_DIR', getenv('WP_TESTS_DIR') ?: __DIR__ . '/tests/vendor/wordpress-tests-lib');
define('WP_CORE_DIR', getenv('WP_CORE_DIR') ?: __DIR__ . '/tests/vendor/wordpress/');

// Check if WordPress test suite is available
if (!file_exists(WP_TESTS_DIR . '/includes/bootstrap.php')) {
    echo "Warning: WordPress test suite not found.\n";
    echo "Some tests may not work properly without WordPress test environment.\n";
    echo "To install WordPress test suite, see: https://make.wordpress.org/core/handbook/testing/automated-testing/running-phpunit-tests/\n\n";
}

// Create test directory if it doesn't exist
if (!file_exists('tests')) {
    mkdir('tests', 0755, true);
    echo "Created tests directory.\n";
}

// Run the tests
echo "Running test suite...\n\n";

$command = new PHPUnit\TextUI\Command();

try {
    $exitCode = $command->run([
        'phpunit',
        '--configuration', 'phpunit.xml',
        '--colors',
        '--verbose',
        '--bootstrap', 'tests/bootstrap.php',
        'tests'
    ], false);
    
    echo "\nTest suite completed with exit code: $exitCode\n";
    exit($exitCode);
    
} catch (Exception $e) {
    echo "Error running tests: " . $e->getMessage() . "\n";
    exit(1);
}