#!/usr/bin/env php
<?php
/**
 * Single test runner for FluentAuth plugin
 * Usage: php run-single-test.php test-file-name
 * Example: php run-single-test.php ArrTest
 */

if (PHP_SAPI !== 'cli') {
    echo "This script must be run from the command line\n";
    exit(1);
}

if ($argc < 2) {
    echo "Usage: php run-single-test.php <test-file-name> [test-method-name]\n";
    echo "Example: php run-single-test.php ArrTest\n";
    echo "Example: php run-single-test.php ArrTest testHas\n";
    exit(1);
}

$testFile = $argv[1];
$testMethod = $argv[2] ?? null;

// Add .php extension if not present
if (substr($testFile, -4) !== '.php') {
    $testFile .= '.php';
}

// Look in Unit tests first
$testPath = __DIR__ . '/tests/Unit/' . $testFile;
if (!file_exists($testPath)) {
    // Look in Integration tests
    $testPath = __DIR__ . '/tests/Integration/' . $testFile;
}

if (!file_exists($testPath)) {
    echo "Test file not found: $testFile\n";
    echo "Available test files:\n";
    
    $unitFiles = glob(__DIR__ . '/tests/Unit/*Test.php');
    $integrationFiles = glob(__DIR__ . '/tests/Integration/*Test.php');
    
    foreach (array_merge($unitFiles, $integrationFiles) as $file) {
        echo "  - " . basename($file) . "\n";
    }
    exit(1);
}

// Check if composer is installed
if (!file_exists('tests/vendor/autoload.php')) {
    echo "Error: Composer dependencies not found.\n";
    echo "Please run: composer install --dev\n";
    exit(1);
}

// Load composer autoloader
require_once 'tests/vendor/autoload.php';

// Build PHPUnit command
$command = [
    'php',
    'tests/vendor/bin/phpunit',
    '--configuration', 'phpunit.xml',
    '--colors',
    '--verbose',
    $testPath
];

if ($testMethod) {
    $command[] = '--filter';
    $command[] = $testMethod;
}

echo "Running test: $testFile" . ($testMethod ? "::$testMethod" : "") . "\n";
echo "============================================\n\n";

// Run the test
passthru(implode(' ', $command), $exitCode);

echo "\nTest completed with exit code: $exitCode\n";
exit($exitCode);