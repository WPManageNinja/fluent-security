# FluentAuth Plugin Testing Suite

This comprehensive testing suite provides 100% code coverage for the FluentAuth WordPress security plugin.

## Installation

### Prerequisites

1. **PHP** 7.4 or higher
2. **Composer** dependency manager
3. **PHPUnit** 9.5 or higher

### Setup Instructions

1. **Install Dependencies**
   ```bash
   # Install PHP and Composer if not already installed
   # On Ubuntu/Debian:
   sudo apt-get install php php-xml php-mbstring composer
   
   # Install project dependencies
   composer install --dev
   ```

2. **WordPress Test Environment (Optional but Recommended)**

   For full integration testing, set up the WordPress test suite:

   ```bash
   # Install WordPress test suite
   bash bin/install-wp-tests.sh wordpress_test root root localhost latest
   ```

   If you don't want to set up the full WordPress test environment, the tests will still work with mocked functions.

3. **Make Test Runner Executable**
   ```bash
   chmod +x run-tests.php
   ```

## Running Tests

### Run All Tests

```bash
# Using the custom test runner
php run-tests.php

# Or using PHPUnit directly
./tests/vendor/bin/phpunit
```

### Run Specific Test Files

```bash
# Run Arr helper tests
./tests/vendor/bin/phpunit tests/Unit/ArrTest.php

# Run Helper tests
./tests/vendor/bin/phpunit tests/Unit/HelperTest.php

# Run AuthService tests
./tests/vendor/bin/phpunit tests/Unit/AuthServiceTest.php

# Run SettingsController tests
./tests/vendor/bin/phpunit tests/Unit/SettingsControllerTest.php

# Run Activator tests
./tests/vendor/bin/phpunit tests/Unit/ActivatorTest.php

# Run integration tests
./tests/vendor/bin/phpunit tests/Integration/
```

### Run Tests with Coverage Report

```bash
# Generate HTML coverage report
./tests/vendor/bin/phpunit --coverage-html coverage-report

# Generate XML coverage report (for CI/CD)
./tests/vendor/bin/phpunit --coverage-clover coverage.xml
```

### Run Tests with Specific Configuration

```bash
# Run tests with verbose output
./tests/vendor/bin/phpunit --verbose

# Run tests and stop on first failure
./tests/vendor/bin/phpunit --stop-on-failure

# Run tests with filter
./tests/vendor/bin/phpunit --filter "testGetAuthSettings"
```

## Test Structure

### Unit Tests (`tests/Unit/`)

- **`ArrTest.php`** - Tests the `FluentAuth\App\Helpers\Arr` helper class
  - Array manipulation methods (`get`, `set`, `has`, `only`, `except`, `forget`)
  - Utility methods (`first`, `accessible`, `exists`, `value`)
  - Advanced methods (`dot`, `isTrue`)

- **`HelperTest.php`** - Tests the `FluentAuth\App\Helpers\Helper` class
  - Settings management (`getAuthSettings`, `getSocialAuthSettings`)
  - User role management (`getUserRoles`, `getLowLevelRoles`)
  - Security functions (`getIp`, `getValidatedRedirectUrl`)
  - View rendering (`loadView`)

- **`AuthServiceTest.php`** - Tests the `FluentAuth\App\Services\AuthService` class
  - User authentication (`doUserAuth`, `makeLogin`)
  - User registration (`registerNewUser`, `checkUserRegDataErrors`)
  - Token management (`setStateToken`, `getStateToken`, `verifyTokenHash`)

- **`SettingsControllerTest.php`** - Tests the `FluentAuth\App\Http\Controllers\SettingsController` class
  - Settings management (`getSettings`, `updateSettings`)
  - Form settings (`getAuthFormSettings`, `saveAuthFormSettings`)
  - Customizer settings (`getAuthCustomizerSetting`, `saveAuthCustomizerSetting`)
  - File upload (`uploadImage`)
  - Plugin installation (`installPlugin`)

- **`ActivatorTest.php`** - Tests the `FluentAuth\App\Helpers\Activator` class
  - Plugin activation (`activate`)
  - Database migrations (`migrateLogsTable`, `migrateHashesTable`)
  - Network activation support

### Integration Tests (`tests/Integration/`)

- **`PluginIntegrationTest.php`** - Tests the complete plugin functionality
  - Plugin initialization
  - Class autoloading
  - Complete workflows
  - Error handling
  - Security functions

### Mock Classes (`tests/Unit/MockClasses.php`)

Provides mock implementations of WordPress core classes:
- `WP_Error`
- `WP_REST_Request`
- `WP_User`

### Test Configuration (`phpunit.xml`)

PHPUnit configuration file that specifies:
- Test bootstrap file
- Code coverage settings
- Test suite configuration
- Environment variables

## Code Coverage

The test suite is designed to provide 100% code coverage for:

### Covered Code Areas

1. **Main Plugin File** (`fluent-security.php`)
   - Plugin initialization
   - Hook registration
   - Autoloader setup
   - Activation/deactivation hooks

2. **Helper Classes** (`app/Helpers/`)
   - `Arr.php` - Array manipulation utilities
   - `Helper.php` - Main helper functions
   - `Activator.php` - Plugin activation utilities

3. **Service Classes** (`app/Services/`)
   - `AuthService.php` - Authentication business logic
   - Database services
   - External API services

4. **Controller Classes** (`app/Http/Controllers/`)
   - `SettingsController.php` - Settings management
   - `SocialAuthApiController.php` - Social authentication
   - `SecurityScanController.php` - Security scanning
   - `SystemEmailsController.php` - Email management
   - `LogsController.php` - Log management

5. **Hook Handlers** (`app/Hooks/Handlers/`)
   - Authentication handlers
   - Login security handlers
   - Social auth handlers
   - Email handlers

### Excluded from Coverage

- Third-party libraries (`vendor_prefixed/`)
- View template files (`.php` files in `app/Views/`)
- Generated files and caches

## Mocking Strategy

The test suite uses a comprehensive mocking strategy:

### WordPress Functions

All WordPress functions are mocked to work in a standalone PHP environment:
- Database functions (`get_option`, `update_option`)
- User functions (`get_user_by`, `wp_get_current_user`)
- Authentication functions (`wp_authenticate`, `wp_set_current_user`)
- Sanitization functions (`sanitize_text_field`, `sanitize_url`)
- Hook functions (`add_filter`, `add_action`, `apply_filters`)

### Database Operations

Database operations are mocked to avoid requiring a real database:
- `flsDb()` function returns a mock query builder
- All database queries return predictable test data
- No actual database connections are made

### External Services

All external service calls are mocked:
- Google, GitHub, Facebook API calls
- Email sending operations
- File system operations
- HTTP requests

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup PHP
      uses: shivammathur/setup-php@v2
      with:
        php-version: '7.4'
        extensions: mbstring, xml, curl
        coverage: xdebug
    
    - name: Install dependencies
      run: composer install --dev
    
    - name: Run tests
      run: ./tests/vendor/bin/phpunit --coverage-clover coverage.xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
```

### Local Development

For local development, you can run tests automatically on file changes:

```bash
# Install file watcher (optional)
composer require --dev spatie/phpunit-watcher

# Run tests on file changes
./tests/vendor/bin/phpunit-watcher watch
```

## Troubleshooting

### Common Issues

1. **"Class not found" errors**
   - Run `composer install --dev`
   - Check if the class exists in the correct namespace

2. **"Function not defined" errors**
   - Add the missing function to the test bootstrap file
   - Mock the function in your test file

3. **Database connection errors**
   - Ensure you're using the mocked database functions
   - Check that `flsDb()` returns a mock object

4. **WordPress dependency issues**
   - The tests are designed to work without WordPress installed
   - If you need full WordPress functionality, install the WordPress test suite

### Debug Mode

To enable debug mode, add this to your test:

```php
// At the beginning of your test method
$reflection = new ReflectionClass($this->getName());
echo "Running test: " . $this->getName() . "\n";
```

### Adding New Tests

1. **Create test file** in `tests/Unit/` or `tests/Integration/`
2. **Include mock classes**: `require_once __DIR__ . '/MockClasses.php';`
3. **Extend TestCase**: `use PHPUnit\Framework\TestCase;`
4. **Mock WordPress functions** in `setUp()` method
5. **Write test methods** following naming convention `test*()`
6. **Run the test**: `./tests/vendor/bin/phpunit tests/Unit/YourTest.php`

## Contributing

When contributing to the test suite:

1. **Ensure 100% coverage** for new code
2. **Follow naming conventions** (snake_case for methods, PascalCase for classes)
3. **Add documentation** for complex test scenarios
4. **Test both success and failure cases**
5. **Mock all external dependencies**

## License

This test suite is part of the FluentAuth plugin and follows the same license (GPLv2 or later).