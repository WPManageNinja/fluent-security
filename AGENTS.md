# FluentAuth AGENTS.md

This file provides guidelines for agentic coding agents working on the FluentAuth WordPress security plugin.

## Build/Lint/Test Commands

### PHP Analysis
```bash
# Run PHPStan static analysis
composer phpstan

# The command runs: phpstan analyse --memory-limit=1G --error-format=table > phpstan-errors.md
```

### JavaScript/Vue Build
```bash
# Install dependencies
npm install

# Build assets using Laravel Mix
npm run dev        # Development build
npm run prod       # Production build
npm run watch      # Watch for changes
```

### Testing
Currently no specific test commands are configured. The package.json has a placeholder test script:
```bash
npm test          # Returns "Error: no test specified" - needs to be implemented
```

### WordPress Plugin Testing
To test individual PHP classes or functions:
1. Enable debugging in WordPress: `define('WP_DEBUG', true);`
2. Test REST endpoints by accessing `/wp-json/fluent-auth/` routes
3. Check admin interface at `/wp-admin/admin.php?page=fluent-auth`

## Code Style Guidelines

### PHP Code Style

#### Naming Conventions
- **Classes**: PascalCase, prefix with `FluentAuth\` namespace
  ```php
  class SettingsController
  class AuthHelper
  ```
- **Methods**: camelCase, descriptive verbs
  ```php
  public function getAuthSettings()
  public function validateSettings()
  ```
- **Variables**: camelCase, descriptive
  ```php
  $authSettings
  $userRoles
  ```
- **Constants**: UPPER_SNAKE_CASE
  ```php
  define('FLUENT_AUTH_VERSION', '2.1.1');
  ```

#### File Organization
- Namespace: `FluentAuth\App\[Module]`
  - `FluentAuth\App\Http\Controllers`
  - `FluentAuth\App\Helpers`
  - `FluentAuth\App\Services`
- PSR-4 autoloading configured in main plugin file
- Each class in its own file
- Directory structure follows namespace structure

#### Code Structure
- Always sanitize user input
- Always validate data before processing
- Use WordPress helper functions: `sanitize_text_field()`, `sanitize_url()`, etc.
- Return WP_Error objects for API errors
- Use type hints where possible
- Follow WordPress coding standards

#### Error Handling
- Return `\WP_Error` objects for validation failures
- Use `is_wp_error()` to check for errors
- Provide meaningful error messages
- Sanitize all user data before processing
```php
if (is_wp_error($settings)) {
    return $settings;
}

return new \WP_Error('validation_error', 'Form Validation failed', $errors);
```

#### Database Operations
- Use the custom `flsDb()` fluent query builder
- Always sanitize database inputs
- Use prepared statements when possible
```php
flsDb()->table('fls_auth_logs')
    ->where('created_at', '<', $dateTime)
    ->delete();
```

### Vue.js/JavaScript Code Style

#### Component Naming
- Use PascalCase for component files
- Use kebab-case for component names in templates
- Descriptive, functional names
  ```vue
  <!-- Dashboard.vue -->
  <template>
    <div class="dashboard-component">
      <!-- content -->
    </div>
  </template>
  ```

#### Vue Component Structure
- `<script>` before `<template>` before `<style>`
- Use `type="text/babel"` for Vue 3 compatibility
- Export default object with name property
- Use composition API patterns where appropriate

#### JavaScript Patterns
- Use ES6+ features (const/let, arrow functions, destructuring)
- CamelCase for functions and variables
- PascalCase for classes
- Use async/await for asynchronous operations
- Error handling with try/catch blocks
```javascript
async function fetchSettings() {
    try {
        const response = await this.$post('settings/get');
        return response.data;
    } catch (error) {
        this.$handleError(error);
    }
}
```

#### API Communication
- Use the custom `Rest` class for HTTP requests
- Centralized error handling via `$handleError` method
- Loading states for async operations
```javascript
// In app.js mixin
methods: {
    $get: Rest.get,
    $post: Rest.post,
    $put: Rest.put,
    $del: Rest.delete,
    $handleError(response) {
        // Centralized error handling
    }
}
```

### CSS/SCSS Style
- Use SCSS for styles
- BEM naming convention for classes
- Component-scoped styles where possible
- Mobile-first responsive design
```scss
.fframe_app {
    &__body {
        // styles
    }
    
    .fframe_menu_item {
        // styles
        
        &--active {
            // active state
        }
    }
}
```

### Security Guidelines

#### Input Validation
- Never trust user input
- Use WordPress sanitization functions:
  ```php
  $sanitized = sanitize_text_field($input);
  $url = sanitize_url($input);
  $html = wp_kses_post($input);
  ```

#### Output Escaping
- Escape all output:
  ```php
  echo esc_html($output);
  echo esc_url($url);
  echo wp_kses($html, $allowed_html);
  ```

#### Permission Checks
- Always verify user capabilities:
  ```php
  if (!current_user_can('manage_options')) {
      return new \WP_Error('permission_denied', 'Access denied');
  }
  ```

#### Nonce Verification
- Use nonces for form submissions and AJAX requests:
  ```php
  check_admin_referer('fluent_auth_action');
  ```

### Git Workflow
- Commit messages should be descriptive and follow conventional commit format
- Keep commits focused on single changes
- Ensure PHPStan analysis passes before committing
- Test functionality thoroughly before pushing

### Configuration Files
- `phpstan.neon`: Static analysis configuration
- `webpack.mix.js`: Frontend build configuration
- `composer.json`: PHP dependencies and scripts
- `package.json`: JavaScript dependencies and scripts

### Testing Guidelines
- No formal test suite currently exists
- Manual testing via WordPress admin interface
- Test REST endpoints using tools like Postman
- Verify frontend functionality in multiple browsers
- Test with different user roles and permissions

### Performance Considerations
- Use static properties for caching frequently accessed data
- Minimize database queries
- Use WordPress transients for caching
- Optimize frontend asset loading
- Lazy load components where appropriate

### Internationalization
- All user-facing text should be translatable
- Use WordPress i18n functions:
  ```php
  __('Settings has been updated', 'fluent-security')
  _e('Error message', 'fluent-security')
  ```
- In Vue components, use `$t()`, `$_n()` and `$_x()` from `src/admin/Bits/i18n.js` (exposed through the app.js mixin)
- Use `__('text', 'fluent-security')` in PHP and `$t('text')` in Vue. Never split a sentence across several `$t()` calls or join a `$t()` result to a value; use placeholders (`$t('Try again in %s minutes.', minutes)`, `$_n('%s file changed', '%s files changed', n)`), and `$_x('Open', 'Verb')` when one English word needs different translations in different places. Vue strings reach translators through the generated `app/Services/TransStrings.php`: after adding or changing a `$t()` / `$_n()` / `$_x()` string, run `npm run translate`. Put a `<!-- translators: ... -->` or `// translators: ...` comment on the line directly above any string with placeholders; `npm run translate` fails on a placeholder string without one, on em/en dashes in UI text, and on keys with leading or trailing whitespace. Long paragraphs go in `reserved18n.json` under a `__snake_case_key__` and the template calls `$t('__snake_case_key__')`. Write for a small-business owner: short sentences, one idea each, everyday words. Rewording a string that is already clear costs its translation in every locale, so leave good strings alone. See `docs/js-translations.md`.