# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

FluentAuth (fluent-security) is a WordPress security plugin providing login security, audit logging, magic login, 2FA, social login (Google/GitHub/Facebook), login customization, and system email management.

## Commands

```bash
# PHP tests
composer test                          # Run PHPUnit suite
./tests/vendor/bin/phpunit tests/Unit/HelperTest.php  # Single test file
./tests/vendor/bin/phpunit --filter "testMethodName"   # Single test method
composer test-coverage                 # HTML coverage report

# Static analysis
composer phpstan                       # PHPStan level 5 (outputs to phpstan-errors.md)

# Frontend build (Laravel Mix — no npm scripts defined, use npx directly)
npx mix                                # Development build
npx mix --production                   # Production build
npx mix watch                          # Watch mode

# Release build
sh build.sh --loco --node-build        # Full build for WP.org distribution
```

## Architecture

### Plugin Bootstrap

Entry point: `fluent-security.php` — defines constants, registers a custom PSR-4-style SPL autoloader for the `FluentAuth\` namespace (maps `FluentAuth\App\*` to `app/*`), then loads hooks and REST routes.

### Namespace & Directory Map

- `FluentAuth\App\Http\Controllers\` — REST API controllers (5 controllers: Settings, Logs, SocialAuthApi, SystemEmails, SecurityScan)
- `FluentAuth\App\Http\routes.php` — All REST endpoint definitions (namespace: `/wp-json/fluent-auth/`)
- `FluentAuth\App\Services\` — Business logic (AuthService, social auth services, SystemEmailService)
- `FluentAuth\App\Services\DB\` — Custom fluent query builder wrapping wpdb; accessed via `flsDb()` global
- `FluentAuth\App\Hooks\Handlers\` — 12 WordPress hook handlers, each with a `register()` method
- `FluentAuth\App\Hooks\hooks.php` — Instantiates and registers all handlers
- `FluentAuth\App\Helpers\` — Helper (settings/utilities), Arr (array ops), Activator (DB migrations), BrowserDetection
- `FluentAuth\App\Views\` — PHP templates (magic login views, email templates)
- `src/admin/` — Vue 3 admin SPA (components: Dashboard, Settings, Logs, SocialAuthSettings, AuthCustomizer, ServerMode, SecurityScan, CustomWpEmails)
- `src/public/` — Public-facing JS (magic_url.js, one_tap.js, login_helper.js, login_customizer.scss)

### Key Patterns

- **Database access**: Always use `flsDb()->table('fls_auth_logs')->where(...)->get()` (Laravel-style query builder). Two custom tables: `fls_auth_logs`, `fls_login_hashes`.
- **REST API**: Routes defined in `app/Http/routes.php` using the custom `Router` class with method chaining. Default permission: `manage_options`, overridable via `fluent_auth/app_permission` filter.
- **Error handling**: Return `\WP_Error` objects from controllers/services for API errors.
- **Settings**: Stored in `wp_options` under key `__fls_auth_settings`. Retrieved/managed via `Helper::getAuthSettings()`.
- **Hook handlers**: Each handler in `app/Hooks/Handlers/` is a class with a `register()` method that hooks into WordPress actions/filters.
- **Frontend**: Vue 3 + Element Plus + Vue Router, built with Laravel Mix. Admin app bootstraps from `src/admin/app.js` using `window.fluentAuthAdmin` for server-side data. REST calls use mixin methods `$get`, `$post`, `$put`, `$del`. Vue i18n via `$t()` mixin method.
- **i18n text domain**: `'fluent-security'`

### Testing

Tests run standalone without WordPress via comprehensive mocks in `tests/bootstrap.php` (mocks WP functions, database, REST classes). Test namespace: `FluentAuth\Tests\` (PSR-4 in `autoload-dev`). Unit tests in `tests/Unit/`, integration tests in `tests/Integration/`. Mock WordPress classes (WP_Error, WP_REST_Request, WP_User) are in `tests/Unit/MockClasses.php`.

## Code Style

- **PHP**: PascalCase classes, camelCase methods/variables, UPPER_SNAKE_CASE constants. Follow WordPress coding standards. Sanitize input (`sanitize_text_field`, `sanitize_url`), escape output (`esc_html`, `esc_url`).
- **Vue/JS**: PascalCase component files, kebab-case in templates. ES6+, async/await. SCSS with BEM naming (`.fframe_app`, `&__body`). `<script>` before `<template>` before `<style>` in SFCs.
- **Commits**: Run `composer phpstan` before committing.
