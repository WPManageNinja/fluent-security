# FluentAuth

**Login security for WordPress — two-factor authentication, passkeys, social login, file integrity scanning and audit logs, in one plugin.**

[![Version](https://img.shields.io/wordpress/plugin/v/fluent-security?color=2563eb&label=version)](https://wordpress.org/plugins/fluent-security/)
[![Tested](https://img.shields.io/wordpress/plugin/tested/fluent-security?color=21759b&label=tested%20up%20to)](https://wordpress.org/plugins/fluent-security/)
[![Installs](https://img.shields.io/wordpress/plugin/installs/fluent-security?color=555)](https://wordpress.org/plugins/fluent-security/)
[![PHP](https://img.shields.io/badge/PHP-7.3%2B-777bb4.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-GPLv2%2B-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

FluentAuth guards the way people sign in to a WordPress site, and tells you when something on
the site has changed. It replaces a stack of single-purpose plugins — login limiting, 2FA,
login redirects, admin bar hiding — with one that hooks in once.

Everything is free. There is no paid tier and no locked screens.

**[Plugin page](https://wordpress.org/plugins/fluent-security/)** ·
**[Documentation](https://fluentauth.com/docs/getting-started/)** ·
**[Website](https://fluentauth.com)**

---

## Features

**Authentication**
- Two-factor authentication: passkeys, authenticator apps (TOTP) and emailed codes
- Passkey sign-in with no password at all — Touch ID, Windows Hello, security keys, password managers
- Per-role enrollment and enforcement, with the factor enrolled *during* sign-in, before a session exists
- Magic login links by email · Social login with Google, GitHub and Facebook · Google One Tap
- Ten single-use recovery codes per setup; authenticator secrets encryptable at rest

**Protection**
- Limit login attempts, with per-IP lockouts and optional email alerts
- IP allow and block lists, with a role restriction for allow-listed addresses
- Reverse proxy and Cloudflare detection, so rules act on the real visitor IP
- Core hardening: disable XML-RPC, application passwords, REST user enumeration, admin bar

**Visibility**
- Security checklist that scores the site and fixes most findings for you
- File integrity scanning for core, and for plugins and themes from the WordPress.org directory
- Side-by-side diffs, one-click restore, and baselines for files nothing else can verify
- Audit log of every login, failed attempt, block, and plugin/theme change
- Recovery tools for a site that has been broken into

**Presentation**
- Login and signup page customizer, plus shortcode forms for any page
- Role-based login and logout redirects
- Custom WordPress system emails with a shared template

---

## Requirements

| | |
|---|---|
| WordPress | 5.0 or newer |
| PHP | 7.3 or newer |
| Optional | `ZipArchive` for theme integrity scanning |

---

## Installation

**From WordPress** — search for *FluentAuth* under Plugins → Add New, then activate.

**From source**

```bash
git clone https://github.com/WPManageNinja/fluent-security.git
cd fluent-security
npm install
npx mix              # build the admin app
```

Symlink or copy the directory into `wp-content/plugins/` and activate. The admin app lives at
**FluentAuth** in the sidebar (page slug `fluent-auth`).

---

## Development

```bash
npm install          # once

npx mix              # development build
npx mix watch        # rebuild on change
npx mix --production # minified, what ships
```

The admin bundle is written to `dist/admin/app.js` and is **gitignored** — run a build before
loading the plugin, or the screen will be blank or stale. A production build is roughly 1.4 MB;
a development build is around 7 MB, so never judge the shipped size from an unflagged build.

### Testing

The suite runs against the official WordPress test library with a real database — not mocks.

```bash
composer install
composer test-setup   # installs WP core + test lib into $TMPDIR (once)
composer test         # the whole suite
```

```bash
composer test-coverage                                  # HTML coverage report
./tests/vendor/bin/phpunit tests/Unit/HelperTest.php    # one file
./tests/vendor/bin/phpunit --filter testMethodName      # one test
```

`composer test-setup` creates the `fluent_security_test` database via
`bin/install-wp-tests.sh`. Adjust the credentials in `composer.json` if yours differ. There are
two suites, `Unit` and `Integration`, defined in `phpunit.xml`.

> Composer's `vendor-dir` is **`tests/vendor`**, not `vendor/` — the plugin ships no Composer
> runtime dependencies, so nothing from Composer is in the released package.

### Static analysis

```bash
composer phpstan     # level 5, writes phpstan-errors.md
```

If PHPStan's parallel workers crash at the configured 1 GB, re-run with a larger limit rather
than treating it as a code error:

```bash
./tests/vendor/bin/phpstan analyse --memory-limit=3G
```

### Release build

```bash
sh build.sh --loco --node-build
```

This regenerates the JS translation map, builds the production bundle, refreshes the `.pot` via
Loco, then stages and zips `builds/fluent-security.zip`.

---

## Architecture

A conventional WordPress plugin: no framework, no Composer runtime dependencies, and a custom
PSR-4-style autoloader mapping `FluentAuth\App\*` to `app/*`.

```
fluent-security.php          bootstrap — constants, autoloader, activation
app/
├── Helpers/                 Helper (settings), Arr, Activator, BrowserDetection
├── Hooks/
│   ├── hooks.php            instantiates and registers every handler
│   └── Handlers/            one class per concern, each with register()
├── Http/
│   ├── routes.php           all REST endpoints
│   └── Controllers/         request handling
├── Services/
│   ├── TwoFa/               factors, WebAuthn, TOTP, recovery codes, enforcement
│   ├── Checks/              the security checklist
│   ├── IntegrityChecker/    core, plugin and theme file verification
│   ├── Baseline/            snapshots for unverifiable files
│   ├── Recovery/            post-compromise tooling
│   ├── DB/                  fluent query builder over wpdb
│   └── LoginBridge.php      adoption API for other plugins
└── Views/                   PHP templates and email markup

src/admin/                   Vue 3 SPA (Element Plus, Vue Router)
src/admin/styles/            all admin CSS — SFCs carry no <style> blocks
src/public/                  front-end JS and login styles
tests/                       PHPUnit, against the real WordPress test library
```

### Key patterns

**Database** — a Laravel-style query builder over `wpdb`, reached through `flsDb()`:

```php
flsDb()->table('fls_auth_logs')
    ->where('status', 'failed')
    ->orderBy('id', 'DESC')
    ->get();
```

Four custom tables: `fls_auth_logs`, `fls_login_hashes`, `fls_auth_factors`,
`fls_file_baselines`. Tables added after the original two create themselves on first use rather
than on activation, because `register_activation_hook` does not fire when a site *updates*.

**REST API** — declared in `app/Http/routes.php` with a chaining router under the
`fluent-auth/` namespace. Endpoints default to `manage_options`, overridable via the
`fluent_auth/app_permission` filter.

**Hook handlers** — every file in `app/Hooks/Handlers/` is a class with a `register()` method,
wired up in `app/Hooks/hooks.php`.

**Settings** — one option, `__fls_auth_settings`, read through `Helper::getAuthSettings()`.
`Helper::getRecommendedSettings()` is the single source for what the plugin considers a
well-configured site; both "apply recommended" and the checklist score against it.

**Admin UI** — Vue 3 SPA bootstrapped from `src/admin/app.js`, talking to the REST API via the
`$get` / `$post` / `$put` / `$del` mixins, with `$t()` for translation. All styling lives in
`src/admin/styles/`, layered in the order documented in `src/admin/app.scss`.

---

## Extending

FluentAuth exposes **142 filters and actions**. A few of the most useful:

| Hook | Purpose |
|---|---|
| `fluent_auth/app_permission` | Change who may reach the admin REST API |
| `fluent_auth/can_user_login` | Veto or allow a login outright |
| `fluent_auth/before_logging_in_user` · `after_logging_in_user` | Wrap the login transaction |
| `fluent_auth/before_creating_user` · `after_creating_user` | Hook registration |
| `fluent_auth/device_factor_required` | Decide whether a user must hold a device factor |
| `fluent_auth/recommended_settings` | Reshape what "apply recommended" writes |
| `fluent_auth/integrity_plugin_targets` | Narrow or widen what integrity scanning covers |
| `fluent_auth/trusted_proxies` · `cloudflare_ip_ranges` | Teach IP resolution about your edge |

### LoginBridge

If your plugin renders its own login screen, it can adopt FluentAuth's stack — attempt limits,
IP rules, magic login, the passkey button and an inline second factor — rather than
reimplementing them. Registration, not a field in the request, is what confers trust, so a
visitor cannot switch the front-end forms back on at a site whose owner turned them off.

```php
use FluentAuth\App\Services\LoginBridge;

// once, wherever the host boots — on every request, ajax included
LoginBridge::register('my-plugin', 'my_plugin_is_auth_screen');

// on the screen itself, before the form renders
LoginBridge::adopt([
    'host'          => 'my-plugin',
    'redirect_to'   => $currentUrl,
    'hidden_fields' => ['my_plugin_auth' => 'yes'],
]);

echo do_shortcode('[fluent_auth_login]');
```

Guard the call so your plugin still works when FluentAuth is not installed:

```php
if (class_exists(LoginBridge::class) && LoginBridge::isAvailable()) {
    // ...
}
```

### Shortcodes

| Shortcode | Renders |
|---|---|
| `[fluent_auth]` | Login, registration and password reset, whichever the visitor needs |
| `[fluent_auth_login]` | Login form |
| `[fluent_auth_signup]` | Registration form |
| `[fluent_auth_reset_password]` | Password reset request and new password |
| `[fluent_auth_magic_login]` | Magic link request form |

All accept `redirect_to="https://…"`.

### wp-config constants

| Constant | Effect |
|---|---|
| `FLUENT_AUTH_DISABLE_TWO_FA` | Lift 2FA site-wide (`true`) or for one account (a username). Emergency use — every login through it is audited |
| `FLUENT_AUTH_SECURITY_KEY` | Key used to encrypt stored authenticator secrets |
| `FLUENT_AUTH_TRUSTED_PROXIES` · `FLUENT_AUTH_PROXY_IP_HEADER` | Describe your reverse proxy |
| `FLUENT_AUTH_GOOGLE_CLIENT_ID` / `_SECRET` | Google credentials, kept out of the database |
| `FLUENT_AUTH_GITHUB_CLIENT_ID` / `_SECRET` | GitHub credentials |
| `FLUENT_AUTH_FACEBOOK_CLIENT_ID` / `_SECRET` | Facebook credentials |
| `FLUENT_AUTH_DISABLE_IP_RESTRICTION` | Suspend IP rules to recover from a bad entry |
| `FLUENT_AUTH_SERVER_MODE` | Run this site as the auth provider for others |

---

## Contributing

Pull requests and issues are welcome at
[WPManageNinja/fluent-security](https://github.com/WPManageNinja/fluent-security).

Before opening a PR:

```bash
composer test        # suite must stay green
composer phpstan     # must report no errors
```

Please match the surrounding code: WordPress coding standards, PascalCase classes, camelCase
methods, sanitize on input and escape on output. New user-facing strings need the
`fluent-security` text domain; new admin strings used as `$t('__key__')` placeholders must also
be registered in `reserved18n.json`, or the release build will ship the bare key.

## Security

Found a vulnerability? Please report it privately to the team at
[fluentauth.com](https://fluentauth.com) rather than opening a public issue.

## License

GPLv2 or later — see [the license text](https://www.gnu.org/licenses/gpl-2.0.html).

Built by the [WPManageNinja](https://wpmanageninja.com) team, who also make FluentCRM,
Fluent Forms, FluentSMTP, FluentBooking and FluentCart.
