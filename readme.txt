=== FluentAuth - Login Security, Two-Factor Authentication, Passkeys & Social Login ===
Contributors: techjewel, wpmanageninja, adreastrian
Tags: security, two factor authentication, limit login attempts, social login, login
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 7.3
Stable tag: 2.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Two-factor authentication, passkeys, social login, magic login, limit login attempts, file change scanning and audit logs for WordPress.

== Description ==

FluentAuth is a login security plugin for WordPress. It protects the way people sign in to your site, and it tells you when something on your site has changed.

You get two-factor authentication, passkeys, social login, magic login links, login attempt limits, IP access rules, a security checklist, file change scanning and a full audit log. All of it in one plugin, with no bloat and no slowdown.

**Highlighted Features**

- Two-Factor Authentication (email, authenticator app and passkeys)
- Passkey login with Touch ID, Windows Hello, a security key or a password manager
- Social Login with Google, GitHub and Facebook
- Google One Tap Login
- Magic Login links by email, with no password
- Limit Login Attempts and block brute force attacks
- IP allow list and IP block list
- Security checklist that finds problems and fixes them for you
- WordPress core, plugin and theme file change scanning
- Audit log of every login, failed attempt, plugin activation and update
- Login and logout redirects
- Login and signup page customizer
- Custom WordPress system emails
- Restrict /wp-admin by user role
- Recovery tools for a site that has been hacked

[youtube https://www.youtube.com/watch?v=P_vREW7s2B4]

[youtube https://www.youtube.com/watch?v=5t_8rvtrkk4]

= Two-Factor Authentication (2FA) =

Ask for a second step after the password. FluentAuth gives you three ways to do it, and you choose which roles may use each one.

- **Email codes.** A one time code sent to the user's inbox. Nothing to install.
- **Authenticator app.** Google Authenticator, Authy, 1Password or any other TOTP app. FluentAuth draws the QR code on your own server, so the secret never leaves your site.
- **Passkeys.** Touch ID, Face ID, Windows Hello, a hardware security key or a password manager. The browser ties the passkey to your domain, so it cannot be used on a fake copy of your login page.

You can let a role set up a second factor, or you can require it. A user who must have one is asked to set it up before they can use the admin area. Setting up an authenticator app also hands the user ten single use recovery codes, for the day the phone is left at home. Passkey users can fall back on those codes too.

There is an admin screen listing everyone who has enrolled, so you can see who is protected and reset a user who is locked out.

Authenticator secrets can be encrypted in your database with a key you keep in wp-config.php. If someone reads your database, the secrets are useless to them.

= Passkey Login =

Passkeys are the strongest option here. The credential lives on the device and is bound to your site's domain by the browser. Phishing does not work against it, because a copied login page has a different domain and the passkey will not answer.

FluentAuth supports passkeys with no third party service. Everything runs on your site.

= Social Login and Registration =

Let people sign in with the accounts they already have.

- Login with Google
- Login with GitHub
- Login with Facebook
- Google One Tap Login

Turn on the providers you want, paste the keys, and the buttons appear on your login and register forms. You can also stop social sign ups when registration is closed on your site.

= Magic Login by Email =

Users type their email address and get a one time login link. No password to remember and no reset flow to walk through. You can make it the main way people sign in, or keep it as an extra option. Links are hashed, expire, and are rate limited.

= Limit Login Attempts =

Block brute force attacks by counting failed logins. Set how many attempts are allowed and over how many minutes, and FluentAuth locks the address out for a while. Every blocked attempt is logged, and you can be emailed when it happens.

= IP Allow List and Block List =

Two simple lists, one address or range per line.

- The block list refuses a login from those addresses outright.
- The allow list skips the attempt limit for addresses you trust, such as your office.

You can also require that a role only signs in from an allow listed address. FluentAuth detects reverse proxies and Cloudflare, so the address it acts on is the real visitor address and not your proxy.

= Security Checklist =

FluentAuth checks your site and gives you a short list of what to look at. Each item says what is wrong, why it matters and what happens if you fix it. Most of them have a button that fixes it for you.

It checks things like:

- Whether your site is served over HTTPS
- Whether PHP errors are shown to visitors
- Whether the dashboard can edit theme and plugin files
- Whether the right constants are set in wp-config.php
- Whether old backup files are sitting in a public folder
- Whether PHP can run inside your uploads folder
- Whether any drop-in or mu-plugin file has appeared or changed
- Whether an administrator uses an easily guessed username
- Whether any administrator account has gone unused
- Whether there are user accounts that do not show on the users screen

Anything that does not apply to your site can be waved away, and you can take that back later.

= File Change Scanning =

FluentAuth compares your files against the official copies published on WordPress.org.

- **WordPress core files** are checked against the official checksums for your version.
- **Plugins from the WordPress.org directory** are checked against the official checksums for the version you have installed.
- **Themes from the WordPress.org directory** are checked against the official theme package, because there are no published checksums for themes. This needs the ZipArchive PHP extension, which most hosts have.
- **Files nothing else can verify**, such as a custom theme or a premium plugin, can be recorded in a snapshot so you hear about it when one of them changes.

When a file has changed you can see a side by side diff of your copy against the original, put the original back with one click, or delete a file that should not be there. You can also flag a plugin or theme running a version that was never published, which is a common sign that files were swapped out.

= Activity and Audit Logs =

FluentAuth records every login, every failed attempt and every blocked address. It also records when a plugin or theme is activated, deactivated or updated, and who did it. Logs go in their own database tables, so your WordPress tables stay clean, and old entries are cleared automatically on a schedule you pick.

= Email Notifications and Reports =

Get an email when an administrator or editor signs in, or when someone is blocked for too many failed attempts. You can also get a daily, weekly or monthly summary of what happened on your site.

= Recovery Tools =

If you think somebody has been in your site, there is a screen that tells you what to do next.

- Sign everyone out and revoke every application password
- Send password reset emails to your users, in batches so nothing times out
- Reinstall WordPress core from the official copy
- Reinstall a plugin or theme from the WordPress.org directory
- Rotate the security keys in wp-config.php, with a clear warning about what else that breaks

Everything done here is written to the audit log with the name of the person who did it.

= Login Redirects =

Send users to different pages after they log in or log out, based on their role. Set it up once and it applies to every login method, including social and magic login.

= Login and Signup Page Customizer =

Change the look of your WordPress login page. Set your own logo, colours, background and form style, and see the result as you edit. You can also build your own login and registration forms anywhere on your site with shortcodes.

= Custom WordPress System Emails =

WordPress sends a lot of plain default emails. FluentAuth lets you rewrite them with your own wording and your own branding, and gives you one template design that they all share. You can also turn off the admin notification that fires every time a new user signs up.

= Core Security Hardening =

Turn off the parts of WordPress your site does not use.

- Disable XML-RPC
- Disable application passwords and remote app login
- Stop user listings being read through the REST API
- Restrict /wp-admin for low level roles
- Hide the admin bar for the roles you choose

= Remote Auth for Multiple Sites =

Use one site as the login provider for your other sites. Users sign in once on the main site and land on the child site already logged in.

= Guided Setup =

A short setup wizard runs the first time you open FluentAuth. It asks a handful of questions, shows you what each answer changes, and turns on a sensible set of options. Skip it and nothing is written, and every answer is an ordinary setting you can change later.

= Built to Be Fast =

FluentAuth is one plugin doing the work of several, and it is written to stay out of the way. The admin area is a single page app built with Vue 3 that talks over the REST API. Logs live in custom database tables. There is no scanning agent sitting in front of every request on your site.

== External Services ==

This plugin can connect to external services. Here is what they are, what gets sent, and when.

= 1. FluentAuth Alerts Service (optional, off by default) =

FluentAuth can scan your files on a schedule and email you when something changes. Those scheduled scans and alert emails are handled by the FluentAuth Alerts Service at `dash.fluentauth.com`, run by WPManageNinja LLC.

This is optional. Scanning runs on your own server either way, so if you never connect you can still scan by hand and read the results in your dashboard.

Nothing is sent unless you choose to connect on the Monitoring screen, which lists what would be sent before you decide. In short: your name and email, your site address, title and admin link, the paths of files that differ from the official release, and your installed plugins and themes with their versions. It never sends the contents of a file, anything from your database, or anything about your visitors. Reports stop when you turn scheduled scanning off, and you can disconnect at any time.

Privacy policy: [https://fluentauth.com/privacy-policy/](https://fluentauth.com/privacy-policy/)
Terms and conditions: [https://wpmanageninja.com/terms-and-conditions/](https://wpmanageninja.com/terms-and-conditions/)

= 2. WordPress.org and GitHub (for file scanning) =

To tell whether a file has changed, the plugin fetches the official copy to compare against. This happens when you run a scan, and when you view or restore a file.

- `api.wordpress.org` and `downloads.wordpress.org` for the official core checksums, plugin checksums, theme packages, and the files themselves when you reinstall one.
- `plugins.svn.wordpress.org`, `themes.svn.wordpress.org` and `raw.githubusercontent.com` for a single original file when you view a diff. The last of these is the official WordPress mirror on GitHub.

All that is sent is the name, version and file path of the item being checked. Nothing about your site or your users goes with it.

WordPress.org [Privacy Policy](https://wordpress.org/about/privacy/). GitHub [Terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and [Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement).

= 3. FluentAuth update emails (optional, only if you subscribe) =

The setup wizard and the dashboard offer a sign-up for release announcements and occasional WordPress security tips. If you fill it in and press Subscribe, your name, your email address and this site's address are sent to `dash.fluentauth.com`, run by WPManageNinja LLC, and you are sent an email asking you to confirm the address before anything else is delivered.

If you also tick the optional box, your PHP version, MySQL version and WordPress version go with it, so we know which versions to keep supporting. That box is off unless you tick it, and those three values are the whole of what it adds.

Nothing is sent unless you press Subscribe. Declining puts the card away, and every email has an unsubscribe link.

Privacy policy: [https://fluentauth.com/privacy-policy/](https://fluentauth.com/privacy-policy/)
Terms and conditions: [https://wpmanageninja.com/terms-and-conditions/](https://wpmanageninja.com/terms-and-conditions/)

= 4. Social login providers (only if you turn them on) =

If you enable a provider, your site talks to it when a user clicks its button to sign in. What is exchanged is the standard OAuth handshake, plus the user's name and email address so the account can be matched or created. Nothing is sent unless you set the provider up yourself.

- Google, at `accounts.google.com` and `oauth2.googleapis.com`. [Terms](https://policies.google.com/terms) and [Privacy Policy](https://policies.google.com/privacy)
- GitHub, at `github.com` and `api.github.com`. [Terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and [Privacy Policy](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement)
- Facebook, at `facebook.com` and `graph.facebook.com`. [Terms](https://www.facebook.com/terms.php) and [Privacy Policy](https://www.facebook.com/privacy/policy/)

== Why FluentAuth? ==

Most WordPress sites get broken into the same way. Somebody guesses a password, or reuses one that leaked somewhere else, and walks in through the login form. The login form is the door, and that is what FluentAuth guards.

Running several security plugins to cover this is its own problem. Each one hooks into every request and runs its own set of rules, and the site gets slower for it. One plugin that covers login security, two-factor authentication, social login, file scanning and audit logs is less work for your server and less work for you.

That is why we built FluentAuth, and that is why it is free.

== Replace Multiple Plugins with FluentAuth ==

If you use FluentAuth, you do not need these:

**For limiting login attempts and blocking brute force**

- Limit Login Attempts Reloaded
- WPS Limit Login

**For two-factor authentication**

- Two Factor
- WP 2FA

**For login and logout redirects**

- LoginWP (formerly Peter's Login Redirect)
- Sky Login Redirect
- WP Login and Logout Redirect

**For hiding the admin bar and restricting access**

- Hide Admin Bar
- Hide Admin Bar Based on User Roles
- Auto Hide Admin Bar
- Hide Admin Bar from Non-Admins

== User Guides ==
<ul>
	<li><a href="https://fluentauth.com/docs/getting-started/" target="_blank">Getting Started with FluentAuth</a></li>
	<li><a href="https://fluentauth.com/docs/login-redirects/" target="_blank">Login / Logout Redirects</a></li>
	<li><a href="https://fluentauth.com/docs/shortcodes/" target="_blank">Register/Login Shortcodes in FluentAuth</a></li>
	<li><a href="https://fluentauth.com/docs/github-auth-connection/" target="_blank">Configure Login with GitHub</a></li>
	<li><a href="https://fluentauth.com/docs/google-auth-connection/" target="_blank">Configure Login with Google</a></li>
	<li><a href="https://fluentauth.com/docs/facebook-auth-connection/" target="_blank">Configure Login with Facebook</a></li>
</ul>

== Other Plugins By The Same Team ==
<ul>
	<li><a href="https://wordpress.org/plugins/fluent-cart/" target="_blank">FluentCart A New Era of eCommerce – Faster, Lighter, and Simpler</a></li>
	<li><a href="https://wordpress.org/plugins/fluent-crm/" target="_blank">FluentCRM – Email Marketing, Newsletter, Email Automation and CRM Plugin for WordPress</a></li>
	<li><a href="https://wordpress.org/plugins/fluentform/" target="_blank">Fluent Forms – Fastest WordPress Form Builder Plugin</a></li>
	<li><a href="https://wordpress.org/plugins/ninja-tables/" target="_blank">Ninja Tables – Best WP DataTables Plugin for WordPress</a></li>
	<li><a href="https://wordpress.org/plugins/ninja-charts/" target="_blank">Ninja Charts – Best WP Charts Plugin for WordPress</a></li>
	<li><a href="https://wordpress.org/plugins/wp-payment-form/" target="_blank">WPPayForm - Stripe Payments Plugin for WordPress</a></li>
	<li><a href="https://wordpress.org/plugins/mautic-for-fluent-forms/" target="_blank">Mautic Integration For Fluent Forms</a></li>
	<li><a href="https://wordpress.org/plugins/fluentforms-pdf/" target="_blank">Fluent Forms PDF - PDF Entries for Fluent Forms</a></li>
	<li><a href="https://wordpress.org/plugins/fluent-smtp/" target="_blank">FluentSMTP - WordPress Mail SMTP, SES, SendGrid, MailGun Plugin</a></li>
</ul>

== CONTRIBUTE ==
If you want to contribute to this project or report a bug, you are welcome. The repository is on <a href="https://github.com/WPManageNinja/fluent-security/">GitHub</a>.

== Installation ==

This section describes how to install the plugin and get it working.

0. Search for FluentAuth in WordPress Plugins, then click install and activate.

OR

1. Upload the plugin files to the `/wp-content/plugins/fluent-auth` directory, or install the plugin through the WordPress plugins screen.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to `FluentAuth` and follow the short setup wizard, or open `FluentAuth` -> `Settings` to configure it yourself.

== Frequently Asked Questions ==

= Is FluentAuth free? =

Yes. Every feature described here is free. There is no paid version and no locked screens.

= Does it slow my site down? =

No. FluentAuth does not sit in front of every request the way a firewall plugin does. Logs are kept in their own database tables, so your WordPress tables stay small, and the admin area is a single page app that loads once.

= Does two-factor authentication work with Google Authenticator? =

Yes. The authenticator app option works with Google Authenticator, Authy, Microsoft Authenticator, 1Password, Bitwarden and any other app that supports TOTP.

= What is a passkey? =

A passkey lets someone sign in with Touch ID, Face ID, Windows Hello, a hardware security key or a password manager instead of typing a code. The browser ties it to your site's domain, so it cannot be used on a fake copy of your login page. FluentAuth supports passkeys as a second factor.

= Can I force two-factor authentication for administrators? =

Yes. You can pick which roles may set up a second factor and which roles must have one. A user who must have one is asked to set it up before they can use the admin area.

= Do I have to connect to an external service? =

No. Two-factor authentication, passkeys, audit logs, login limits and the rest all run on your own site.

Two things do reach out. Scanning asks WordPress.org for the official copy of your files, which is how it can tell whether a file changed, and it sends nothing about your site to do that. And there is an optional FluentAuth Alerts Service that handles scheduled scans and alert emails. It is off until you connect it, and the screen lists what would be sent before you decide. See the External Services section above.

= Is it GDPR compliant? =

Yes. All of your data stays in your WordPress database unless you choose to connect the optional alerts service, and what that sends is listed above in the External Services section.

= Does it work with WooCommerce and membership plugins? =

Yes. FluentAuth works on the standard WordPress login, so it covers logins from WooCommerce, LearnDash, membership plugins and custom login forms.

= Can I use it on a multisite install? =

Yes. FluentAuth runs per site on a multisite install, and it is aware of multisite when it decides whether a user may sign in to a given site. There is no network wide settings screen, so each site is configured on its own.

= What happens if I lock myself out? =

Use one of the recovery codes you were given when you set up your authenticator app. If you have lost those too, another administrator can reset your second factor from the 2FA Enrollment screen.

= Does the file scanner remove malware? =

It is not a malware scanner. It tells you which files no longer match the official copy published on WordPress.org, shows you what changed, and lets you put the original back. That catches the file changes an attacker leaves behind, and it does it without a signature list to keep up to date.

== Screenshots ==
1. Reporting Dashboard
2. Login Security Settings
3. Passkey, Authenticator App and Email Two-Factor Authentication
4. Custom Login/Signup Shortcodes
5. Dynamic Login Redirects
6. Detailed Audit Logs
7. Social Login Settings
8. System Emails Customization
9. Login/Signup Page Customizer
10. WordPress Core Files Integrity Check
11. Account and File Recovery Tools

== Changelog ==

= 2.2.0 - Date: Sep 16, 2026 =
* New: Passkey two-factor authentication with Touch ID, Windows Hello, security keys and password managers
* New: Authenticator app (TOTP) two-factor authentication, with the QR code drawn on your own server
* New: Ten single use recovery codes issued with every authenticator app setup, usable as a passkey fallback
* New: Per role two-factor enrollment and per role enforcement, with a setup prompt before admin access
* New: Two-Factor Enrollment screen listing enrolled users, with a per user reset
* New: Encryption for stored authenticator secrets, using a key kept in wp-config.php
* New: Security checklist with findings you can fix, accept or take back, covering HTTPS, debug output, the file editor, wp-config constants, backup files, uploads folder execution, drop-ins, mu-plugins, admin usernames, dormant admins and hidden users
* New: Plugin and theme file integrity scanning against the WordPress.org directory
* New: File baseline snapshots for custom themes and premium plugins that nothing else can verify
* New: Side by side diff for any changed file, with restore and delete
* New: Recovery tools for a site that has been broken into, including sign everyone out, revoke application passwords, batched password resets, core reinstall, plugin and theme reinstall and optional salt rotation
* New: IP allow list and IP block list, with a role restriction for allow listed addresses
* New: Reverse proxy and Cloudflare detection for the real visitor IP address
* New: Site activity logging for plugin and theme activation, deactivation and updates
* New: Guided setup wizard for new installs
* New: Six hourly and twelve hourly scan schedules
* New: Extension inventory sent with each scan report, so alerts can name the plugin or theme involved
* New: Login with Facebook documentation and setup screen
* New: Optional sign-up for release announcements and security tips, asked once and put away for a week if you decline
* Improved: The scanning service now tells you what it sends before you connect, and asks before disconnecting
* Improved: A scan you run by hand is now reported, not just the scheduled one
* Improved: Settings rebuilt around a sidebar, with related settings grouped on one page
* Improved: The second factor is now asked for on logins that never reach the login form
* Improved: Login attempt limits hardened, and login activity is always recorded
* Improved: Social login hardening
* Improved: Admin UI refreshed across the dashboard, settings, scanning and email screens
* Improved: The alerts service key is no longer sent to the browser in any response
* Improved: The alerts service key and site id now travel in the request body rather than the URL, so neither is written to a server log
* Improved: A backup copy left in your site's folder is reported whatever its extension, including copies of the rules file
* Improved: Two-factor code emails now have a send limit of their own, so turning the login attempt limit off no longer removes it
* Improved: Passkey clone detection now applies whenever the key has a counter, rather than being skipped when a zero is reported
* Improved: Email smart codes can no longer resolve to a password hash, a password reset key or private user data
* Improved: Sign-in links to a child site now expire after five minutes
* Fixed: Settings migrations now run when the plugin is updated, not only when it is activated by hand
* Fixed: A site switched off on the alerts dashboard could not open its own scanning screen
* Fixed: The dashboard counted everyone with an account when reporting two-factor enrollment, instead of the people who can actually enrol
* Fixed: Dark mode - dropdown arrows were invisible, and the restricted roles field appeared empty
* Fixed: Plugin and theme names were squeezed out of the Monitoring list on a phone
* Fixed: Recovery history showed "by false" for actions taken outside the dashboard, and the activity log showed "User #0"
* Fixed: Password reset email link

= 2.1.2 - Date: Apr 28, 2026 =
* Hardened Security Scan and Settings endpoints with stricter input validation and sanitization
* Sanitized social auth redirect cookie to prevent storing untrusted values
* Added client token verification in Google One-Tap login for stronger identity checks
* Fixed: Magic Login rate limiter incorrectly using days instead of minutes
* Fixed: Login issue with GitHub social authentication
* Fixed: Timezone mismatch in dashboard quick stats and audit log time differences
* Fixed: canLogin filter ignoring falsy return values (now respects developer overrides)
* Fixed: Sprintf positional argument syntax in digest email and removed a duplicate filter
* Improved: Translation readiness: wrapped previously hard-coded admin UI strings with the translation helper and fixed typos / awkward phrasing across the dashboard, settings, security scan, server mode, and email customization screens
* Improved: Internal test coverage and codebase reliability

= 2.1.1 - Date: Dec 03, 2025 =
* Introducing One-Tap Login via Google Social Auth Connection
* Improved Translation & Localization
* Security: Improved Data Security and Sanitization and compitable with latest WordPress security standards
* Bug Fixes and Performance Improvements

= 2.0.3 - Date: Jun 11, 2025 =
* Typo and Smartcode fixed on Custom Emails
* WP_Error Notice fixed

= 2.0.2 - Date: Jun 11, 2025 =
* Fixed: Login Redirect Issue
* Fixed Typo on Admin Menu
* Fixed Styling Issues

= 2.0.0 - Date: Jun 09, 2025 =
* Introduing Login/Signup Page Customizer
* Added Login with Facebook
* Added Syststem Emails Custimizations
* Introducing WordPress Core Files Integrity Check
* Configurable: One-Click Login via Email as primary login method
* UI & UX Improvements
* Disable Signup on social media connection when global signup is disabled

= 1.1.0 - Date: Dec 16, 2014 =
* Added hooks for 3rd party developers
* Improvement on Authentication flow

= 1.0.8 - Date: Dec 02, 2024 =
* Added Additional Hooks for Regsitration and Signup
* Improved UI & UX
* Fixed translation issues

= 1.0.7 - Date: Jul 26, 2024 =
* Added Email verification on User Regstration Flow
* PHP 8.x compatability issue fixed
* JS errors fixed on Magic Links Shortcodes

= 1.0.6 - Date: Jan 28, 2024 =
* Fix Compatibility issue with PHP 8.x
* Upgrade Internal Libraries
* Improved Login with Google
* Improved UI & UX

= 1.0.5 - Date: May 04, 2023 =
* Added Login or Signup with Google Social Auth Connection
* Magic Login URL token is now hashed to improve the security

= 1.0.4 - Date: Feb 04, 2023 =
* Added Daily/Weekly/Monthly Email reporting Feature
* Made Login Form as Custom (no login url expose)
* Two-Factor Authentication Improvement

= 1.0.2 - Date: Dec 17, 2022 =
* Fix UI issue on dashboard
* Login with GitHub improvement
* Do Two-Factor Authentication even for social login for selected user roles
* Added more hooks for developers

= 1.0.2 - Date: Dec 16, 2022 =
* Improved UI & UX
* Added feature to block /wp-admin access and hide admin bar for low-level user roles
* Fix conflict issue with LearnDash and other wp-users REST-API
* Improved IP Address for login verification.

= 1.0.0 - Date: Dec 12, 2022 =
* Initial Release

== Upgrade Notice ==

= 2.2.0 =
Adds passkeys, authenticator app two-factor authentication, a security checklist, plugin and theme file scanning, IP access rules and recovery tools. Your existing settings carry over.
