=== FluentAuth - Login Security, Two-Factor Authentication, Passkeys & Social Login ===
Contributors: techjewel, wpmanageninja, adreastrian
Tags: security, two factor authentication, limit login attempts, social login, login
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 7.3
Stable tag: 3.0.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Two-factor authentication, passkeys, social login, magic login, limit login attempts, file change scanning and audit logs for WordPress.

== Description ==

FluentAuth is a login security plugin for WordPress. It protects the way people sign in to your site, and it tells you when something on your site has changed.

You get two-factor authentication, passkeys, social login, magic login links, login attempt limits, IP access rules, a security checklist, file change scanning and a full audit log. All of it in one plugin, with no bloat and no slowdown.

**Highlighted Features**

- Two-Factor Authentication (email, authenticator app and passkeys)
- Passkey sign-in with Touch ID, Windows Hello, a security key or a password manager
- Social Login with Google, GitHub and Facebook
- Google One Tap Login
- Magic Login links by email, with no password
- Limit Login Attempts and block brute force attacks
- IP allow list and IP block list
- Security checklist that finds problems and fixes them
- WordPress core, plugin and theme file change scanning
- Audit log of every login, failed attempt and plugin change
- Login and logout redirects
- Login and signup page customizer
- Custom WordPress system emails
- Restrict /wp-admin by user role
- Recovery tools for a site that has been hacked

[youtube https://www.youtube.com/watch?v=Tt9LHwHySmA]

= Two-Factor Authentication (2FA) =

Ask for a second step after the password. Three ways to do it, and you choose which roles may use each one.

- **Email codes.** A one time code sent to the user's inbox. Nothing to install.
- **Authenticator app.** Google Authenticator, Authy, 1Password or any other TOTP app. FluentAuth draws the QR code on your own server, so the secret never leaves your site.
- **Passkeys.** Touch ID, Face ID, Windows Hello, a hardware security key or a password manager. The browser ties the passkey to your domain, so it cannot be used on a fake copy of your login page.

You can let a role set up a second factor or require it, and you choose how strong a required one has to be: a device factor only, meaning a passkey or an authenticator app, or any of the three. Anyone who must have one sets it up while they sign in, before a session is created for them, so the requirement cannot be walked past.

An authenticator app also hands out ten single use recovery codes, and passkey users can fall back on those too. Everyone manages their own second factor from their WordPress profile screen, and an admin screen lists who has enrolled, what each person registered, and lets you reset anyone locked out.

Authenticator secrets can be encrypted in your database with a key you keep in wp-config.php, so reading the database gets an attacker nothing.

= Passkey Login =

Passkeys are the strongest option here. The credential lives on the device and is bound to your domain by the browser, so phishing does not work against it: a copied login page has a different domain and the passkey will not answer.

They can be the second step after a password, or the way in on their own - turn on passkey sign-in and the login form offers a button that signs the user in with no password at all. No third party service is involved: everything runs on your site.

= Social Login and Registration =

Let people sign in with the accounts they already have.

- Login with Google
- Login with GitHub
- Login with Facebook
- Google One Tap Login

Turn on the providers you want, paste the keys, and the buttons appear on your login and register forms. You can also stop social sign ups when registration is closed on your site.

= Magic Login by Email =

Users type their email address and get a one time login link. No password to remember and no reset flow to walk through. Make it the main way people sign in, or keep it as an extra option. Links are hashed, expire, are rate limited and can only be claimed once, and asking for a link never reveals whether an address has an account on your site.

= Limit Login Attempts =

Block brute force attacks by counting failed logins. Set how many attempts are allowed and over how many minutes, and FluentAuth locks the address out for a while. Every blocked attempt is logged, and you can be emailed when it happens.

= IP Allow List and Block List =

Two simple lists, one address or range per line. The block list refuses a login from those addresses outright. The allow list skips the attempt limit for addresses you trust, such as your office.

You can also require that a role only signs in from an allow listed address. FluentAuth detects reverse proxies and Cloudflare, so the address it acts on is the real visitor address and not your proxy.

= Security Checklist =

FluentAuth checks your site and gives you a short list of what to look at. Each item says what is wrong, why it matters and what happens if you fix it, and most have a button that fixes it for you. Anything that does not apply can be waved away, and you can take that back later. It checks things like:

- HTTPS, and PHP errors shown to visitors
- Theme and plugin file editing from the dashboard
- The security constants in wp-config.php
- Old backup files sitting in a public folder
- PHP execution inside your uploads folder
- Drop-in or mu-plugin files that have appeared or changed
- Administrators with an easily guessed username, or gone unused
- User accounts that do not show on the users screen

= File Change Scanning =

FluentAuth compares your files against the official copies published on WordPress.org.

- **WordPress core files**, against the official checksums for your version.
- **Plugins from the WordPress.org directory**, against the checksums for the version you have installed.
- **Themes from the WordPress.org directory**, against the official theme package, since themes have no published checksums. Needs the ZipArchive PHP extension, which most hosts have.
- **Files nothing else can verify**, such as a custom theme or a premium plugin, recorded in a snapshot so you hear about it when one changes.

When a file has changed you can see a side by side diff against the original, put the original back with one click, or delete a file that should not be there. You can also flag a plugin or theme running a version that was never published, a common sign that files were swapped out.

= Activity and Audit Logs =

FluentAuth records every login, failed attempt and blocked address, and every plugin or theme activated, deactivated or updated, with who did it. Logs go in their own database tables, so your WordPress tables stay clean, and old entries are cleared on a schedule you pick.

= Email Notifications and Reports =

Get an email when an administrator or editor signs in, or when someone is blocked for too many failed attempts. You can also get a daily, weekly or monthly summary of what happened on your site.

= Recovery Tools =

If you think somebody has been in your site, one screen tells you what to do next.

- Sign everyone out and revoke every application password
- Send password reset emails to your users, in batches so nothing times out
- Reinstall WordPress core from the official copy
- Reinstall a plugin or theme from the WordPress.org directory
- Rotate the security keys in wp-config.php, with a clear warning about what else that breaks

Everything done here is written to the audit log with the name of the person who did it.

= Login Redirects =

Send users to different pages after they log in or log out, based on their role. Set it up once and it applies to every login method, including social and magic login.

= Login and Signup Page Customizer =

Set your own logo, colours, background and form style on the WordPress login page, and see the result as you edit. You can also build login and registration forms anywhere on your site with shortcodes.

= Custom WordPress System Emails =

WordPress sends a lot of plain default emails. FluentAuth lets you rewrite them with your own wording and branding, and gives you one template design they all share. You can also turn off the admin notification that fires every time a new user signs up.

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

FluentAuth is one plugin doing the work of several, written to stay out of the way. The admin area is a single page Vue 3 app over the REST API, logs live in custom database tables, and no scanning agent sits in front of every request on your site.

= For Developers =

Another plugin can put its own login screen on FluentAuth's flows. It registers with the LoginBridge service, and from then on its custom form gets the attempt limits, the IP rules and the two-factor challenge, including an inline second step on a custom AJAX action. There are filters through the whole auth flow, and the site owner's settings always win over what an adopting plugin asks for.

== External Services ==

Nothing below leaves your site unless you turn that feature on.

* **File scanning** compares your files against the official copies, so it fetches them from WordPress.org (`api.wordpress.org`, `downloads.wordpress.org`, `plugins.svn.wordpress.org`, `themes.svn.wordpress.org`) and the official WordPress mirror on GitHub (`raw.githubusercontent.com`). Only the name, version and file path of the item being checked is sent. [WordPress.org privacy](https://wordpress.org/about/privacy/) · GitHub [terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and [privacy](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement).
* **FluentAuth Alerts Service** (`dash.fluentauth.com`, run by WPManageNinja LLC) sends you scheduled scan alerts by email. Off until you connect it, and the screen lists what would be sent - your name and email, your site address and title, the paths of files that differ, and your plugin and theme versions - before you decide. Never file contents, database data, or anything about your visitors. [Privacy](https://fluentauth.com/privacy) · [Terms](https://fluentauth.com/terms).
* **Social login** contacts Google, GitHub or Facebook only if you set one up, and only when a user clicks the button: the standard OAuth handshake plus the user's name and email so the account can be matched. Google ([terms](https://policies.google.com/terms), [privacy](https://policies.google.com/privacy)) · GitHub ([terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service), [privacy](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement)) · Facebook ([terms](https://www.facebook.com/terms.php), [privacy](https://www.facebook.com/privacy/policy/)).

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

A passkey lets someone sign in with Touch ID, Face ID, Windows Hello, a hardware security key or a password manager instead of typing a code. The browser ties it to your site's domain, so it cannot be used on a fake copy of your login page. FluentAuth supports passkeys as a second factor, and as a way to sign in on their own with no password at all.

= Can I force two-factor authentication for administrators? =

Yes. You can pick which roles may set up a second factor and which roles must have one. A user who must have one is asked to set it up while they sign in, before a session is created for them, so the requirement cannot be walked past by going straight to a page that is not the login form. You can also say how strong that factor has to be: a device factor only, meaning a passkey or an authenticator app, or any of the three including an emailed code.

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

If you are the only administrator and everything is gone, add `define('FLUENT_AUTH_DISABLE_TWO_FA', true);` to your wp-config.php and the second factor is lifted for the whole site. Put a username in place of `true` to lift it for that one account only. Take the line out once you are back in. While it is there the login screen says so, the dashboard warns you, and every sign-in that used it is written to the audit log.

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
12. Passkey Sign-In Without a Password
13. Security Checklist With One-Click Fixes

== Changelog ==

= 3.0.3 - Date: Sep 20, 2026 =
* Added Compiatibility with MainWP or Programmatically Authenticate Users
* Improved User Facing Strings and Error Messages
* Showing recovery help message after 50 seconds of inactivity on the two-factor setup screen

= 3.0.2 - Date: Sep 18, 2026 =
* Fix: Requiring two-factor no longer locks anybody out of wp-admin, or breaks front-end forms and add-to-cart for logged-in members.
* Fix: Sites in other languages no longer report a WordPress core file as changed on every scan.
* Fix: Recovery codes are shown only to the person they belong to, and setting up an authenticator app no longer replaces codes you have already saved.
* Fix: Passkey setup on sites that use passkeys without authenticator apps, including retrying a prompt the server refused.
* New: Tells you when another plugin is also enforcing two-factor login, since two of them cannot both finish a sign-in.
* Improvement: Says when a scan could not reach WordPress.org, instead of going quiet.

= 3.0.1 - Date: Sep 17, 2026 =
* Fix: Setup wizard switches could not be turned off.
* Fix: Two-factor requirements now follow the method switches - a method that is off is off for everybody. Sites updating from 3.0.0 that required a factor with every method off keep working: the authenticator app is switched on for them automatically.
* Fix: The dashboard reported two-factor as off on sites using passkeys without authenticator apps.
* Fix: The login page designer can now edit the sign-in form's own colours, and from name and reply-to apply to every email FluentAuth sends.
* Improvement: Plain-language rewrite of the admin screens, plus fixes to activity log search, the encryption panel and sign-ins through third-party login forms.

= 3.0.0 - Date: Sep 16, 2026 =
* New: Two-factor authentication with passkeys, authenticator apps and email codes. Pick which roles may set one up and which must have one, and how strong a required factor has to be. A required factor is now enrolled during sign-in, before a session is created, and everyone manages their own from their WordPress profile screen. Ten recovery codes come with every authenticator setup, stored secrets can be encrypted with a key in wp-config.php, and an emergency bypass constant is there for the day somebody locks themselves out.
* New: Passkey sign-in with no password at all, offered on the login form beside magic links and social login.
* New: Security checklist that tells you what to fix and fixes most of it for you, covering HTTPS, debug output, the file editor, wp-config constants, backup files, uploads folder execution, drop-ins, mu-plugins, admin usernames, dormant admins and hidden users.
* New: File change scanning for WordPress core, and for plugins and themes from the WordPress.org directory, with a side by side diff, a one click restore, and baseline snapshots for the files nothing else can verify.
* New: Recovery tools for a site that has been broken into - sign everyone out, revoke application passwords, batched password resets, core and extension reinstall, and optional salt rotation, each one written to the audit log.
* New: IP allow and block lists with a role restriction, real visitor IP detection behind a reverse proxy or Cloudflare, activity logging for plugin and theme changes, a guided setup wizard, and a LoginBridge service so another plugin can run its own login screen on FluentAuth's flows.
* Improved: Settings rebuilt around a sidebar and the admin UI refreshed throughout, with hardening across login attempts, magic login, social login, email smart codes and the alerts service - plus fixes for two-factor enrollment counts, dark mode, small screen layout and the password reset email link.

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

= 3.0.0 =
A major release. Adds passkey sign-in and passkey two-factor authentication, authenticator app two-factor authentication, a security checklist, plugin and theme file scanning, IP access rules and recovery tools. Your existing settings carry over, and a role you had already marked as requiring a second factor keeps exactly the meaning it had before.
