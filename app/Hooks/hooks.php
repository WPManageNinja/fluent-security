<?php

defined('ABSPATH') || exit;

/*
 * Init Direct Classes Here
 */

/*
 * Settings brought forward for a site that updated rather than activated. Activation
 * hooks do not fire on update, so this is the only thing that reaches those sites - see
 * Activator::maybeMigrateSettings().
 *
 * On `plugins_loaded` rather than `admin_init`, because the event this has to beat is a
 * login, and `admin_init` does not run on wp-login.php. A site updated by auto-update,
 * WP-CLI or a deploy is very often next touched by somebody signing in - and arriving
 * after that is arriving after the administrator has already been held at the login
 * screen, which is the exact morning this exists to prevent. The flag it reads is
 * autoloaded, so the usual case costs nothing.
 */
// No leading backslash: WordPress builds the callback id from this string verbatim, so a
// spelling nobody would guess is a hook nobody can remove_action() off.
add_action('plugins_loaded', ['FluentAuth\App\Helpers\Activator', 'maybeMigrateSettings'], 1);

(new \FluentAuth\App\Hooks\Handlers\AdminMenuHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\CustomAuthHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\LoginSecurityHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\MagicLoginHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\SocialAuthHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\GoogleOneTapAuthHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TwoFaHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TotpProfileHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\PasskeyProfileHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TwoFaProfileHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TotpSetupPageHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TotpNudgeHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TwoFaReminderHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TwoFaBypassHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\PasskeyLoginHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\BasicTasksHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\SiteActivityHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\WPSystemEmailHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\LoginCustomizerHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\ServerModeHandler())->register();
