<?php

defined('ABSPATH') || exit;

/*
 * Init Direct Classes Here
 */

(new \FluentAuth\App\Hooks\Handlers\AdminMenuHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\CustomAuthHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\LoginSecurityHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\MagicLoginHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\SocialAuthHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\TwoFaHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\BasicTasksHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\WPSystemEmailHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\LoginCustomizerHandler())->register();
(new \FluentAuth\App\Hooks\Handlers\ServerModeHandler())->register();

