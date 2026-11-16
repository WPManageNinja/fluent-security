<?php
define('FLUENT_AUTH_PLUGIN_PATH', 'dummy/path');
define('FLUENT_AUTH_PLUGIN_URL', 'dummy/url');
define('FLUENT_AUTH_VERSION', '2.0.2');
define('WPINC', 'wp-includes');
define('COOKIEPATH', '/');
define('COOKIE_DOMAIN', '/');
if (!defined('LOGGED_IN_COOKIE')) {
    define('LOGGED_IN_COOKIE', 'wordpress_logged_in_phpstan');
}
if (!defined('AUTH_COOKIE')) {
    define('AUTH_COOKIE', 'wordpress_phpstan');
}
if (!defined('SECURE_AUTH_COOKIE')) {
    define('SECURE_AUTH_COOKIE', 'wordpress_sec_phpstan');
}
