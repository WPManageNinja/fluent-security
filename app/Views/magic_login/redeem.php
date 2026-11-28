<?php defined('ABSPATH') || exit;

/**
 * @var bool $is_valid
 * @var string $site_name
 * @var string $login_url
 */

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php echo esc_attr(get_option('blog_charset')); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <meta name="referrer" content="no-referrer">
    <title><?php echo esc_html($site_name); ?></title>
    <style>
        body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f6f7f9; color: #1d2327; font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        .fls_redeem { max-width: 360px; padding: 32px 24px; text-align: center; }
        .fls_redeem p { margin: 0 0 20px; }
        .fls_redeem button, .fls_redeem a { display: inline-block; padding: 10px 20px; border: 0; border-radius: 6px; background: #1F7F4C; color: #fff; font: inherit; text-decoration: none; cursor: pointer; }
        @media (prefers-color-scheme: dark) { body { background: #16181d; color: #e6e7ea; } }
    </style>
</head>
<body>
<div class="fls_redeem">
    <?php if ($is_valid): ?>
        <form id="fls_redeem_form" method="post">
            <p><?php esc_html_e('Signing you in...', 'fluent-security'); ?></p>
            <button type="submit">
                <?php
                /* translators: %s: Site Name */
                echo esc_html(sprintf(__('Sign in to %s', 'fluent-security'), $site_name));
                ?>
            </button>
        </form>
        <script>
            // Automated browsers can run this too; leave them the button, which they will not press.
            if (!navigator.webdriver) {
                document.getElementById('fls_redeem_form').submit();
            }
        </script>
    <?php else: ?>
        <p><?php esc_html_e('This sign-in link has expired or was already used.', 'fluent-security'); ?></p>
        <a href="<?php echo esc_url($login_url); ?>"><?php esc_html_e('Go to the login page', 'fluent-security'); ?></a>
    <?php endif; ?>
</div>
</body>
</html>
