<?php defined('ABSPATH') || exit;

/**
 * @var string $url
 * @var string $btn_text
 */

?>
<a rel="noopener" target="_blank" href="<?php echo esc_url($url); ?>" style="background-color: #1F7F4C; font-size: 18px; font-family: Helvetica, Arial, sans-serif; font-weight: bold; text-decoration: none; padding: 14px 20px; color: #ffffff; border-radius: 5px; display: inline-block; mso-padding-alt: 0;">
    <!--[if mso]>
    <i style="letter-spacing: 25px; mso-font-width: -100%; mso-text-raise: 30pt;">&nbsp;</i>
    <![endif]-->
    <span style="mso-text-raise: 15pt;"><?php echo esc_html($btn_text); ?></span>
    <!--[if mso]>
    <i style="letter-spacing: 25px; mso-font-width: -100%;">&nbsp;</i>
    <![endif]-->
</a>
