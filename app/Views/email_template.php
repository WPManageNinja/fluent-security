<?php
defined('ABSPATH') || exit;
/**
 * @var array $template_config
 * @var string $body
 * @var string $footer
 **/
?>
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <meta name="x-apple-disable-message-reformatting">
    <style>
        body {
            margin: 0;
            line-height: 1.5;
        }

        .body_wrap {
            font-family: ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji"
        }

        p {
            font-size: 16px;
            line-height: 24px;
        }

        ul, li {
            font-size: 16px;
            line-height: 24px;
        }

        blockquote {
            background-color: rgb(249, 250, 251);
            padding: 16px;
            border-radius: 4px;
            margin: 24px 0;
            border-left-width: 4px;
        }

        hr {
            border-color: rgb(209, 213, 219);
            margin-top: 24px;
            margin-bottom: 24px;
            width: 100%;
            border: none;
            border-top: 1px solid #eaeaea;
        }

        blockquote p {
            font-size: 15px;
            color: rgb(55, 65, 81);
            margin: 0px;
            line-height: 24px;
        }

        .footer_text {
            font-size: 12px;
            line-height: 18px;
            text-align: center;
        }
    </style>

    <?php if ($template_config): ?>
        <style id="pref_style">
            <?php if(!empty($template_config['body_bg'])) : ?>
            body, .body_wrap {
                background-color: <?php echo esc_html($template_config['body_bg']); ?>;
            }

            <?php endif; ?>
            <?php if(!empty($template_config['footer_content_color'])) : ?>
            .footer_table {
                color: <?php echo esc_html($template_config['footer_content_color']); ?>;
            }

            <?php endif; ?>

            .content_wrap {
                background-color: <?php echo esc_html($template_config['content_bg']); ?>;
                color: <?php echo esc_html($template_config['content_color']); ?>;
            }

            blockquote {
                background-color: <?php echo esc_html($template_config['highlight_bg']); ?>;
                color: <?php echo esc_html($template_config['highlight_color']); ?>;
            }

            blockquote p {
                color: <?php echo esc_html($template_config['highlight_color']); ?>;
            }
        </style>
    <?php endif; ?>

    <?php do_action('fluent_auth/wp_system_email_head'); ?>
</head>
<body>
<div class="body_wrap">
    <table align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-left:auto;margin-right:auto;padding-top:32px;padding-bottom:32px;padding-left:16px;padding-right:16px;max-width:600px">
        <tbody>
        <tr style="width:100%">
            <td>
                <table class="content_wrap" align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="border-radius:8px;padding:32px;box-shadow:0 0 #0000, 0 0 #0000, 0 1px 2px 0 rgb(0,0,0,0.05)">
                    <tbody>
                    <tr>
                        <td>
                            <?php echo $body; ?>
                        </td>
                    </tr>
                    </tbody>
                </table>
                <?php if (!empty($footer)): ?>
                    <table class="footer_table" align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:32px;text-align:center;">
                        <tbody>
                        <tr>
                            <td class="footer_text">
                                <?php echo $footer; ?>
                            </td>
                        </tr>
                        </tbody>
                    </table>
                <?php endif; ?>
            </td>
        </tr>
        </tbody>
    </table>
</div>
</body>
</html>
