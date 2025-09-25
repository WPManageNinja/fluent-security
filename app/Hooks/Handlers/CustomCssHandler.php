<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class CustomCssHandler
{
    public function register()
    {
        add_action('login_head', [$this, 'injectLoginCss']);
        add_action('wp_head', [$this, 'injectFrontendCss']);
    }

    public function injectLoginCss()
    {
        if ($this->isFluentAuthLoginPage()) {
            $this->outputCustomCss();
        }
    }

    public function injectFrontendCss()
    {
        if ($this->shouldInjectFrontendCss()) {
            $this->outputCustomCss();
        }
    }

    public function outputCustomCss()
    {
        $settings = Helper::getAuthSettings();
        $customCss = $settings['custom_css'] ?? '';

        if (empty($customCss)) {
            return;
        }

        $customCss = $this->sanitizeCss($customCss);

        if (empty($customCss)) {
            return;
        }

        echo '<style type="text/css" id="fls-login-customizer-custom-css">' . "\n";
        echo $customCss . "\n";
        echo '</style>' . "\n";
    }

    private function sanitizeCss($css)
    {
        $css = preg_replace('/<script[^>]*>.*?<\/script>/si', '', $css);
        $css = preg_replace('/javascript:/i', '', $css);
        $css = preg_replace('/vbscript:/i', '', $css);
        $css = preg_replace('/on\w+\s*=/i', '', $css);

        $css = strip_tags($css);

        return $css;
    }

    private function shouldInjectFrontendCss()
    {
        $formsSettings = Helper::getAuthFormsSettings();
        if (empty($formsSettings['enabled']) || $formsSettings['enabled'] !== 'yes') {
            return false;
        }

        global $post;
        if (!$post) {
            return false;
        }

        $shortcodes = ['fluent_auth', 'fluent_auth_login', 'fluent_auth_signup', 'fluent_auth_reset_password', 'fluent_auth_magic_login'];

        foreach ($shortcodes as $shortcode) {
            if (has_shortcode($post->post_content, $shortcode)) {
                return true;
            }
        }

        return false;
    }

    private function isFluentAuthLoginPage()
    {
        $customizerSettings = Helper::getAuthCustomizerSettings();

        if (empty($customizerSettings['status']) || $customizerSettings['status'] !== 'yes') {
            return false;
        }

        return true;
    }
}
