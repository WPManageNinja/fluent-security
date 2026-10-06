<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\BrowserDetection;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\TwoFaBypass;

/**
 * Keeps the lockout escape visible while it is in place.
 *
 * The constant exists to get somebody back in, which means it exists to be removed
 * again - and the failure mode of every emergency switch is that it is left on, because
 * nothing ever reminds anybody. Two things run against that: a sign in it allowed is
 * written to the log like any other event, and the admin area says so on every screen
 * until the line is taken out.
 *
 * The notice is deliberately not dismissible. A warning that can be clicked away is a
 * warning that will be, on the first busy morning, and then the site is running without
 * a second factor and nothing on screen says so.
 */
class TwoFaBypassHandler
{
    public function register()
    {
        add_action('wp_login', [$this, 'maybeLogBypassedLogin'], 10, 2);
        add_action('admin_notices', [$this, 'renderNotice']);
    }

    /**
     * Records a sign in that skipped a second factor it would otherwise have owed.
     *
     * @param $login string
     * @param $user \WP_User
     * @return void
     */
    public function maybeLogBypassedLogin($login, $user = null)
    {
        if (!$user instanceof \WP_User || !TwoFaBypass::isActiveFor($user)) {
            return;
        }

        $agent = $this->getUserAgent();
        $detection = new BrowserDetection();

        flsDb()->table('fls_auth_logs')->insert([
            'user_id'    => $user->ID,
            'username'   => $user->user_login,
            'agent'      => $agent,
            'ip'         => Helper::getIp(),
            'browser'    => $detection->getBrowser($agent)['browser_name'],
            'device_os'  => $detection->getOS($agent)['os_family'],
            'status'     => 'login',
            'media'      => 'two_fa_bypassed',
            'description' => __('Signed in without a second factor, allowed by the constant in wp-config.php.', 'fluent-security'),
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ]);

        do_action('fluent_auth/two_fa_bypass_used', $user);
    }

    /**
     * @return void
     */
    public function renderNotice()
    {
        if (!TwoFaBypass::isConfigured() || !current_user_can('manage_options')) {
            return;
        }

        $who = TwoFaBypass::describe();

        ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php esc_html_e('Two-factor authentication is switched off in wp-config.php.', 'fluent-security'); ?></strong>
                <?php
                echo esc_html(sprintf(
                    /* translators: %1$s: the accounts covered, %2$s: the constant name */
                    __('It currently covers %1$s, who can sign in with a password alone. Remove the %2$s line once the second factor is working again.', 'fluent-security'),
                    $who,
                    TwoFaBypass::CONSTANT
                ));
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * @return string
     */
    private function getUserAgent()
    {
        return isset($_SERVER['HTTP_USER_AGENT'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']))
            : '';
    }
}
