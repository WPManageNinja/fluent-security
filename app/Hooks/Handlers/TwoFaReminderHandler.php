<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Services\TwoFa\DeviceRequirement;

/**
 * Tells somebody who owes a second factor that they owe one, and where to set it up.
 *
 * That is the whole of it, and the shrinking is the point. This class used to be an
 * enforcement gate: it redirected users out of every wp-admin page, refused
 * admin-ajax, and refused REST - the last two blanket, for any user who owed a factor.
 * All three are gone (2026-09-18), on the view that they were the wrong amount of
 * machinery for what this plugin is.
 *
 * The reasoning, since removing a security control deserves to be written down rather
 * than discovered later in a diff:
 *
 * - The real gate is elsewhere and always was, now. EnrollmentTwoFaMethod runs during
 *   the login itself, before the auth cookie is issued, and a required user cannot get
 *   a session without setting a factor up. Nothing here protects that; it never did.
 * - So all this ever covered was the gap between an owner switching the requirement on
 *   and the people already signed in next signing out. On the sites this plugin is for -
 *   a small business, very often one administrator - that population is the owner
 *   themselves, for one session, immediately after they chose the setting.
 * - Against that, the cost was real and measured. The ajax refusal 403'd nine of twelve
 *   common actions, including front-end form submissions and add-to-cart for ordinary
 *   logged-in members. The REST refusal did the same to every authenticated REST call on
 *   the site. Neither said anything a site owner could trace back to this plugin, and one
 *   of them - recovery codes missing from the ajax allowlist - locked a real user out of
 *   3.0.1 with no route back in.
 *
 * So the trade is: a session that predates the policy keeps working normally until it
 * ends, and the person holding it is told, on every admin screen, that they need to set
 * a factor up and where to do it. Enforcement happens at the door, once, where it cannot
 * be worked around and cannot break anything.
 *
 * Application passwords stay governed by `disable_app_login`, which is the switch a site
 * owner already has for them - not by this.
 */
class TwoFaReminderHandler
{
    public function register()
    {
        add_action('admin_notices', [$this, 'renderNotice']);
    }

    /**
     * @return void
     */
    public function renderNotice()
    {
        if (!$this->owesDeviceFactor()) {
            return;
        }

        /*
         * The profile screen rather than the standalone setup page, because anybody
         * reading an admin notice is already in wp-admin and the profile screen is the
         * fuller of the two - it offers a passkey, an authenticator app and recovery
         * codes on one card. The standalone page is for users who cannot get here at all,
         * and they meet it during login instead.
         */
        $url = admin_url('profile.php#fls-two-factor');

        ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php esc_html_e('Two-factor authentication is required for your account.', 'fluent-security'); ?></strong>
                <?php esc_html_e('You can carry on for now, but you will be asked to set one up the next time you sign in.', 'fluent-security'); ?>
            </p>
            <p>
                <a href="<?php echo esc_url($url); ?>" class="button button-primary">
                    <?php esc_html_e('Set it up now', 'fluent-security'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Whether the person reading this owes a device factor.
     *
     * Public because it is the whole of the decision, and because a notice that appears
     * on every admin screen is worth being able to ask about directly.
     *
     * @return bool
     */
    public function owesDeviceFactor()
    {
        if (!is_user_logged_in()) {
            return false;
        }

        $user = wp_get_current_user();

        return $user instanceof \WP_User && DeviceRequirement::isOwedBy($user);
    }
}
