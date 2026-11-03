<?php

namespace FluentAuth\App\Hooks\Handlers;

/**
 * Tells an administrator when the server's PHP has a known critical hole, and that the
 * fix is their host's to make.
 *
 * Nothing in a plugin can defend against a bug in PHP itself - the php2shell pair
 * (CVE-2026-109618, CVE-2026-109619) can fire on mod_php before WordPress has loaded,
 * and the interim mitigations are server settings that ini_set() reaches too late. So
 * this only reads the version and says so. Small business owners do not read CVE feeds;
 * they do read wp-admin.
 */
class PhpAdvisoryHandler
{
    /**
     * The first fixed release on each branch still maintained upstream. A branch older
     * than every key here has no official release at all, only backports.
     */
    const FIXED = [
        '8.2' => '8.2.35',
        '8.3' => '8.3.36',
        '8.4' => '8.4.27',
        '8.5' => '8.5.12',
    ];

    const LEARN_MORE_URL = 'https://fluentauth.com/articles/php2shell';

    /**
     * The exact PHP_VERSION an administrator said their host has patched. Per site, like
     * every other FluentAuth option, so a sub-site admin on a network answers for their
     * own site only. Keyed to the version so the notice comes back when PHP changes.
     */
    const DISMISSED_OPTION = '__fls_php_advisory_dismissed';

    const DISMISS_ACTION = 'fluent_auth_dismiss_php_advisory';

    public function register()
    {
        add_action('admin_notices', [$this, 'renderNotice']);
        add_action('admin_post_' . self::DISMISS_ACTION, [$this, 'handleDismiss']);
    }

    /**
     * @return void
     */
    public function handleDismiss()
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Sorry, you are not allowed to do that.', 'fluent-security'), 403);
        }

        check_admin_referer(self::DISMISS_ACTION);

        self::dismiss();

        wp_safe_redirect(wp_get_referer() ?: admin_url());
        exit;
    }

    /**
     * @param $version string
     * @return void
     */
    public static function dismiss($version = PHP_VERSION)
    {
        update_option(self::DISMISSED_OPTION, $version, false);
    }

    /**
     * @param $version string
     * @return bool
     */
    public static function isDismissed($version = PHP_VERSION)
    {
        return get_option(self::DISMISSED_OPTION) === $version;
    }

    /**
     * @return void
     */
    public function renderNotice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $advisory = self::advisory();

        if (!$advisory) {
            return;
        }

        ?>
        <div class="notice notice-error">
            <p>
                <strong>FluentAuth:</strong>
                <strong><?php echo esc_html($advisory['title']); ?></strong>
                <?php echo esc_html($advisory['body']); ?>
                <a href="<?php echo esc_url($advisory['learn_more_url']); ?>" target="_blank" rel="noopener"><?php esc_html_e('Learn more', 'fluent-security'); ?></a>
            </p>
            <?php if ($advisory['dismiss_url']) : ?>
                <p>
                    <a href="<?php echo esc_url($advisory['dismiss_url']); ?>" class="button"><?php esc_html_e('My host confirmed this is patched', 'fluent-security'); ?></a>
                </p>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * What to tell the administrator, or null when this PHP is fine or an administrator
     * has said their host patched it. Shared by the WordPress notice and the dashboard,
     * which hides WordPress notices.
     *
     * An 'outdated' version is only a maybe: Ubuntu, Debian, RHEL and many hosts backport
     * the fix and keep the version number, and nothing inside PHP can tell us which. The
     * exception is a Sury build, which is confirmed and so cannot be dismissed.
     *
     * @param $fullVersion string
     * @return array|null status, confirmed, title, body, learn_more_url and dismiss_url
     */
    public static function advisory($fullVersion = PHP_VERSION)
    {
        $version = self::shortVersion($fullVersion);
        $status = self::statusFor($version);
        $confirmed = $status === 'outdated' && self::isSuryBuild($fullVersion);

        if ($status === 'safe' || (!$confirmed && self::isDismissed($fullVersion))) {
            return null;
        }

        if ($confirmed) {
            /* translators: %s: PHP version, e.g. 8.3.20 */
            $title = sprintf(__('This site runs PHP %s, which has a critical security hole that lets attackers take over the server.', 'fluent-security'), $version);
            /* translators: %s: the PHP version that contains the fix, e.g. 8.3.36 */
            $body = sprintf(__('Ask your hosting provider to update PHP to %s or newer. This is a server update; no plugin can fix it.', 'fluent-security'), self::FIXED[self::branchOf($version)]);
        } elseif ($status === 'outdated') {
            /* translators: %s: PHP version, e.g. 8.3.20 */
            $title = sprintf(__('This site runs PHP %s, which may have a critical security hole that lets attackers take over the server.', 'fluent-security'), $version);
            /* translators: %s: the PHP version that contains the fix, e.g. 8.3.36 */
            $body = sprintf(__('Linux distributions often patch PHP without changing the version number, so your server may already be safe. Ask your hosting provider if the security patch is applied. If not, ask them to update PHP to %s or newer.', 'fluent-security'), self::FIXED[self::branchOf($version)]);
        } else {
            /* translators: %s: PHP version, e.g. 8.3.20 */
            $title = sprintf(__('This site runs PHP %s, which has a critical security hole that lets attackers take over the server.', 'fluent-security'), $version);
            $body = __('This PHP version no longer gets security fixes. Upgrade to PHP 8.2 or newer; your hosting provider can do this for you.', 'fluent-security');
        }

        return [
            'status'         => $status,
            'confirmed'      => $confirmed,
            'title'          => $title,
            'body'           => $body,
            'learn_more_url' => self::LEARN_MORE_URL,
            'dismiss_url'    => $confirmed ? '' : self::dismissUrl()
        ];
    }

    /**
     * Ondrej Sury's packages ("8.4.20-1+ubuntu22.04.1+deb.sury.org+1") ship upstream
     * releases and never backport, so their version number is the truth.
     *
     * @param $version string
     * @return bool
     */
    public static function isSuryBuild($version)
    {
        return strpos($version, '+deb.sury.org') !== false;
    }

    /**
     * Raw rather than wp_nonce_url(), which HTML-escapes the ampersand and would break the
     * dashboard's href. Empty for anyone who may not dismiss.
     *
     * @return string
     */
    private static function dismissUrl()
    {
        if (!current_user_can('manage_options')) {
            return '';
        }

        return add_query_arg([
            'action'   => self::DISMISS_ACTION,
            '_wpnonce' => wp_create_nonce(self::DISMISS_ACTION)
        ], admin_url('admin-post.php'));
    }

    /**
     * 'safe', 'outdated' (a maintained branch below its fix) or 'unsupported' (a branch
     * with no official fix).
     *
     * @param $version string
     * @return string
     */
    public static function statusFor($version)
    {
        $version = self::shortVersion($version);
        $branch = self::branchOf($version);

        if (isset(self::FIXED[$branch])) {
            return version_compare($version, self::FIXED[$branch], '>=') ? 'safe' : 'outdated';
        }

        return version_compare($branch, '8.2', '<') ? 'unsupported' : 'safe';
    }

    /**
     * The leading x.y.z. Distro and host builds append whatever they like
     * ("8.3.6-1ubuntu0.2", "8.2.29-1+0~20250101.40+debian12~1.gbp1a2b3c"), which
     * version_compare would read as a pre-release and nobody needs to read in a notice.
     *
     * @param $version string
     * @return string
     */
    public static function shortVersion($version)
    {
        return preg_match('/^\d+\.\d+\.\d+/', $version, $match) ? $match[0] : $version;
    }

    /**
     * @param $version string
     * @return string
     */
    private static function branchOf($version)
    {
        $parts = explode('.', $version);

        return (int)$parts[0] . '.' . (isset($parts[1]) ? (int)$parts[1] : 0);
    }
}
