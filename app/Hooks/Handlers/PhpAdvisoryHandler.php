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

    public function register()
    {
        add_action('admin_notices', [$this, 'renderNotice']);
    }

    /**
     * @return void
     */
    public function renderNotice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $status = self::statusFor(PHP_VERSION);

        if ($status === 'safe') {
            return;
        }

        ?>
        <div class="notice notice-error">
            <p>
                <strong>FluentAuth:</strong>
                <strong>
                    <?php
                    /* translators: %s: PHP version, e.g. 8.3.20 */
                    echo esc_html(sprintf(__('This site runs PHP %s, which has a critical security hole that lets attackers take over the server.', 'fluent-security'), PHP_VERSION));
                    ?>
                </strong>
                <?php if ($status === 'outdated') : ?>
                    <?php
                    /* translators: %s: the PHP version that contains the fix, e.g. 8.3.36 */
                    echo esc_html(sprintf(__('Ask your hosting provider to update PHP to %s or newer. This is a server update; no plugin can fix it.', 'fluent-security'), self::FIXED[self::branchOf(PHP_VERSION)]));
                    ?>
                <?php else : ?>
                    <?php esc_html_e('This PHP version no longer gets security fixes. Upgrade to PHP 8.2 or newer; your hosting provider can do this for you.', 'fluent-security'); ?>
                <?php endif; ?>
            </p>
        </div>
        <?php
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
        // Distro builds append a suffix ("8.3.6-1ubuntu0.2") that version_compare would
        // read as a pre-release; only the leading x.y.z says anything here.
        if (preg_match('/^\d+\.\d+\.\d+/', $version, $match)) {
            $version = $match[0];
        }

        $branch = self::branchOf($version);

        if (isset(self::FIXED[$branch])) {
            return version_compare($version, self::FIXED[$branch], '>=') ? 'safe' : 'outdated';
        }

        return version_compare($branch, '8.2', '<') ? 'unsupported' : 'safe';
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
