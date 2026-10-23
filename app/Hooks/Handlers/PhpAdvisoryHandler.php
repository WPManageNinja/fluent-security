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
        </div>
        <?php
    }

    /**
     * What to tell the administrator, or null when this PHP is fine. Shared by the
     * WordPress notice and the dashboard, which hides WordPress notices.
     *
     * @return array|null title, body and learn_more_url
     */
    public static function advisory()
    {
        $version = self::shortVersion(PHP_VERSION);
        $status = self::statusFor($version);

        if ($status === 'safe') {
            return null;
        }

        return [
            /* translators: %s: PHP version, e.g. 8.3.20 */
            'title' => sprintf(__('This site runs PHP %s, which has a critical security hole that lets attackers take over the server.', 'fluent-security'), $version),
            'body'  => $status === 'outdated'
                /* translators: %s: the PHP version that contains the fix, e.g. 8.3.36 */
                ? sprintf(__('Ask your hosting provider to update PHP to %s or newer. This is a server update; no plugin can fix it.', 'fluent-security'), self::FIXED[self::branchOf($version)])
                : __('This PHP version no longer gets security fixes. Upgrade to PHP 8.2 or newer; your hosting provider can do this for you.', 'fluent-security'),
            'learn_more_url' => self::LEARN_MORE_URL
        ];
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
