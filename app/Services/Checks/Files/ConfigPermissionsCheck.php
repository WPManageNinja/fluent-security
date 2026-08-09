<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * Whether wp-config.php can be read by anyone else on the server.
 *
 * The file holds the database password and the keys that sign every login cookie. On a shared
 * server, world-readable means the other accounts on that machine can read both.
 *
 * Only world-readable is reported. Group-readable is usually deliberate - it is how a good
 * many hosts let the web server and the site's own user share a file - and flagging it would
 * mark a correctly configured site down for its host's arrangement, which is the kind of
 * wrongness that teaches people to stop reading the list.
 *
 * Worth a look rather than fix-this, for the same reason: on a server with one account on it
 * this costs nothing at all, and the plugin cannot tell from in here which kind it is on.
 */
class ConfigPermissionsCheck extends Check
{
    /* Owner reads and writes, group reads, nobody else. */
    const TARGET = 0640;

    public function id()
    {
        return 'config_permissions';
    }

    public function group()
    {
        return 'files';
    }

    public function run()
    {
        $path = $this->configPath();

        /*
         * Nothing to report rather than a pass: a config file we cannot find is not a config
         * file we have checked, and saying otherwise would be the assurance nobody verified.
         */
        if (!$path) {
            return [];
        }

        $perms = $this->permissions($path);

        if ($perms === null) {
            return [];
        }

        /*
         * Silenced on purpose. Unlike the file checks this is dismissed outright rather than
         * accepted-as-it-stands: what is being waved away is the question, not a version of a
         * file - somebody on a machine of their own has decided this does not apply to them,
         * and it will not start applying when the mode changes.
         */
        if ($this->isDismissed($path)) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Configuration file permissions', 'fluent-security'),
                'scored' => false
            ])];
        }

        if (!($perms & 0004)) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Your configuration file is not readable by others', 'fluent-security'),
                'scored' => true
            ])];
        }

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_LOOK,
            'title'    => __('Your database password can be read by others on this server', 'fluent-security'),
            'why'      => __('The file holding it is readable by every account on this machine. On shared hosting that is everyone else on the server; on a machine of your own it may not matter.', 'fluent-security'),
            'details'  => [
                /* translators: 1: a file path, 2: file permissions in octal, for example 644 */
                sprintf(__('%1$s is set to %2$s', 'fluent-security'), $path, $this->octal($perms)),
                /* translators: %s: file permissions in octal */
                sprintf(__('Restricting it sets it to %s, which leaves your own site\'s access untouched', 'fluent-security'), $this->octal(self::TARGET))
            ],
            'action'   => 'fix',
            'label'    => __('Restrict it', 'fluent-security'),
            'dismiss'  => 'ignore',
            'scored'   => false
        ])];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function fix($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
        }

        $path = $this->configPath();

        if (!$path) {
            return new \WP_Error(
                'not_found',
                __('Your configuration file is not where WordPress usually keeps it, so it is not safe to change it from here.', 'fluent-security'),
                ['status' => 422]
            );
        }

        /*
         * chmod only succeeds for the file's owner, and the owner keeps read access under the
         * mode being set - so a change that goes through cannot be one that locks the site out
         * of its own configuration.
         */
        @chmod($path, self::TARGET);

        clearstatcache(true, $path);
        $perms = $this->permissions($path);

        if ($perms !== null && !($perms & 0004)) {
            return [
                'message' => __('Done. Other accounts on this server can no longer read your configuration file.', 'fluent-security')
            ];
        }

        /*
         * Reported from what the file says afterwards, not from what chmod returned. On plenty
         * of hosts the call is accepted and the mode does not move.
         */
        return new \WP_Error(
            'chmod_ignored',
            __('The permissions could not be changed from here — this usually means your host manages them. Ask them to make wp-config.php unreadable by other accounts.', 'fluent-security'),
            ['status' => 422]
        );
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin knows how to check.', 'fluent-security'),
                ['status' => 404]
            );
        }

        $path = $this->configPath();

        if (!$path) {
            return new \WP_Error(
                'not_found',
                __('Your configuration file is not where WordPress usually keeps it.', 'fluent-security'),
                ['status' => 422]
            );
        }

        /*
         * Filed on the ignore list the scan screen already owns, so a site has one place its
         * "yes, I know" lives and one Reset button that clears the lot.
         */
        $lists = IntegrityHelper::getIgnoreLists();
        $relative = AcceptedFiles::toRelative($path);

        if (!in_array($relative, $lists['files'], true)) {
            $lists['files'][] = $relative;
            IntegrityHelper::updateIgnoreLists($lists);
        }

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $path
     * @return bool
     */
    protected function isDismissed($path)
    {
        return in_array(
            AcceptedFiles::toRelative($path),
            Arr::get(IntegrityHelper::getIgnoreLists(), 'files', []),
            true
        );
    }

    /**
     * WordPress looks in the install directory, then one above it - but only if the directory
     * above does not hold another WordPress. Same rule here, so this cannot pick up a
     * neighbouring site's configuration.
     *
     * @return string
     */
    protected function configPath()
    {
        if (file_exists(ABSPATH . 'wp-config.php')) {
            return ABSPATH . 'wp-config.php';
        }

        $parent = dirname(ABSPATH) . '/wp-config.php';

        if (file_exists($parent) && !file_exists(dirname(ABSPATH) . '/wp-settings.php')) {
            return $parent;
        }

        return '';
    }

    /**
     * @param string $path
     * @return int|null
     */
    protected function permissions($path)
    {
        $perms = @fileperms($path);

        if ($perms === false) {
            return null;
        }

        return $perms & 0777;
    }

    /**
     * @param int $perms
     * @return string
     */
    protected function octal($perms)
    {
        return substr(sprintf('%o', $perms), -3);
    }
}
