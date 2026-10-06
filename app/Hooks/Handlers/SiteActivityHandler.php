<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\BrowserDetection;
use FluentAuth\App\Helpers\Helper;

/**
 * Records what was done to the site itself, rather than who signed in to it.
 *
 * A plugin being switched on is the quietest way a site changes what it runs, and until
 * now nothing here noticed. It goes in the same log as the sign-ins on purpose: when an
 * account is taken over, what happened next is the part that matters, and reading it in
 * one place beats matching timestamps across two.
 */
class SiteActivityHandler
{
    /* Written into `status`. The log screen shows every row carrying it as Site activity. */
    const STATUS = 'site_activity';

    /**
     * Plugin file => the version on disk before an update started.
     *
     * Read at the last moment before the files are replaced, because by the time the
     * update reports itself finished the old version is gone and there is nothing left
     * to say what it moved from. Also what tells a real update from one that failed.
     *
     * @var array<string, string>
     */
    private $versionsBeforeUpdate = [];

    public function register()
    {
        /*
         * Both fire only for a deliberate activation: core passes $silent when it cycles a
         * plugin around an update, and a silent call skips these hooks entirely. So an
         * auto-update does not land here pretending somebody clicked something.
         */
        add_action('activated_plugin', [$this, 'recordActivation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'recordDeactivation'], 10, 2);

        /*
         * Updates take two hooks. The first runs while the old files are still in place,
         * which is the only moment the version being replaced can be read. The second is
         * the only signal that the upgrader has finished - but it fires whether or not the
         * install worked, so what actually confirms an update is the version on disk
         * having moved between the two.
         */
        add_filter('upgrader_pre_install', [$this, 'rememberVersionBeforeUpdate'], 10, 2);
        add_action('upgrader_process_complete', [$this, 'recordUpdates'], 10, 2);
    }

    /**
     * @param string $plugin  Plugin file, relative to the plugins directory.
     * @param bool   $network Whether it was activated across the network.
     * @return void
     */
    public function recordActivation($plugin, $network = false)
    {
        $this->record('plugin_activated', $network
            /* translators: %s: a plugin name and version */
            ? __('Activated %s across the network.', 'fluent-security')
            /* translators: %s: a plugin name and version */
            : __('Activated %s.', 'fluent-security'), $plugin);
    }

    /**
     * @param string $plugin  Plugin file, relative to the plugins directory.
     * @param bool   $network Whether it was deactivated across the network.
     * @return void
     */
    public function recordDeactivation($plugin, $network = false)
    {
        $this->record('plugin_deactivated', $network
            /* translators: %s: a plugin name and version */
            ? __('Deactivated %s across the network.', 'fluent-security')
            /* translators: %s: a plugin name and version */
            : __('Deactivated %s.', 'fluent-security'), $plugin);
    }

    /**
     * A pass-through filter: it reads, it does not decide. Returning anything but what it
     * was given would cancel the install.
     *
     * @param mixed $response
     * @param array $hookExtra
     * @return mixed
     */
    public function rememberVersionBeforeUpdate($response, $hookExtra = [])
    {
        $plugin = is_array($hookExtra) ? (string)($hookExtra['plugin'] ?? '') : '';

        if ($plugin) {
            $this->versionsBeforeUpdate[$plugin] = $this->readPlugin($plugin)['version'];
        }

        return $response;
    }

    /**
     * @param mixed $upgrader
     * @param array $hookExtra
     * @return void
     */
    public function recordUpdates($upgrader = null, $hookExtra = [])
    {
        if (!is_array($hookExtra)) {
            return;
        }

        /* The same hook carries themes, translations, core, and fresh installs. */
        if (($hookExtra['type'] ?? '') !== 'plugin' || ($hookExtra['action'] ?? '') !== 'update') {
            return;
        }

        /* One plugin updated on its own, or a bulk run reporting all of them at the end. */
        $plugins = !empty($hookExtra['plugins']) ? (array)$hookExtra['plugins'] : [];

        if (!$plugins && !empty($hookExtra['plugin'])) {
            $plugins = [$hookExtra['plugin']];
        }

        foreach ($plugins as $plugin) {
            $this->recordUpdate((string)$plugin);
        }
    }

    private function recordUpdate($plugin)
    {
        /*
         * Nothing was read on the way in, so nothing can be said about what changed. The
         * update path always passes through the filter above, so this means it never
         * started - a download that failed, say.
         */
        if (!isset($this->versionsBeforeUpdate[$plugin])) {
            return;
        }

        $before = $this->versionsBeforeUpdate[$plugin];
        unset($this->versionsBeforeUpdate[$plugin]);

        $after = $this->readPlugin($plugin);

        /*
         * The completion hook fires on a failed install too, and an automatic update rolls
         * the old files back before it. Either way the version has not moved, and a log
         * saying a site updated when it did not is worse than no log at all.
         */
        if (!$after['version'] || $after['version'] === $before) {
            return;
        }

        if ($before) {
            $description = sprintf(
                /* translators: 1: plugin name, 2: the version it was on, 3: the version it is on now */
                __('Updated %1$s from %2$s to %3$s.', 'fluent-security'),
                $after['name'],
                $before,
                $after['version']
            );
        } else {
            $description = sprintf(
                /* translators: 1: plugin name, 2: the version it is on now */
                __('Updated %1$s to %2$s.', 'fluent-security'),
                $after['name'],
                $after['version']
            );
        }

        $this->write('plugin_updated', $description);
    }

    private function record($event, $format, $plugin)
    {
        $name = $this->describePlugin($plugin);

        if (!$name) {
            return;
        }

        $this->write($event, sprintf($format, $name));
    }

    /**
     * The plugin's own name and version where they can be read, and the file otherwise -
     * a plugin being deleted is deactivated on the way out, by which point its header is
     * already gone, and "Deactivated hello-dolly/hello.php" still names what happened.
     *
     * @param string $plugin
     * @return string
     */
    private function describePlugin($plugin)
    {
        $plugin = (string)$plugin;

        if (!$plugin) {
            return '';
        }

        $data = $this->readPlugin($plugin);

        return $data['version'] ? $data['name'] . ' ' . $data['version'] : $data['name'];
    }

    /**
     * Straight off the plugin's header, never the cache - the cache is cleared and rebuilt
     * around an update, and this is called on both sides of one.
     *
     * @param string $plugin
     * @return array{name: string, version: string}
     */
    private function readPlugin($plugin)
    {
        $plugin = (string)$plugin;
        $fallback = ['name' => $plugin, 'version' => ''];

        if (!$plugin) {
            return $fallback;
        }

        if (!function_exists('get_plugin_data')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $file = WP_PLUGIN_DIR . '/' . $plugin;

        if (!@is_readable($file)) {
            return $fallback;
        }

        $data = get_plugin_data($file, false, false);
        $name = trim((string)($data['Name'] ?? ''));

        return [
            'name'    => $name ?: $plugin,
            'version' => trim((string)($data['Version'] ?? ''))
        ];
    }

    /**
     * @param string $event
     * @param string $description
     * @return void
     */
    private function write($event, $description)
    {
        $user = wp_get_current_user();
        $agent = $this->getUserAgent();

        $data = [
            'username'    => ($user && $user->ID) ? $user->user_login : '',
            'ip'          => Helper::getIp(),
            'status'      => self::STATUS,
            'media'       => $event,
            /* TINYTEXT, and a plugin with a very long name should not cost the whole row. */
            'description' => mb_substr($description, 0, 250),
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql')
        ];

        /*
         * Left out entirely rather than set empty when nobody is signed in - WP-CLI and
         * cron both get here - because the column is a BIGINT that rejects '' outright
         * under MySQL strict mode.
         */
        if ($user && $user->ID) {
            $data['user_id'] = $user->ID;
        }

        /*
         * Unlike the recovery screen's entries, these usually come from an ordinary
         * browser request, so the row can say which one. The raw agent is kept whatever
         * it is - "WP CLI 2.12.0" on an update run from the command line is worth having -
         * but the detected browser and OS are only worth a column when something was
         * actually recognised. Storing the detector's "unknown" puts the word
         * "unknown / unknown" in the table where a dash reads better.
         */
        if ($agent) {
            $detection = new BrowserDetection();

            $data['agent'] = $agent;
            $data['browser'] = $this->known($detection->getBrowser($agent)['browser_name']);
            $data['device_os'] = $this->known($detection->getOS($agent)['os_family']);
        }

        flsDb()->table('fls_auth_logs')->insert($data);
    }

    /**
     * What the detector returns when it recognised nothing, turned back into nothing.
     *
     * @param string $value
     * @return string
     */
    private function known($value)
    {
        $value = trim((string)$value);

        return strtolower($value) === 'unknown' ? '' : $value;
    }

    private function getUserAgent()
    {
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            return '';
        }

        return sanitize_text_field(substr(wp_unslash($_SERVER['HTTP_USER_AGENT']), 0, 190));
    }
}
