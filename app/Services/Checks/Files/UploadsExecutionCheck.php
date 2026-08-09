<?php

namespace FluentAuth\App\Services\Checks\Files;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Whether code can be made to run from the uploads folder.
 *
 * Every route into a WordPress site that ends in a shell ends here: something accepts a file,
 * the file lands in uploads, and the attacker asks the web server for it. Blocking execution
 * in a folder meant for pictures costs a site nothing and closes that ending.
 *
 * The check asks the web server rather than reading .htaccess, and that is the whole design.
 * Reading the file tells you what somebody wrote, not what the server does with it: on nginx
 * it tells you nothing at all, on a managed host the rule may be overridden, and a rule that
 * is present and ignored reports as fixed. So a file is written, fetched over HTTP, and the
 * answer is whatever comes back. That is also what lets the screen say the sentence worth
 * saying - not "a rule is in place" but "we tested it, and code will not run there".
 *
 * There are three answers, not two. A probe that cannot complete - loopback requests
 * disabled, HTTP auth on a staging site, a firewall in the way - must say so. Reporting a
 * failed test as either verdict is worse than not testing: one is a false alarm, the other is
 * an assurance nobody checked.
 */
class UploadsExecutionCheck extends Check
{
    const CACHE_KEY = '__fls_uploads_probe';

    const BLOCKED = 'blocked';

    const EXECUTES = 'executes';

    const UNKNOWN = 'unknown';

    public function id()
    {
        return 'uploads_execution';
    }

    public function group()
    {
        return 'files';
    }

    /*
     * One HTTP request to the site's own front end. Cached, so a page load pays for it once
     * a day rather than every time somebody opens the screen.
     */
    public function cost()
    {
        return self::COST_PROBE;
    }

    public function run()
    {
        $result = $this->cachedProbe();
        $state = Arr::get($result, 'state');

        if ($state === self::BLOCKED) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Code cannot run from your uploads folder', 'fluent-security'),
                'scored' => true
            ])];
        }

        if ($state === self::UNKNOWN) {
            /*
             * Not scored. A site we could not reach is not a site with a problem, and marking
             * it down for our own inability to test it is how a score stops meaning anything.
             */
            return [new Finding([
                'id'       => $this->id(),
                'check'    => $this->id(),
                'group'    => $this->group(),
                'state'    => Finding::STATE_OPEN,
                'severity' => Finding::SEVERITY_LOOK,
                'title'    => __('We could not test your uploads folder', 'fluent-security'),
                'why'      => __('Your site would not answer a request from itself, so we cannot tell you whether code can run in the folder your uploads go to. This is usually a hosting setting rather than a problem with your site.', 'fluent-security'),
                'details'  => $this->probeDetails($result),
                'action'   => 'fix',
                'label'    => __('Try again', 'fluent-security'),
                'scored'   => false
            ])];
        }

        $canWrite = $this->canWriteRules();

        return [new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => __('Someone could run their own code from your uploads folder', 'fluent-security'),
            'why'      => $canWrite
                ? __('If anything on your site accepts a file, a file slipped through it would run. We tested this folder and it is not blocked. Blocking it does not affect your images or documents.', 'fluent-security')
                : __('If anything on your site accepts a file, a file slipped through it would run. We tested this folder and it is not blocked. Your web server is not one we can write the rule for, so your host will need to add it.', 'fluent-security'),
            'details'  => $canWrite ? $this->probeDetails($result) : $this->snippetDetails($result),
            'action'   => $canWrite ? 'fix' : 'none',
            'label'    => __('Block it', 'fluent-security'),
            'scored'   => true
        ])];
    }

    /**
     * Write the rule, then test it again and report what the server actually does now.
     *
     * The re-test is the point. chmod, .htaccess and every other change of this kind can be
     * accepted by the filesystem and ignored by the server, and a check that reported success
     * from the write alone would be telling the reader something nobody verified.
     *
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

        delete_transient(self::CACHE_KEY);

        /* "Try again" on an untestable site is a re-probe and nothing else. */
        $before = $this->probeState();

        if ($before !== self::EXECUTES) {
            return [
                'message' => $before === self::BLOCKED
                    ? __('Tested again: code cannot run in your uploads folder.', 'fluent-security')
                    : __('Your site still would not answer a request from itself, so we cannot test this.', 'fluent-security')
            ];
        }

        if (!$this->canWriteRules()) {
            return new \WP_Error(
                'not_writable',
                __('Your web server does not use the file this rule goes in, so your host will need to add it.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $written = $this->writeRules();

        if (is_wp_error($written)) {
            return $written;
        }

        delete_transient(self::CACHE_KEY);
        $state = $this->probeState();

        if ($state === self::BLOCKED) {
            return ['message' => __('Done. We tested it: code can no longer run in your uploads folder.', 'fluent-security')];
        }

        if ($state === self::UNKNOWN) {
            return ['message' => __('The rule was added, but your site would not answer a request from itself, so we could not confirm it works.', 'fluent-security')];
        }

        return new \WP_Error(
            'rule_ignored',
            __('The rule was added but your web server is ignoring it. Your host will need to block PHP in the uploads folder for you.', 'fluent-security'),
            ['status' => 422]
        );
    }

    /**
     * @return array
     */
    protected function cachedProbe()
    {
        $cached = get_transient(self::CACHE_KEY);

        if (is_array($cached)) {
            return $cached;
        }

        $result = $this->probe();

        /*
         * A definite answer keeps for a day. One we could not get keeps for an hour - long
         * enough that a site whose loopback requests are blocked outright is not paying the
         * timeout on a page load every few minutes, short enough that a site which was merely
         * busy gets a real answer soon after. Retrying sooner than this is what the button on
         * the finding is for.
         */
        $ttl = $result['state'] === self::UNKNOWN ? HOUR_IN_SECONDS : DAY_IN_SECONDS;

        set_transient(self::CACHE_KEY, $result, apply_filters('fluent_auth/uploads_probe_ttl', $ttl, $result));

        return $result;
    }

    /**
     * @return string
     */
    protected function probeState()
    {
        $result = $this->cachedProbe();

        return Arr::get($result, 'state', self::UNKNOWN);
    }

    /**
     * Put a file in uploads, ask the web server for it, and see what comes back.
     *
     * @return array
     */
    protected function probe()
    {
        $uploads = wp_upload_dir();

        if (!empty($uploads['error']) || empty($uploads['basedir'])) {
            return ['state' => self::UNKNOWN, 'reason' => 'no_uploads_dir'];
        }

        $name = 'fluentauth-check-' . wp_generate_password(8, false) . '.php';
        $path = trailingslashit($uploads['basedir']) . $name;
        $url = trailingslashit($uploads['baseurl']) . $name;

        /*
         * Two markers rather than one, so the two outcomes are told apart by what is present
         * rather than by what is missing. Served as source, the body carries the opening tag;
         * executed, it carries only the word.
         */
        $written = @file_put_contents($path, '<' . '?php echo "FLS-EXECUTED"; // FLS-SOURCE');

        if ($written === false) {
            return ['state' => self::UNKNOWN, 'reason' => 'not_writable'];
        }

        /*
         * Five seconds, not thirty. This runs behind a page load, and a site that cannot
         * answer itself quickly is a site we are going to report as untested either way -
         * waiting longer only makes the screen slower to say so.
         */
        $response = wp_remote_get($url, [
            'timeout'   => 5,
            'sslverify' => apply_filters('fluent_auth/uploads_probe_sslverify', true),
            'headers'   => ['Cache-Control' => 'no-cache']
        ]);

        @unlink($path);

        if (is_wp_error($response)) {
            return ['state' => self::UNKNOWN, 'reason' => 'request_failed', 'note' => $response->get_error_message()];
        }

        $code = (int)wp_remote_retrieve_response_code($response);
        $body = (string)wp_remote_retrieve_body($response);

        /* Refused outright, which is what most rules of this kind do. */
        if ($code === 403 || $code === 401) {
            return ['state' => self::BLOCKED, 'reason' => 'refused', 'code' => $code];
        }

        if ($code !== 200) {
            return ['state' => self::UNKNOWN, 'reason' => 'unexpected_status', 'code' => $code];
        }

        /* Handed over as text, so nothing ran. */
        if (strpos($body, 'FLS-SOURCE') !== false) {
            return ['state' => self::BLOCKED, 'reason' => 'served_as_text', 'code' => $code];
        }

        if (strpos($body, 'FLS-EXECUTED') !== false) {
            return ['state' => self::EXECUTES, 'reason' => 'executed', 'code' => $code];
        }

        return ['state' => self::UNKNOWN, 'reason' => 'unrecognised_response', 'code' => $code];
    }

    /**
     * Whether this server reads the file the rule goes in.
     *
     * @return bool
     */
    protected function canWriteRules()
    {
        $software = isset($_SERVER['SERVER_SOFTWARE'])
            ? strtolower(sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])))
            : '';

        $usesHtaccess = strpos($software, 'apache') !== false || strpos($software, 'litespeed') !== false;

        if (!$usesHtaccess) {
            return false;
        }

        $uploads = wp_upload_dir();

        if (!empty($uploads['error']) || empty($uploads['basedir'])) {
            return false;
        }

        $file = trailingslashit($uploads['basedir']) . '.htaccess';

        return file_exists($file) ? is_writable($file) : is_writable($uploads['basedir']);
    }

    /**
     * @return true|\WP_Error
     */
    protected function writeRules()
    {
        require_once ABSPATH . 'wp-admin/includes/misc.php';

        $uploads = wp_upload_dir();
        $file = trailingslashit($uploads['basedir']) . '.htaccess';

        /*
         * Written between markers with insert_with_markers(), which is the mechanism WordPress
         * uses for its own permalink rules - so this adds to whatever is already in the file
         * and can be taken out again without disturbing anybody else's lines.
         */
        $inserted = insert_with_markers($file, 'FluentAuth', $this->rules());

        if (!$inserted) {
            return new \WP_Error(
                'write_failed',
                __('The rule could not be written. Your host will need to block PHP in the uploads folder for you.', 'fluent-security'),
                ['status' => 422]
            );
        }

        return true;
    }

    /**
     * @return array
     */
    protected function rules()
    {
        return [
            '<FilesMatch "\.(?i:php|php[0-9]|phtml|phps|phar)$">',
            '  <IfModule mod_authz_core.c>',
            '    Require all denied',
            '  </IfModule>',
            '  <IfModule !mod_authz_core.c>',
            '    Order allow,deny',
            '    Deny from all',
            '  </IfModule>',
            '</FilesMatch>'
        ];
    }

    /**
     * @param array $result
     * @return array
     */
    protected function probeDetails($result)
    {
        $uploads = wp_upload_dir();

        $details = [
            /* translators: %s: a folder path */
            sprintf(__('Folder: %s', 'fluent-security'), Arr::get($uploads, 'basedir', '')),
            /* translators: %s: the result of the test */
            sprintf(__('Tested by requesting a PHP file over HTTP — result: %s', 'fluent-security'), Arr::get($result, 'reason', ''))
        ];

        $note = Arr::get($result, 'note');

        if ($note) {
            $details[] = $note;
        }

        return $details;
    }

    /**
     * The rule to hand over, for a server we cannot write to.
     *
     * @param array $result
     * @return array
     */
    protected function snippetDetails($result)
    {
        $uploads = wp_upload_dir();

        return array_merge($this->probeDetails($result), [
            __('Ask your host to add this to your nginx configuration:', 'fluent-security'),
            'location ~* /' . trim(str_replace(ABSPATH, '', Arr::get($uploads, 'basedir', '')), '/') . '/.*\.(php|phtml|phar)$ { deny all; }'
        ]);
    }
}
