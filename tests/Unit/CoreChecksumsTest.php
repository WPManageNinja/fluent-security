<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SecurityScanController;
use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\ChecksumException;

/*
 * The real checker with only its local half stubbed, so getRemoteHashes() and the comparison
 * are both the production ones. The local paths are real core files because getModifiedFiles()
 * calls filemtime() on anything it reports.
 */
class LocalStubChecker extends CheckerService
{
    public static $files = [];

    public function getLocalHashes()
    {
        $this->localHashes = self::$files;
        $this->extraFolders = [];

        return ['files' => $this->localHashes, 'extra_folders' => []];
    }
}

/**
 * Where the core scan gets something to compare against.
 *
 * The whole scan rests on one request to api.wordpress.org, and core's own helper fails it in
 * two ways that look nothing like a broken site: it asks for the site's locale and takes
 * {"checksums":false} - the answer for a translated package that has not been built yet - as
 * a hard no, and it allows three seconds for a 300KB download outside cron. Between them they
 * took core scanning away from whole locales for the week after every point release, and
 * permanently from the ones wordpress.org never builds.
 *
 * The fallback that fixes it is only safe because of the pruning, so the two are pinned
 * together here: en_US stands in for a missing locale, and the single file that differs
 * between the two packages goes out with wp-content. Get the second half wrong and every
 * translated site is told its core is modified, which is a worse failure than the one the
 * fallback is for.
 */
class CoreChecksumsTest extends BaseTestCase
{
    /** @var array each request the code made, in order */
    private $requests = [];

    private $handler = null;

    private $localeFilter = null;

    public function setUp(): void
    {
        parent::setUp();

        $this->requests = [];
        $this->forgetCache();
    }

    public function tearDown(): void
    {
        if ($this->handler) {
            remove_filter('pre_http_request', $this->handler);
            $this->handler = null;
        }

        if ($this->localeFilter) {
            remove_filter('locale', $this->localeFilter, 99);
            $this->localeFilter = null;
        }

        $this->forgetCache();

        parent::tearDown();
    }

    private function forgetCache()
    {
        global $wp_version;

        foreach (['7.1.1', '7.2-alpha-60000', $wp_version] as $version) {
            foreach (['fr_FR', 'en_US', 'he_IL'] as $locale) {
                delete_transient('fls_core_checksums_' . md5($version . '|' . $locale));
            }
        }
    }

    /*
     * Answer the checksum API from a map of locale => checksums. A locale that is not in the
     * map gets wordpress.org's real answer for a package it has not built: 200, with
     * `checksums` set to false.
     */
    private function serve(array $byLocale, $transportError = null)
    {
        $this->handler = function ($pre, $args, $url) use ($byLocale, $transportError) {
            if (strpos($url, 'api.wordpress.org/core/checksums') === false) {
                return $pre;
            }

            parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

            $this->requests[] = [
                'locale'  => isset($query['locale']) ? $query['locale'] : '',
                'version' => isset($query['version']) ? $query['version'] : '',
                'timeout' => isset($args['timeout']) ? $args['timeout'] : null
            ];

            if ($transportError) {
                return new \WP_Error('http_request_failed', $transportError);
            }

            $locale = isset($query['locale']) ? $query['locale'] : '';
            $checksums = isset($byLocale[$locale]) ? $byLocale[$locale] : false;

            return [
                'response' => ['code' => 200, 'message' => 'OK'],
                'body'     => json_encode(['checksums' => $checksums]),
                'headers'  => []
            ];
        };

        add_filter('pre_http_request', $this->handler, 10, 3);
    }

    /*
     * Run the rest of the test as a site in this locale.
     *
     * The comparison tests go through the constructor, which reads get_locale() and the real
     * $wp_version rather than taking arguments - so the locale has to be set on the site, not
     * passed in.
     */
    private function asLocale($locale)
    {
        $this->localeFilter = function () use ($locale) {
            return $locale;
        };

        add_filter('locale', $this->localeFilter, 99);
    }

    /* A package as wordpress.org publishes it: core files, plus the parts we never compare. */
    private function package($localPackage = null)
    {
        return [
            'wp-includes/version.php'                  => $localPackage ? 'localized-hash' : 'en-us-hash',
            'wp-includes/pluggable.php'                => 'aaa',
            'wp-admin/admin.php'                       => 'bbb',
            'wp-login.php'                             => 'ccc',
            'wp-config-sample.php'                     => 'ddd',
            'wp-content/plugins/hello.php'             => 'eee',
            'wp-content/themes/twentytwenty/style.css' => 'fff'
        ];
    }

    /* ------------------------------------------------------------------ the fallback */

    /**
     * A locale wordpress.org has not built falls back to en_US rather than failing.
     *
     * This is the common case, not an exotic one: for weeks after a point release the
     * translated packages trail it, and until this fallback existed every one of those sites
     * got an error instead of a scan.
     */
    public function test_missing_locale_package_falls_back_to_en_us()
    {
        $this->serve(['en_US' => $this->package()]);

        $result = CheckerService::getCoreChecksums('7.1.1', 'fr_FR');

        $this->assertSame(['fr_FR', 'en_US'], wp_list_pluck($this->requests, 'locale'));
        $this->assertSame('aaa', $result['files']['wp-includes/pluggable.php']);
    }

    /**
     * And drops the one file the two packages disagree about.
     *
     * A translated build's version.php declares $wp_local_package, so its hash never matches
     * the en_US one. Comparing it anyway would report a modified core file on every localized
     * site on the fallback path - the scan would be answering, and lying.
     */
    public function test_fallback_exempts_the_file_that_carries_the_local_package()
    {
        $this->serve(['en_US' => $this->package()]);

        $result = CheckerService::getCoreChecksums('7.1.1', 'fr_FR');

        $this->assertArrayNotHasKey('wp-includes/version.php', $result['files']);
        $this->assertSame(['wp-includes/version.php' => true], $result['exempt']);
    }

    /**
     * The site's own locale is still preferred, and keeps version.php.
     *
     * The fallback is a repair, not the normal path: a site whose package exists is compared
     * against its own package, version.php included, so a tampered one is still caught.
     */
    public function test_published_locale_is_used_as_is()
    {
        $this->serve([
            'fr_FR' => $this->package('fr_FR'),
            'en_US' => $this->package()
        ]);

        $result = CheckerService::getCoreChecksums('7.1.1', 'fr_FR');

        $this->assertSame(['fr_FR'], wp_list_pluck($this->requests, 'locale'));
        $this->assertSame('localized-hash', $result['files']['wp-includes/version.php']);
        $this->assertSame([], $result['exempt']);
    }

    /* ------------------------------------------------------------------ the pruning */

    /**
     * wp-content and wp-config-sample.php are never compared, on either path.
     *
     * wp-content is the site's own - plugins, themes and translations all live there and all
     * legitimately differ - and it is scanned separately against its own sources. Left in, a
     * healthy site would report hundreds of modified files and the real ones would be lost in
     * them.
     */
    public function test_wp_content_and_the_sample_config_are_dropped()
    {
        $this->serve(['fr_FR' => $this->package('fr_FR')]);

        $result = CheckerService::getCoreChecksums('7.1.1', 'fr_FR');

        $this->assertArrayNotHasKey('wp-config-sample.php', $result['files']);

        foreach (array_keys($result['files']) as $file) {
            $this->assertStringStartsNotWith('wp-content', $file);
        }
    }

    /* ------------------------------------------------------------------ the comparison */

    /*
     * The four real core paths the stub pretends the site has, so filemtime() has something to
     * read if the comparison decides to report one.
     */
    private function localFiles($versionHash)
    {
        return [
            'wp-includes/version.php'   => $versionHash,
            'wp-includes/pluggable.php' => 'aaa',
            'wp-admin/admin.php'        => 'bbb',
            'wp-login.php'              => 'ccc'
        ];
    }

    /**
     * A translated site scanned through the fallback reports nothing.
     *
     * The regression this whole exemption exists for, and the one the hash-map tests above
     * cannot see. Removing version.php from the remote set is not enough on its own: a local
     * file with no remote hash is an unexpected file, so the first version of the fallback
     * turned a false "modified" into a false "new" and every localized site was told it had a
     * planted file in wp-includes. Asserted on the finished comparison, not on the map.
     */
    public function test_a_localized_site_on_the_fallback_reports_a_clean_core()
    {
        $this->asLocale('fr_FR');
        $this->serve(['en_US' => $this->package()]);
        LocalStubChecker::$files = $this->localFiles('localized-hash');

        $checker = new LocalStubChecker();

        $this->assertSame([], $checker->getModifiedFiles());
    }

    /**
     * But a tampered version.php is still caught when the site's own package exists.
     *
     * The exemption is the price of the fallback and is confined to it. If it leaked to the
     * normal path, the one core file that names the version - a natural thing for someone to
     * edit after planting an older, exploitable copy of core - would stop being checked on
     * every site.
     */
    public function test_a_modified_version_file_is_still_reported_on_the_normal_path()
    {
        $this->asLocale('fr_FR');
        $this->serve(['fr_FR' => $this->package('fr_FR')]);
        LocalStubChecker::$files = $this->localFiles('tampered');

        $checker = new LocalStubChecker();
        $modified = $checker->getModifiedFiles();

        $this->assertArrayHasKey('wp-includes/version.php', $modified);
        $this->assertSame('modified', $modified['wp-includes/version.php']['status']);
    }

    /* ------------------------------------------------------------------ the failures */

    /**
     * Nothing published for the version in any locale is its own reason, named as such.
     *
     * A nightly, an RC before its checksums land, or a build that never came from
     * wordpress.org. Nothing the site owner can fix by retrying, so the message says so
     * instead of suggesting it.
     */
    public function test_unpublished_version_reports_the_version()
    {
        $this->serve([]);

        try {
            CheckerService::getCoreChecksums('7.2-alpha-60000', 'fr_FR');
            $this->fail('Expected a ChecksumException');
        } catch (ChecksumException $e) {
            $this->assertSame(ChecksumException::UNPUBLISHED, $e->getReason());
            $this->assertStringContainsString('7.2-alpha-60000', $e->getMessage());
        }
    }

    /**
     * A blocked or broken outbound request is the other reason, and points at the network.
     */
    public function test_unreachable_api_reports_the_network()
    {
        $this->serve([], 'cURL error 6: Could not resolve host');

        try {
            CheckerService::getCoreChecksums('7.1.1', 'fr_FR');
            $this->fail('Expected a ChecksumException');
        } catch (ChecksumException $e) {
            $this->assertSame(ChecksumException::UNREACHABLE, $e->getReason());
            $this->assertStringContainsString('api.wordpress.org', $e->getMessage());
            $this->assertStringContainsString('Could not resolve host', $e->getDetail());
        }
    }

    /**
     * A transport failure is not retried against en_US.
     *
     * The fallback answers one question - has this locale's package been built - and a
     * connection that failed has not answered it. Retrying doubles the wait on a site whose
     * firewall blocks the host, for an answer that cannot arrive.
     */
    public function test_a_transport_failure_is_not_retried_in_another_locale()
    {
        $this->serve([], 'Connection timed out');

        try {
            CheckerService::getCoreChecksums('7.1.1', 'fr_FR');
        } catch (ChecksumException $e) {
            // expected
        }

        $this->assertCount(1, $this->requests);
    }

    /**
     * Neither message sends anyone to reconnect the alert relay.
     *
     * This scan does not use the relay, and most sites running it have never connected one -
     * so the old advice was both wrong and unfollowable, and it hid a network problem behind a
     * setup problem. Pinned because the sentence is easy to reintroduce from the old copy.
     *
     * @dataProvider failureModes
     */
    public function test_no_failure_blames_the_api_connection($servedLocales, $transportError)
    {
        $this->serve($servedLocales, $transportError);

        try {
            CheckerService::getCoreChecksums('7.1.1', 'fr_FR');
            $this->fail('Expected a ChecksumException');
        } catch (ChecksumException $e) {
            $message = strtolower($e->getMessage());

            $this->assertStringNotContainsString('reconnect', $message);
            $this->assertStringNotContainsString('api key', $message);
            $this->assertStringNotContainsString('api token', $message);
        }
    }

    public function failureModes()
    {
        return [
            'nothing published' => [[], null],
            'host unreachable'  => [[], 'Connection refused']
        ];
    }

    /* ------------------------------------------------------------------ the cache */

    /**
     * The answer is fetched once, not once per caller.
     *
     * Three callers pull the same 300KB otherwise - the Scan button, the daily run and a core
     * reinstall - and the checksums for a released version never change. The key carries the
     * version, so an updated site cannot be compared against the build it used to be.
     */
    public function test_checksums_are_cached_between_calls()
    {
        $this->serve(['fr_FR' => $this->package('fr_FR')]);

        CheckerService::getCoreChecksums('7.1.1', 'fr_FR');
        CheckerService::getCoreChecksums('7.1.1', 'fr_FR');

        $this->assertCount(1, $this->requests);
    }

    /**
     * A failure is not cached.
     *
     * The unpublished case resolves itself when wordpress.org builds the package, and the
     * unreachable one when the network recovers. Caching either would hold the site at the
     * error for hours after the cause had gone.
     */
    public function test_a_failure_is_not_cached()
    {
        $this->serve([], 'Connection refused');

        foreach ([1, 2] as $attempt) {
            try {
                CheckerService::getCoreChecksums('7.1.1', 'fr_FR');
            } catch (ChecksumException $e) {
                // expected
            }
        }

        $this->assertCount(2, $this->requests);
    }

    /* ------------------------------------------------------------------ the timeout */

    /**
     * The request gets a workable timeout.
     *
     * Core allows `wp_doing_cron() ? 30 : 3` seconds for a response over 300KB. The daily scan
     * runs under cron and got 30; the Scan button is a REST request and got 3, which is how a
     * slow host ended up with a nightly scan that worked and a button that did not.
     */
    public function test_the_request_is_not_capped_at_three_seconds()
    {
        $this->serve(['fr_FR' => $this->package('fr_FR')]);

        CheckerService::getCoreChecksums('7.1.1', 'fr_FR');

        $this->assertGreaterThanOrEqual(20, $this->requests[0]['timeout']);
    }

    /* ------------------------------------------------------------------ the screen */

    /**
     * The scan endpoint hands the reason straight to the screen.
     *
     * The scan screen prints `message`, so whatever is put there is what the site owner reads.
     * The old handler replaced both reasons with one sentence about reconnecting the API and
     * buried the real cause in `data`, where nothing displays it.
     */
    public function test_the_scan_endpoint_returns_the_real_reason()
    {
        $this->serve([], 'Connection refused');

        $result = SecurityScanController::scanSite(new \WP_REST_Request());

        $this->assertWpErrorWithCode($result, 'checksums_unavailable');
        $this->assertStringContainsString('api.wordpress.org', $result->get_error_message());
        $this->assertStringNotContainsString('reconnect', strtolower($result->get_error_message()));

        $data = $result->get_error_data();
        $this->assertSame(422, $data['status']);
        $this->assertSame(ChecksumException::UNREACHABLE, $data['reason']);
    }
}
