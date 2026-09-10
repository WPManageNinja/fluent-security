<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\BasicTasksHandler;

/**
 * The switches on the Core Security screen, checked against what they actually do
 * rather than what they say.
 */
class BasicTasksHandlerTest extends BaseTestCase
{
    private $handler;

    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_auth_logs");
        delete_option('_fls_last_digest_sent');

        $this->handler = new BasicTasksHandler();
    }

    public function tearDown(): void
    {
        delete_option('_fls_last_digest_sent');
        parent::tearDown();
    }

    private function saveSettings(array $overrides)
    {
        $settings = array_merge(Helper::getAuthSettings(), $overrides);
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    /*
     * XML-RPC
     */

    public function testPingbackMethodsAreRemovedWhenXmlRpcIsDisabled()
    {
        $this->saveSettings(['disable_xmlrpc' => 'yes']);

        $methods = $this->handler->maybeRemovePingbackMethods([
            'pingback.ping'                     => 'this:pingback_ping',
            'pingback.extensions.getPingbacks'  => 'this:pingback_extensions_getPingbacks',
            'wp.getPosts'                       => 'this:wp_getPosts',
            'jetpack.testConnection'            => 'jetpack',
        ]);

        $this->assertArrayNotHasKey('pingback.ping', $methods);
        $this->assertArrayNotHasKey('pingback.extensions.getPingbacks', $methods);
        // Everything that is not a pingback is somebody else's business.
        $this->assertArrayHasKey('wp.getPosts', $methods);
        $this->assertArrayHasKey('jetpack.testConnection', $methods);

        $headers = $this->handler->maybeRemovePingbackHeader(['X-Pingback' => 'x', 'X-Other' => 'y']);
        $this->assertSame(['X-Other' => 'y'], $headers);
    }

    public function testPingbackMethodsAreLeftAloneWhenXmlRpcIsEnabled()
    {
        $this->saveSettings(['disable_xmlrpc' => 'no']);

        $methods = ['pingback.ping' => 'this:pingback_ping', 'wp.getPosts' => 'x'];

        $this->assertSame($methods, $this->handler->maybeRemovePingbackMethods($methods));
        $this->assertSame(['X-Pingback' => 'x'], $this->handler->maybeRemovePingbackHeader(['X-Pingback' => 'x']));
    }

    /*
     * Users REST
     */

    public function testHiddenUserLookupIsRefusedWithAnAuthStatusRatherThanA500()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        $author = $this->factory->user->create(['role' => 'author']);

        // With a published post core itself would show this author to anyone.
        $this->factory->post->create(['post_author' => $author, 'post_status' => 'publish']);

        wp_set_current_user(0);
        $response = rest_do_request(new \WP_REST_Request('GET', '/wp/v2/users/' . $author));
        $this->assertSame(401, $response->get_status());
        $this->assertSame('permission_error', $response->get_data()['code']);

        wp_set_current_user($this->factory->user->create(['role' => 'subscriber']));
        $response = rest_do_request(new \WP_REST_Request('GET', '/wp/v2/users/' . $author));
        $this->assertSame(403, $response->get_status());

        // Whoever may edit other people's posts may still see who wrote them.
        wp_set_current_user($this->factory->user->create(['role' => 'editor']));
        $response = rest_do_request(new \WP_REST_Request('GET', '/wp/v2/users/' . $author));
        $this->assertSame(200, $response->get_status());
    }

    public function testEveryoneMayStillReadTheirOwnRecord()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        $author = $this->factory->user->create(['role' => 'author']);
        $other = $this->factory->user->create(['role' => 'author']);
        wp_set_current_user($author);

        // What the block editor preloads on every load.
        $request = new \WP_REST_Request('GET', '/wp/v2/users/me');
        $request->set_param('context', 'edit');
        $this->assertSame(200, rest_do_request($request)->get_status());

        $this->assertSame(200, rest_do_request(new \WP_REST_Request('GET', '/wp/v2/users/' . $author))->get_status());
        $this->assertSame(403, rest_do_request(new \WP_REST_Request('GET', '/wp/v2/users/' . $other))->get_status());
    }

    public function testHiddenUserListIsEmptyForAnonymousRequests()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        $this->factory->user->create(['role' => 'author']);

        wp_set_current_user(0);
        $response = rest_do_request(new \WP_REST_Request('GET', '/wp/v2/users'));

        $this->assertSame(200, $response->get_status());
        $this->assertSame([], $response->get_data());
    }

    /*
     * The other places usernames leak from
     */

    private function captureRedirect($callback)
    {
        $captured = null;

        $catch = function ($location) use (&$captured) {
            $captured = $location;
            throw new \RuntimeException('redirected');
        };

        add_filter('wp_redirect', $catch);

        try {
            $callback();
        } catch (\RuntimeException $e) {
            // Expected: this is how the exit() below the redirect is escaped.
        } finally {
            remove_filter('wp_redirect', $catch);
        }

        return $captured;
    }

    public function testAnAuthorIdLookupIsSentHomeInsteadOfToTheAuthorSlug()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        $this->set_permalink_structure('/%postname%/');
        wp_set_current_user(0);
        $_GET['author'] = '1';

        try {
            $sentTo = $this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            });
        } finally {
            unset($_GET['author']);
            $this->set_permalink_structure('');
        }

        $this->assertSame(home_url('/'), $sentTo);
    }

    public function testAnAuthorIdWithATrailingNewlineIsBlockedLikeCoreWouldFollowIt()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        $this->set_permalink_structure('/%postname%/');
        wp_set_current_user(0);

        // redirect_canonical() matches "1\n" with ^[0-9]+$ and WP_Query reads it as 1.
        $_GET['author'] = "1\n";

        try {
            $sentTo = $this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            });
        } finally {
            unset($_GET['author']);
            $this->set_permalink_structure('');
        }

        $this->assertSame(home_url('/'), $sentTo);
    }

    public function testAuthorIdLookupsAreLeftAloneWherePlainPermalinksNeedThem()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        $this->set_permalink_structure('');
        wp_set_current_user(0);
        $_GET['author'] = '1';

        try {
            $sentTo = $this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            });
        } finally {
            unset($_GET['author']);
        }

        $this->assertNull($sentTo);
    }

    public function testAuthorIdLookupsAreLeftAloneWhenTheSwitchIsOffOrForStaff()
    {
        $this->set_permalink_structure('/%postname%/');
        $_GET['author'] = '1';

        try {
            $this->saveSettings(['disable_users_rest' => 'no']);
            wp_set_current_user(0);
            $this->assertNull($this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            }));

            $this->saveSettings(['disable_users_rest' => 'yes']);
            wp_set_current_user($this->factory->user->create(['role' => 'administrator']));
            $this->assertNull($this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            }));

            // An editor cannot list users but edits other people's posts: same answer.
            wp_set_current_user($this->factory->user->create(['role' => 'editor']));
            $this->assertNull($this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            }));

            // An author has neither.
            wp_set_current_user($this->factory->user->create(['role' => 'author']));
            $this->assertSame(home_url('/'), $this->captureRedirect(function () {
                $this->handler->maybeBlockAuthorIdLookup();
            }));
        } finally {
            unset($_GET['author']);
            $this->set_permalink_structure('');
        }
    }

    public function testTheUserSitemapUrlIsNotFoundRatherThanTheHomePage()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        wp_set_current_user(0);

        global $wp_query;
        $wp_query->set('sitemap', 'users');

        try {
            $this->handler->maybeNotFoundUserSitemap();
            $this->assertTrue($wp_query->is_404());

            // Any other sitemap is none of our business.
            $wp_query->init();
            $wp_query->set('sitemap', 'posts');
            $this->handler->maybeNotFoundUserSitemap();
            $this->assertFalse($wp_query->is_404());
        } finally {
            $wp_query->init();
        }
    }

    public function testTheUserSitemapIsHiddenWithTheSameSwitch()
    {
        $this->saveSettings(['disable_users_rest' => 'yes']);
        wp_set_current_user(0);

        $provider = new \WP_Sitemaps_Users();
        $this->assertFalse($this->handler->maybeHideUserSitemap($provider, 'users'));
        $this->assertSame($provider, $this->handler->maybeHideUserSitemap($provider, 'posts'));

        $this->saveSettings(['disable_users_rest' => 'no']);
        $this->assertSame($provider, $this->handler->maybeHideUserSitemap($provider, 'users'));
    }

    /*
     * Digest email
     */

    private function logSuccessfulLoginNow()
    {
        global $wpdb;
        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'someone',
            'user_id'    => 1,
            'ip'         => '10.0.0.1',
            'status'     => 'success',
            'media'      => 'web',
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql'),
        ]);
    }

    /**
     * Runs the digest with wp_mail() short-circuited, returning what it tried to send.
     */
    private function runDigest()
    {
        $sent = null;

        $spy = function ($return, $atts) use (&$sent) {
            $sent = $atts;
            return true;
        };

        add_filter('pre_wp_mail', $spy, 10, 2);
        $this->handler->maybeSendDigestEMail();
        remove_filter('pre_wp_mail', $spy, 10);

        return $sent;
    }

    private function todayKey()
    {
        return strtolower(date('D', current_time('timestamp')));
    }

    private function anotherDayKey()
    {
        $days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
        $others = array_values(array_diff($days, [$this->todayKey()]));

        return $others[0];
    }

    public function testWeekdayDigestSendsOnItsDay()
    {
        $this->saveSettings(['digest_summary' => $this->todayKey(), 'notification_email' => 'owner@example.com']);
        $this->logSuccessfulLoginNow();

        $sent = $this->runDigest();

        $this->assertNotNull($sent, 'The digest chosen for today should go out today');
        $this->assertSame('owner@example.com', $sent['to']);
        $this->assertStringContainsString('Weekly', $sent['subject']);
        $this->assertNotEmpty(get_option('_fls_last_digest_sent'));
    }

    public function testWeekdayDigestWaitsForItsDay()
    {
        $this->saveSettings(['digest_summary' => $this->anotherDayKey(), 'notification_email' => 'owner@example.com']);
        $this->logSuccessfulLoginNow();

        $this->assertNull($this->runDigest());
        $this->assertEmpty(get_option('_fls_last_digest_sent'));
    }

    public function testDailyDigestSendsAndIsNotRepeatedWithinItsWindow()
    {
        $this->saveSettings(['digest_summary' => 'daily', 'notification_email' => '{admin_email}']);
        $this->logSuccessfulLoginNow();

        $first = $this->runDigest();
        $this->assertNotNull($first);
        $this->assertSame(get_option('admin_email'), $first['to']);
        $this->assertStringContainsString('Daily', $first['subject']);

        $this->assertNull($this->runDigest(), 'Already sent for this window');
    }

    public function testDigestIsNotSentWhenThereIsNothingToReport()
    {
        $this->saveSettings(['digest_summary' => 'daily', 'notification_email' => 'owner@example.com']);

        $this->assertNull($this->runDigest());
    }

    public function testUnknownFrequencyNeverSends()
    {
        $this->saveSettings(['digest_summary' => 'fortnightly', 'notification_email' => 'owner@example.com']);
        $this->logSuccessfulLoginNow();

        $this->assertNull($this->runDigest());
    }
}
