<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;

/**
 * A password reset endpoint that answers differently for real and fake accounts is a
 * free username oracle, which undoes the careful wording on the login form.
 */
class PasswordResetEnumerationTest extends BaseTestCase
{
    private $handler;

    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_auth_logs");

        $formSettings = Helper::getAuthFormsSettings();
        $formSettings['enabled'] = 'yes';
        update_option('__fls_auth_forms_settings', $formSettings);
        Helper::resetStatics();

        $this->handler = new CustomAuthHandler();

        $this->factory->user->create(['user_login' => 'realuser', 'user_email' => 'real@example.test']);
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    private function requestReset($usernameOrEmail)
    {
        $_REQUEST['user_login'] = $usernameOrEmail;
        $_REQUEST['_fls_reset_pass_nonce'] = wp_create_nonce('fluent_auth_reset_pass_nonce');

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);
        add_filter('pre_wp_mail', '__return_true', 1);   // do not actually send

        ob_start();
        try {
            $this->handler->handlePasswordResentAjax();
        } catch (\WPDieException $e) {
            // expected
        }
        $output = ob_get_clean();

        remove_filter('pre_wp_mail', '__return_true', 1);
        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        unset($_REQUEST['user_login'], $_REQUEST['_fls_reset_pass_nonce']);

        return json_decode($output, true);
    }

    public function testAnUnknownUsernameGetsTheSameAnswerAsARealOne()
    {
        $real = $this->requestReset('realuser');
        $fake = $this->requestReset('definitely-not-a-user');

        $this->assertSame($real, $fake, 'The response must not reveal whether the account exists');
    }

    public function testAnUnknownEmailGetsTheSameAnswerAsARealOne()
    {
        $real = $this->requestReset('real@example.test');
        $fake = $this->requestReset('nobody@example.test');

        $this->assertSame($real, $fake);
    }

    /**
     * The old early return also skipped `lostpassword_errors`, which is where the
     * attempt limit hooks in - so probing for accounts was never counted.
     */
    public function testProbingForUnknownAccountsIsRateLimited()
    {
        $this->requestReset('definitely-not-a-user');

        global $wpdb;
        $logged = (int)$wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = 'password_reset'"
        );

        $this->assertSame(1, $logged);
    }

    /**
     * Unknown accounts write a row with no user_id. The column has to be omitted, not
     * set to '' or null - the query builder sends both as an empty string, which a
     * BIGINT column rejects outright under MySQL strict mode.
     */
    public function testLoggingAnUnknownAccountSurvivesStrictMode()
    {
        global $wpdb;

        $previousMode = $wpdb->get_var('SELECT @@SESSION.sql_mode');
        $wpdb->query("SET SESSION sql_mode = 'STRICT_TRANS_TABLES'");

        try {
            $wpdb->last_error = '';
            $this->requestReset('definitely-not-a-user');

            $this->assertSame('', $wpdb->last_error, 'The insert must not be rejected');

            $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = 'password_reset'");
            $this->assertNotNull($row);
            $this->assertNull($row->user_id);
            /*
             * The log shows these beside plugin updates and file quarantines, so the row
             * has to name the event rather than the form it arrived through.
             */
            $this->assertSame('password_reset_request', $row->media);
            $this->assertSame(
                'Password reset requested',
                \FluentAuth\App\Helpers\Helper::getLoginMediaLabel($row->media)
            );
        } finally {
            $wpdb->query($wpdb->prepare('SET SESSION sql_mode = %s', $previousMode));
        }
    }

    /**
     * Being rate limited is a fact about the requester, not the account, so unlike the
     * outcomes above it is safe - and useful - to report.
     */
    public function testTheRateLimitMessageIsStillReported()
    {
        for ($i = 0; $i < 8; $i++) {
            $response = $this->requestReset('realuser');
        }

        $this->assertStringContainsString('too many attempts', strtolower($response['message']));
    }
}
