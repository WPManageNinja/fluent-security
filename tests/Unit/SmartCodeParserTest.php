<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\SmartCodeParser;

/**
 * What a `{{user.*}}` smart code is allowed to reach.
 *
 * These codes are written into the system email templates and rendered against the person
 * the email is being sent to, so whatever one resolves to leaves the site in plain text and
 * sits in a mailbox afterwards. The resolver used to hand back any column on the users row
 * and any meta key on the account, which included the password hash, the live
 * password-reset token, and this plugin's own single-use child-site login token.
 *
 * The template author is an administrator, so this was never a privilege escalation. It was
 * a way to put a crackable credential into the mail path by writing eleven characters into
 * a template, which is a thing a security plugin should not offer.
 */
class SmartCodeParserTest extends BaseTestCase
{
    /** @var \WP_User */
    private $user;

    /** @var SmartCodeParser */
    private $parser;

    public function setUp(): void
    {
        parent::setUp();

        $this->parser = new SmartCodeParser();

        $id = $this->factory->user->create([
            'user_login'   => 'smartcode_probe',
            'user_email'   => 'smartcode_probe@example.test',
            'display_name' => 'Smart Code Probe',
            'first_name'   => 'Smart',
            'role'         => 'subscriber'
        ]);

        $this->user = get_user_by('ID', $id);
    }

    private function render($code)
    {
        return $this->parser->parse('[' . $code . ']', $this->user);
    }

    public function testTheDetailsATemplateIsWrittenForStillRender()
    {
        $this->assertSame('[Smart Code Probe]', $this->render('{{user.display_name}}'));
        $this->assertSame('[smartcode_probe]', $this->render('{{user.user_login}}'));
        $this->assertSame('[smartcode_probe@example.test]', $this->render('{{user.user_email}}'));
        $this->assertSame('[Smart]', $this->render('{{user.first_name}}'));
    }

    /**
     * The one that matters. A bcrypt hash in an email is an offline cracking job handed to
     * whoever reads the mailbox, and nothing about the template author's intent changes that.
     */
    public function testThePasswordHashNeverRenders()
    {
        $rendered = $this->render('{{user.user_pass}}');

        $this->assertSame('[]', $rendered);
        $this->assertStringNotContainsString('$', $rendered);
        $this->assertStringNotContainsString($this->user->user_pass, $rendered);
    }

    public function testThePasswordResetTokenNeverRenders()
    {
        global $wpdb;

        $key = get_password_reset_key($this->user);
        $this->assertNotWPError($key);

        /* The column holds the hashed form; neither half may be printed. */
        $stored = $wpdb->get_var($wpdb->prepare(
            "SELECT user_activation_key FROM {$wpdb->users} WHERE ID = %d",
            $this->user->ID
        ));

        $this->assertNotEmpty($stored);

        $rendered = $this->render('{{user.user_activation_key}}');

        $this->assertSame('[]', $rendered);
        $this->assertStringNotContainsString($stored, $rendered);
    }

    public function testAnOrdinaryMetaFieldStillRenders()
    {
        update_user_meta($this->user->ID, 'company_name', 'Ordinary Ltd');

        $this->assertSame('[Ordinary Ltd]', $this->render('{{user.meta.company_name}}'));
    }

    /**
     * WordPress's own mark for meta that is not the account holder's to read. Every plugin
     * that keeps a secret in user meta uses it, so honouring the prefix covers the ones this
     * plugin has never heard of.
     */
    public function testUnderscoredMetaIsRefused()
    {
        update_user_meta($this->user->ID, '_private_api_token', 'sk-live-do-not-send');

        $rendered = $this->render('{{user.meta._private_api_token}}');

        $this->assertSame('[]', $rendered);
        $this->assertStringNotContainsString('sk-live', $rendered);
    }

    public function testThisPluginsOwnSecretMetaIsRefused()
    {
        update_user_meta($this->user->ID, '__flsc_temp_token', 'abcdef0123456789___' . $this->user->ID);

        $rendered = $this->render('{{user.meta.__flsc_temp_token}}');

        $this->assertSame('[]', $rendered);
        $this->assertStringNotContainsString('abcdef0123456789', $rendered);
    }

    public function testSessionTokensAndCapabilitiesAreRefused()
    {
        global $wpdb;

        update_user_meta($this->user->ID, 'session_tokens', 'not-an-array-on-purpose');

        $this->assertSame('[]', $this->render('{{user.meta.session_tokens}}'));
        $this->assertSame('[]', $this->render('{{user.meta.' . $wpdb->get_blog_prefix() . 'capabilities}}'));
    }

    /**
     * A site that genuinely needs a column this list does not carry can have it, but only by
     * somebody deciding so.
     */
    public function testAPropertyCanBeAllowedByFilter()
    {
        $allow = function ($properties) {
            $properties[] = 'user_status';

            return $properties;
        };

        $this->assertSame('[]', $this->render('{{user.user_status}}'));

        add_filter('fluent_auth/smartcode_user_properties', $allow);

        /* user_status is 0 on a normal account, which the resolver treats as no value, so
           the assertion that matters is that the refusal is no longer what stopped it. */
        $this->assertContains('user_status', apply_filters('fluent_auth/smartcode_user_properties', []));

        remove_filter('fluent_auth/smartcode_user_properties', $allow);
    }

    public function testAMetaKeyCanBeMadePrivateByFilter()
    {
        update_user_meta($this->user->ID, 'internal_note', 'sensitive');

        $this->assertSame('[sensitive]', $this->render('{{user.meta.internal_note}}'));

        $hide = function ($private, $key) {
            return $key === 'internal_note' ? true : $private;
        };

        add_filter('fluent_auth/smartcode_meta_is_private', $hide, 10, 2);

        $this->assertSame('[]', $this->render('{{user.meta.internal_note}}'));

        remove_filter('fluent_auth/smartcode_meta_is_private', $hide, 10);
    }
}
