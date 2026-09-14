<?php

namespace FluentAuth\App\Services\Checks\Config;

use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\TwoFa\SecretKey;
use FluentAuth\App\Services\TwoFa\SecretMigration;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Whether the authenticator secrets can still be read, and whether they are protected.
 *
 * Two questions in one check because they are the same subject seen from either side, and
 * because only one of them can be true at a time.
 *
 * The urgent one is not "you should encrypt these" - it is "the key changed and nobody has
 * noticed". That state is silent by nature: logins keep working for everyone who signs in
 * with a password alone, the failure only shows up when somebody reaches for their
 * authenticator app, and the deploy that overwrote wp-config.php three weeks ago is long
 * forgotten. A dashboard nobody opens is no use for that, which is why this is a check and
 * not only a notice on the two-factor screen.
 *
 * The other, quieter question is worth `advice` and nothing louder. Storing a TOTP secret
 * in the clear is how nearly every WordPress plugin does it, the fix needs a line in
 * wp-config.php, and a site that has not done it is not compromised - it is one database
 * leak away from being. That belongs in the same voice as the other wp-config
 * recommendations, not in the same amber as a file that changed last night.
 */
class SecretEncryptionCheck extends Check
{
    public function id()
    {
        return 'totp_secret_encryption';
    }

    public function group()
    {
        return 'config';
    }

    public function run()
    {
        /*
         * Nothing to protect. A site with no authenticator app enrolled and none on offer
         * does not need to hear about how their secrets are stored - there are none.
         */
        if (!TotpTwoFaMethod::isEnabledForAnyRole() && !SecretKey::isEnabled()) {
            return [];
        }

        $diagnosis = SecretKey::diagnose();

        if ($diagnosis !== SecretKey::STATE_OK && $diagnosis !== SecretKey::STATE_OFF) {
            return [$this->unreadable($diagnosis)];
        }

        if ($diagnosis === SecretKey::STATE_OK) {
            return [new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_PASSED,
                'title'  => __('Authenticator secrets are encrypted', 'fluent-security'),
                'scored' => false
            ])];
        }

        return [$this->unencrypted()];
    }

    /**
     * The key is gone or has changed, and some enrollments cannot be read.
     *
     * Each cause gets its own sentence, because both are recoverable but not in the same
     * way: a missing line is put back, a changed value needs the old one pasted in. A
     * single "decryption failed" would hide the fact that either can be undone at all.
     *
     * @param string $diagnosis
     * @return Finding
     */
    protected function unreadable($diagnosis)
    {
        $count = SecretMigration::unreadableCount();

        $details = [];

        if ($diagnosis === SecretKey::STATE_CONSTANT_MISSING) {
            $details[] = sprintf(
                /* translators: %s: the wp-config.php constant name */
                __('The %s line is no longer in your wp-config.php. If a deployment overwrote the file, putting the same line back makes every authenticator app work again.', 'fluent-security'),
                SecretKey::CONSTANT
            );
        } else {
            $details[] = sprintf(
                /* translators: %s: the wp-config.php constant name */
                __('The %s value in your wp-config.php is not the one these secrets were encrypted with. If you still have the previous value, you can paste it in on the two-factor settings screen and everything will be re-encrypted under the new one.', 'fluent-security'),
                SecretKey::CONSTANT
            );
        }

        /*
         * Said plainly, because it is the question anybody reading this actually has, and
         * the answer is reassuring: nobody is locked out. An unreadable secret makes the
         * account read as not enrolled, so the door the user meets is the setup screen.
         */
        $details[] = __('Nobody is locked out. An account whose secret cannot be read is treated as not having an authenticator app, so those users will be asked to set one up again the next time they sign in to the admin area.', 'fluent-security');

        return new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $count
                ? sprintf(
                    /* translators: %d: number of affected authenticator apps */
                    _n(
                        '%d authenticator app can no longer be read',
                        '%d authenticator apps can no longer be read',
                        $count,
                        'fluent-security'
                    ),
                    $count
                )
                : __('The authenticator encryption key has changed', 'fluent-security'),
            'why'      => __('The key these secrets were encrypted with is not the one in force now, so the codes from those apps will not be accepted.', 'fluent-security'),
            'details'  => $details,
            'action'   => 'navigate',
            'label'    => __('Review two-factor settings', 'fluent-security'),
            'route'    => 'settings_general',
            'section'  => 'two_fa',
            /*
             * Not dismissible. Everything else on this screen is a judgement about how a
             * site should be set up; this is a statement that some of its data cannot be
             * read, and silencing it would not make that less true.
             */
            'dismiss'  => '',
            'scored'   => false
        ]);
    }

    /**
     * Encryption is available but not switched on.
     *
     * @return Finding
     */
    protected function unencrypted()
    {
        if (Dismissals::has($this->id())) {
            return new Finding([
                'id'     => $this->id(),
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => __('Authenticator secrets are stored unencrypted', 'fluent-security'),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ]);
        }

        $details = [
            __('An authenticator secret has to be readable to check a code, so unlike a password it cannot be hashed. Anyone who obtains a copy of your database can generate valid codes for every enrolled account until those users pair a new app.', 'fluent-security')
        ];

        if (!SecretKey::isSupported()) {
            $details[] = __('This server does not have the OpenSSL functions this needs, so encryption cannot be switched on here. Your host can say whether that can change.', 'fluent-security');
        } else {
            $details[] = sprintf(
                /* translators: %s: the wp-config.php constant name */
                __('The two-factor settings screen will generate a %s line for your wp-config.php and encrypt the existing secrets once it is in place.', 'fluent-security'),
                SecretKey::CONSTANT
            );
        }

        return new Finding([
            'id'       => $this->id(),
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            /*
             * Advice, not a fault. This is how nearly every plugin stores a TOTP secret,
             * the fix needs a text editor, and the site is not compromised for want of it.
             */
            'severity' => Finding::SEVERITY_ADVICE,
            'title'    => __('Authenticator secrets are stored unencrypted', 'fluent-security'),
            'why'      => __('They are readable to anyone who gets a copy of your database.', 'fluent-security'),
            'details'  => $details,
            'action'   => SecretKey::isSupported() ? 'navigate' : 'none',
            'label'    => __('Set up encryption', 'fluent-security'),
            'route'    => 'settings_general',
            'section'  => 'two_fa',
            'dismiss'  => 'ignore',
            'scored'   => false
        ]);
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

        /*
         * Only the advice can be accepted. An unreadable secret is not a preference, and
         * accept() is reachable by anyone who can call the endpoint with an id.
         */
        if (!SecretKey::isHealthy()) {
            return new \WP_Error(
                'not_acceptable',
                __('This one reports that stored secrets cannot be read, which is not something to mark as expected.', 'fluent-security'),
                ['status' => 422]
            );
        }

        Dismissals::add($this->id());

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        if ($findingId !== $this->id()) {
            return new \WP_Error(
                'unknown_check',
                __('There is nothing to undo for this one.', 'fluent-security'),
                ['status' => 404]
            );
        }

        Dismissals::remove($this->id());

        return ['message' => __('This is back on the list.', 'fluent-security')];
    }
}
