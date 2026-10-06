<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Services\QrCode;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\RelyingParty;

/**
 * Everything protecting one account, on one card, on the profile screen.
 *
 * The parts of this were written a method at a time, and it showed: an authenticator
 * app heading with two checkboxes under it, then a passkey heading with a table under
 * that, then a third set of recovery code controls that appeared under whichever of the
 * two happened to be in use. Read top to bottom it was three features arguing; what a
 * person opening this screen actually wants is one answer to "what is protecting this
 * account, and what can I do about it".
 *
 * So the methods report into one list here, a line each, and the setup that used to be
 * spread down the page moved behind the button that asks for it. TotpProfileHandler and
 * PasskeyProfileHandler still own every decision - what may be turned on, by whom, and
 * what happens when it is - and this file owns only how that is put in front of somebody.
 *
 * The asymmetry both of those handlers describe is what shapes the admin view: an
 * administrator opening somebody else's profile gets the same card with the removals and
 * none of the enrolments, because taking a lost device off an account is recovery and
 * adding one to it is not.
 */
class TwoFaProfileHandler
{
    public function register()
    {
        add_action('show_user_profile', [$this, 'render']);
        add_action('edit_user_profile', [$this, 'render']);
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    public function render($user)
    {
        if (!$user instanceof \WP_User || !current_user_can('edit_user', $user->ID)) {
            return;
        }

        $context = $this->getContext($user);

        /*
         * A membership site offers most of its users nothing here. A heading followed by
         * three rows of "not available" is not information, so where there is nothing to
         * report and nothing to do, this section is not on the page at all.
         */
        if (!$context['has_anything']) {
            return;
        }

        /*
         * Only ever to the person the codes belong to.
         *
         * This handler draws both `show_user_profile` and `edit_user_profile`, so without the
         * check an administrator opening somebody else's profile inside the five-minute window
         * was shown that person's recovery codes - and pullNotice() deletes the transient on
         * the way past, so the owner then never saw them and had no idea they existed. Nothing
         * here is worth showing to a reader it does not belong to: an unread notice expiring on
         * its own costs its owner a re-generate, which is a button they already have.
         */
        $notice = $user->ID === get_current_user_id()
            ? TotpProfileHandler::pullNotice($user->ID)
            : null;

        $this->renderStyles();

        ?>
        <h2 id="fls-two-factor"><?php esc_html_e('Two-Factor Authentication', 'fluent-security'); ?></h2>

        <div class="fls2fa" id="fls2fa">
            <?php
            wp_nonce_field(TotpProfileHandler::NONCE_ACTION, '_fls_totp_nonce');
            wp_nonce_field(PasskeyProfileHandler::NONCE_ACTION, '_fls_passkey_nonce');
            ?>

            <p class="fls2fa__intro">
                <?php
                if ($context['is_self']) {
                    esc_html_e('A second step at sign-in, so your password on its own is not enough to get into this account.', 'fluent-security');
                } else {
                    /* translators: %s: the login name of the user whose profile is open */
                    printf(
                        esc_html__('You can take a lost device off this account. Only %s can add one, from their own profile.', 'fluent-security'),
                        '<strong>' . esc_html($user->user_login) . '</strong>'
                    );
                }
                ?>
            </p>

            <?php
            $this->renderOwedBanner($context);
            $this->renderNotice($notice);
            ?>

            <div class="fls2fa__card">
                <?php
                $this->renderTotpRow($context);
                $this->renderPasskeyRow($context);
                $this->renderRecoveryRow($context);
                $this->renderEmailRow($context);
                ?>
            </div>

            <?php
            $this->renderTotpModal($context);
            $this->renderPasskeyModal($context);
            $this->renderCodesModal($notice);
            $this->renderNoScriptControls($context);
            ?>
        </div>
        <?php

        $this->renderScript($context);
    }

    /**
     * Everything the card needs to know, read once.
     *
     * Gathered up front rather than asked row by row, because several of the rows turn
     * on the same answers - whether a device factor exists decides both what the
     * recovery row offers and what the email row calls itself - and a screen that asks
     * the same question twice is a screen that can answer it two different ways.
     *
     * @param $user \WP_User
     * @return array
     */
    private function getContext($user)
    {
        $credentials = PasskeyStore::getForUser($user);
        $passkeyAllowed = PasskeyTwoFaMethod::isAllowedForUser($user) && RelyingParty::isSupported();
        $totpEnrolled = TotpTwoFaMethod::isEnrolled($user);
        $totpAllowed = TotpTwoFaMethod::isAllowedForUser($user);
        $isSelf = get_current_user_id() === (int)$user->ID;
        $hasDevice = DeviceRequirement::hasDeviceFactor($user);

        $emailMethod = new EmailTwoFaMethod();
        $emailAvailable = $emailMethod->isAvailableForUser($user);

        // Registered rather than usable - see DeviceRequirement::holdsEnrolledDevice().
        $holdsDevice = DeviceRequirement::holdsEnrolledDevice($user);

        return [
            'user'                => $user,
            'is_self'             => $isSelf,
            'totp_enrolled'       => $totpEnrolled,
            'totp_allowed'        => $totpAllowed,
            'totp_activated_at'   => $totpEnrolled ? TotpTwoFaMethod::getActivatedAt($user) : '',
            'totp_can_setup'      => $isSelf && $totpAllowed && !$totpEnrolled,
            'passkeys'            => $credentials,
            'passkey_allowed'     => $passkeyAllowed,
            'passkey_can_add'     => $isSelf && $passkeyAllowed,
            'passkey_dormant'     => $credentials && !PasskeyTwoFaMethod::hasFallback($user),
            'primary'             => $this->getPrimaryAction($isSelf && !$holdsDevice, [
                'passkey' => !$credentials && $passkeyAllowed,
                'totp'    => $totpAllowed && !$totpEnrolled
            ]),
            'recovery_left'       => RecoveryCodes::countRemaining($user),
            'has_device'          => $hasDevice,
            'has_enrolled_device' => $holdsDevice,
            'email_available'     => $emailAvailable,
            'owed'                => DeviceRequirement::isOwedBy($user),
            'has_anything'        => $totpEnrolled || $totpAllowed || $passkeyAllowed || (bool)$credentials || $emailAvailable
        ];
    }

    /**
     * Which of the setup buttons is the blue one.
     *
     * A card with two primaries is a card telling somebody to do two things at once, so
     * the emphasis goes to the strongest method they could still set up - and only while
     * the account holds nothing at all. Past that point this screen has no business
     * pushing anybody anywhere: somebody with a dormant passkey is already being told in
     * amber what to do about it, and a blue button pointing elsewhere beside that line
     * is the card giving two answers to one question.
     *
     * @param $push bool whether the card should be pushing anything at all
     * @param $offers array method key => whether it could still be set up, strongest
     *                      first, in the order the login flow itself asks for them
     * @return string a method key, or an empty string
     */
    private function getPrimaryAction($push, $offers)
    {
        if (!$push) {
            return '';
        }

        foreach ($offers as $key => $offered) {
            if ($offered) {
                return $key;
            }
        }

        return '';
    }

    /**
     * @param $context array
     * @return void
     */
    private function renderOwedBanner($context)
    {
        if (!$context['owed']) {
            return;
        }

        ?>
        <div class="fls2fa__banner">
            <?php echo self::icon('alert'); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup ?>
            <p>
                <strong><?php esc_html_e('A second factor is required for this account.', 'fluent-security'); ?></strong>
                <?php
                if ($context['is_self']) {
                    /*
                     * "Still owed", not "your role is required" - see TotpProfileHandler.
                     * Somebody who met the requirement with a passkey never sees this.
                     */
                    esc_html_e('Set up an authenticator app or a passkey below to carry on signing in.', 'fluent-security');
                } else {
                    esc_html_e('They will be asked to set one up the next time they sign in.', 'fluent-security');
                }
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * @param $context array
     * @return void
     */
    private function renderTotpRow($context)
    {
        // Nothing to say about a method this account can neither use nor turn off.
        if (!$context['totp_enrolled'] && !$context['totp_allowed']) {
            return;
        }

        $enrolled = $context['totp_enrolled'];

        ob_start();

        if ($enrolled && $context['totp_activated_at']) {
            /* translators: %s: date the authenticator app was set up */
            echo esc_html(sprintf(
                __('Added %s', 'fluent-security'),
                mysql2date(get_option('date_format'), $context['totp_activated_at'])
            ));
        } elseif ($enrolled) {
            esc_html_e('A code from an app on your phone.', 'fluent-security');
        } else {
            esc_html_e('A 6-digit code from an app such as Google Authenticator or 1Password.', 'fluent-security');
        }

        $meta = ob_get_clean();

        ob_start();

        if ($context['totp_can_setup']) {
            ?>
            <a href="#fls2fa-totp" class="button<?php echo $context['primary'] === 'totp' ? ' button-primary' : ''; ?> fls2fa__action"
               data-fls2fa-open="fls2fa-totp">
                <?php esc_html_e('Set up', 'fluent-security'); ?>
            </a>
            <?php
        } elseif ($enrolled) {
            ?>
            <button type="button" class="button fls2fa__danger fls2fa__action" data-fls2fa-totp-disable="1">
                <?php esc_html_e('Turn off', 'fluent-security'); ?>
            </button>
            <?php
        }

        $actions = ob_get_clean();

        $this->renderRow([
            'icon'    => 'app',
            'name'    => __('Authenticator app', 'fluent-security'),
            'meta'    => $meta,
            'status'  => $enrolled ? __('Active', 'fluent-security') : __('Not set up', 'fluent-security'),
            'tone'    => $enrolled ? 'on' : 'off',
            'actions' => $actions
        ]);
    }

    /**
     * @param $context array
     * @return void
     */
    private function renderPasskeyRow($context)
    {
        $credentials = $context['passkeys'];

        if (!$credentials && !$context['passkey_allowed']) {
            return;
        }

        $count = count($credentials);

        ob_start();

        if ($count) {
            /* translators: %d: how many passkeys are registered */
            echo esc_html(sprintf(_n('%d device registered', '%d devices registered', $count, 'fluent-security'), $count));
        } else {
            esc_html_e('Your fingerprint, face or a security key. Nothing to type.', 'fluent-security');
        }

        $meta = ob_get_clean();

        ob_start();

        if ($context['passkey_can_add']) {
            ?>
            <a href="#fls2fa-passkey" class="button<?php echo $context['primary'] === 'passkey' ? ' button-primary' : ''; ?> fls2fa__action"
               data-fls2fa-open="fls2fa-passkey">
                <?php echo $count ? esc_html__('Add another', 'fluent-security') : esc_html__('Set up', 'fluent-security'); ?>
            </a>
            <?php
        }

        $actions = ob_get_clean();

        ob_start();
        $this->renderDevices($context);
        $extra = ob_get_clean();

        /*
         * A dormant passkey is registered and not asked for, so it reads as neither on
         * nor absent. Saying "Active" beside a line explaining that it is not in use is
         * the contradiction the row exists to resolve.
         */
        if ($count && $context['passkey_dormant']) {
            $status = __('Not in use', 'fluent-security');
            $tone = 'warn';
        } elseif ($count) {
            $status = __('Active', 'fluent-security');
            $tone = 'on';
        } else {
            $status = __('Not set up', 'fluent-security');
            $tone = 'off';
        }

        $this->renderRow([
            'icon'    => 'key',
            'name'    => __('Passkeys', 'fluent-security'),
            'meta'    => $meta,
            'status'  => $status,
            'tone'    => $tone,
            'actions' => $actions,
            'extra'   => $extra
        ]);
    }

    /**
     * The registered passkeys themselves, indented under their row.
     *
     * A device per line rather than the four column table this used to be: "Name, Added,
     * Last used" gave three columns of dates equal weight with the one thing anybody
     * scans for, which is which device they are looking at.
     *
     * @param $context array
     * @return void
     */
    private function renderDevices($context)
    {
        if (!$context['passkeys']) {
            return;
        }

        ?>
        <ul class="fls2fa__devices">
            <?php foreach ($context['passkeys'] as $credential) : ?>
                <li class="fls2fa__device">
                    <div class="fls2fa__device-main">
                        <span class="fls2fa__device-name"><?php echo esc_html($credential->label); ?></span>
                        <span class="fls2fa__device-meta">
                            <?php
                            $bits = [];

                            if ($credential->created_at) {
                                /* translators: %s: date the passkey was registered */
                                $bits[] = sprintf(__('Added %s', 'fluent-security'), mysql2date(get_option('date_format'), $credential->created_at));
                            }

                            $bits[] = $credential->last_used_at
                                /* translators: %s: date the passkey was last used to sign in */
                                ? sprintf(__('Last used %s', 'fluent-security'), mysql2date(get_option('date_format'), $credential->last_used_at))
                                : __('Never used', 'fluent-security');

                            if ($credential->backup_eligible) {
                                $bits[] = __('Synced across devices', 'fluent-security');
                            }

                            echo esc_html(implode(' · ', $bits));
                            ?>
                        </span>
                    </div>
                    <button type="button" class="button button-small fls2fa__danger fls2fa__device-remove"
                            data-fls2fa-passkey-remove="<?php echo esc_attr($credential->id); ?>">
                        <?php esc_html_e('Remove', 'fluent-security'); ?>
                    </button>
                </li>
            <?php endforeach; ?>
        </ul>

        <?php
        /*
         * Says out loud when a passkey is registered but will not actually be asked for.
         * Without it the feature fails in the one way a user cannot diagnose: they
         * register a device, see it listed, and are never challenged with it - because a
         * single passkey with nothing behind it is a lockout waiting for the day the
         * device is lost. See PasskeyTwoFaMethod::hasFallback().
         */
        if ($context['passkey_dormant']) :
            ?>
            <p class="fls2fa__hint fls2fa__hint--warn">
                <?php
                if (!$context['is_self']) {
                    esc_html_e('Not in use yet: a lone passkey is not asked for at sign-in until this account has a second way in.', 'fluent-security');
                } else {
                    esc_html_e('Not in use yet. A lone passkey would lock you out of the account if the device were lost, so it is not asked for until there is a way back in behind it.', 'fluent-security');

                    echo ' ';

                    /*
                     * Recovery codes first, and named: they are the one of the three that
                     * needs no second device, and the row that hands them out is directly
                     * below this line.
                     */
                    if ($context['totp_allowed']) {
                        esc_html_e('Generate recovery codes below, set up an authenticator app, or add a second passkey.', 'fluent-security');
                    } else {
                        esc_html_e('Generate recovery codes below, or add a second passkey.', 'fluent-security');
                    }
                }
                ?>
            </p>
        <?php
        endif;
    }

    /**
     * @param $context array
     * @return void
     */
    private function renderRecoveryRow($context)
    {
        /*
         * Only once there is a device to be locked out of. Recovery codes belong to the
         * account rather than to a method - see RecoveryCodes - but a row offering an
         * escape from nothing is just a puzzle.
         *
         * Registered, not usable: the account that needs this row most is the one holding
         * a lone passkey, whose codes are the thing that will put that passkey into the
         * login flow. Reading it the strict way hid the row from exactly that user.
         */
        if (!$context['has_enrolled_device']) {
            return;
        }

        $left = $context['recovery_left'];
        $low = $left < 3;

        ob_start();

        if (!$left) {
            esc_html_e('None on this account yet. Generate a set so that losing the device does not lock you out.', 'fluent-security');
        } elseif ($low) {
            esc_html_e('Running low. Generate a new set and keep it away from the device you sign in with.', 'fluent-security');
        } else {
            esc_html_e('Single-use codes to get back in if you lose the device.', 'fluent-security');
        }

        $meta = ob_get_clean();

        ob_start();

        /*
         * Self only, and never for an administrator looking at somebody else: the codes
         * can only be shown once, at the moment they are made, so whoever presses this
         * is the only person who will ever see them.
         */
        if ($context['is_self']) {
            ?>
            <button type="button" class="button fls2fa__action"
                    data-fls2fa-recovery="<?php echo $left ? 'replace' : 'new'; ?>">
                <?php echo $left ? esc_html__('Replace', 'fluent-security') : esc_html__('Generate', 'fluent-security'); ?>
            </button>
            <?php
        }

        $actions = ob_get_clean();

        $this->renderRow([
            'icon'    => 'lifebuoy',
            'name'    => __('Recovery codes', 'fluent-security'),
            'meta'    => $meta,
            /* translators: %d: number of unused recovery codes */
            'status'  => sprintf(_n('%d left', '%d left', $left, 'fluent-security'), $left),
            'tone'    => $low ? 'warn' : 'on',
            'actions' => $actions
        ]);
    }

    /**
     * The mailed code, which nobody enrols in and nobody here can switch off.
     *
     * Listed anyway, because the question this card answers is what protects the
     * account, and leaving out the method the site turns on by policy would answer it
     * wrongly - most obviously for the user who is about to ask why they were emailed a
     * code by a screen that never mentioned email.
     *
     * @param $context array
     * @return void
     */
    private function renderEmailRow($context)
    {
        if (!$context['email_available']) {
            return;
        }

        // Passkeys and the app both outrank it - see TwoFaService::getMethods().
        $standby = $context['has_device'];

        $this->renderRow([
            'icon'   => 'mail',
            'name'   => __('Email code', 'fluent-security'),
            'meta'   => $standby
                ? __('Sent only when no passkey or authenticator app can be used.', 'fluent-security')
                : __('A code is sent to this account\'s email address at sign-in.', 'fluent-security'),
            'status' => $standby ? __('Standby', 'fluent-security') : __('Active', 'fluent-security'),
            'tone'   => $standby ? 'off' : 'on',
            /* Set by the site owner for a whole role, so there is nothing to press here. */
            'note'   => __('Set by the site', 'fluent-security')
        ]);
    }

    /**
     * One line of the card.
     *
     * @param $args array
     * @return void
     */
    private function renderRow($args)
    {
        $args = array_merge([
            'icon'    => '',
            'name'    => '',
            'meta'    => '',
            'status'  => '',
            'tone'    => 'off',
            'actions' => '',
            'note'    => '',
            'extra'   => ''
        ], $args);

        ?>
        <div class="fls2fa__row">
            <div class="fls2fa__line">
                <span class="fls2fa__icon fls2fa__icon--<?php echo esc_attr($args['tone']); ?>">
                    <?php echo self::icon($args['icon']); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup ?>
                </span>
                <div class="fls2fa__body">
                    <span class="fls2fa__name"><?php echo esc_html($args['name']); ?></span>
                    <span class="fls2fa__meta"><?php echo wp_kses_post($args['meta']); ?></span>
                </div>
                <span class="fls2fa__status fls2fa__status--<?php echo esc_attr($args['tone']); ?>">
                    <?php echo esc_html($args['status']); ?>
                </span>
                <div class="fls2fa__actions">
                    <?php
                    echo $args['actions']; // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built above

                    if ($args['note'] && !$args['actions']) {
                        echo '<span class="fls2fa__note">' . esc_html($args['note']) . '</span>';
                    }
                    ?>
                </div>
            </div>
            <?php echo $args['extra']; // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built above ?>
        </div>
        <?php
    }

    /**
     * Pairing an authenticator app.
     *
     * Still a part of the profile form rather than a request of its own: the code is
     * confirmed by TotpProfileHandler::handleUpdate() on save, which is what makes this
     * whole panel work with the modal script switched off - without JavaScript it is
     * simply a panel further down the page with its own submit button.
     *
     * @param $context array
     * @return void
     */
    private function renderTotpModal($context)
    {
        if (!$context['totp_can_setup']) {
            return;
        }

        $user = $context['user'];
        $secret = TotpTwoFaMethod::getOrCreatePendingSecret($user);

        if (!$secret) {
            echo '<p class="fls2fa__hint fls2fa__hint--warn">'
                . esc_html__('A secret could not be generated on this server, so an authenticator app cannot be set up. Please contact your host.', 'fluent-security')
                . '</p>';
            return;
        }

        $uri = TotpProvider::getProvisioningUri($secret, $user->user_login, get_bloginfo('name'));

        /*
         * Drawn here rather than by a chart service, because the URI contains the shared
         * secret: handing it to a third party to render would hand over the second
         * factor along with it.
         */
        $qr = QrCode::svg($uri, [
            'size'  => 190,
            'label' => __('QR code for setting up your authenticator app', 'fluent-security')
        ]);

        $this->openModal('fls2fa-totp', __('Set up your authenticator app', 'fluent-security'));

        ?>
        <p class="fls2fa__modal-lead">
            <?php esc_html_e('Scan this with your authenticator app, then type the code it shows to pair the two.', 'fluent-security'); ?>
        </p>

        <?php if ($qr) : ?>
            <div class="fls2fa__qr">
                <?php echo $qr; // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from integers, the label is escaped ?>
            </div>
        <?php endif; ?>

        <details class="fls2fa__details">
            <summary><?php esc_html_e('Cannot scan it?', 'fluent-security'); ?></summary>
            <p class="fls2fa__field-label"><?php esc_html_e('Setup key', 'fluent-security'); ?></p>
            <!--
                Not an input: the key is longer than the panel is wide, and a field crops
                what will not fit rather than wrapping it, which leaves people typing in
                half a key. It is nothing the form submits either.
            -->
            <div class="fls2fa__code-block" id="fls2fa_secret"><?php echo esc_html(trim(chunk_split($secret, 4, ' '))); ?></div>
            <p class="fls2fa__hint">
                <?php esc_html_e('Choose "enter a setup key" in your app and paste this in. Spaces do not matter.', 'fluent-security'); ?>
            </p>
            <p class="fls2fa__field-label"><?php esc_html_e('Or a setup link', 'fluent-security'); ?></p>
            <div class="fls2fa__code-block fls2fa__code-block--small"><?php echo esc_html($uri); ?></div>
            <p class="fls2fa__hint"><?php esc_html_e('Some password managers accept this directly.', 'fluent-security'); ?></p>
        </details>

        <p class="fls2fa__field-label">
            <label for="fls_totp_confirm_code"><?php esc_html_e('Code from your app', 'fluent-security'); ?></label>
        </p>
        <input type="text" name="fls_totp_confirm_code" id="fls_totp_confirm_code" class="fls2fa__input"
               inputmode="numeric" autocomplete="off" placeholder="000000"/>
        <p class="fls2fa__hint">
            <?php esc_html_e('Nothing changes until you finish - this saves your profile along with it.', 'fluent-security'); ?>
        </p>

        <div class="fls2fa__modal-actions">
            <button type="submit" class="button button-primary">
                <?php esc_html_e('Verify and turn on', 'fluent-security'); ?>
            </button>
            <button type="button" class="button fls2fa__close" data-fls2fa-close="1">
                <?php esc_html_e('Cancel', 'fluent-security'); ?>
            </button>
        </div>
        <?php

        $this->closeModal();
    }

    /**
     * @param $context array
     * @return void
     */
    private function renderPasskeyModal($context)
    {
        if (!$context['passkey_can_add']) {
            return;
        }

        $this->openModal('fls2fa-passkey', __('Add a passkey', 'fluent-security'));

        ?>
        <p class="fls2fa__modal-lead">
            <?php esc_html_e('Your device will ask for your fingerprint, face or PIN. None of that ever reaches this site - only a public key it can check signatures against.', 'fluent-security'); ?>
        </p>

        <p class="fls2fa__field-label">
            <label for="fls_passkey_label"><?php esc_html_e('Name this device', 'fluent-security'); ?></label>
        </p>
        <input type="text" id="fls_passkey_label" class="fls2fa__input"
               placeholder="<?php esc_attr_e('Work laptop', 'fluent-security'); ?>"/>
        <p class="fls2fa__hint"><?php esc_html_e('So you can tell it apart from the others later.', 'fluent-security'); ?></p>

        <div class="fls2fa__modal-actions">
            <button type="button" class="button button-primary" id="fls_passkey_add">
                <?php esc_html_e('Continue', 'fluent-security'); ?>
            </button>
            <button type="button" class="button fls2fa__close" data-fls2fa-close="1">
                <?php esc_html_e('Cancel', 'fluent-security'); ?>
            </button>
            <span class="fls2fa__status-text" id="fls_passkey_status"></span>
        </div>
        <?php

        $this->closeModal();
    }

    /**
     * Recovery codes, the one time they can be shown.
     *
     * They exist only as hashes once stored, so this panel is the single moment between
     * being generated and being gone. A save redirects, which is why the set that comes
     * back from an enrolment arrives here in a transient rather than in the response -
     * see TotpProfileHandler::setNotice(). The set that comes back from the Replace
     * button never touches one: that request answers with the codes and this panel is
     * filled in from the reply.
     *
     * @param $notice array|false
     * @return void
     */
    private function renderCodesModal($notice)
    {
        $codes = (is_array($notice) && !empty($notice['codes'])) ? (array)$notice['codes'] : [];

        $this->openModal('fls2fa-codes', __('Your recovery codes', 'fluent-security'), $codes ? 'auto' : 'latent');

        ?>
        <p class="fls2fa__modal-lead" id="fls2fa_codes_lead">
            <?php
            echo esc_html($codes && !empty($notice['message'])
                ? $notice['message']
                : __('Each code works once. Store them somewhere other than the device you sign in with - they are not shown again.', 'fluent-security'));
            ?>
        </p>

        <ol class="fls2fa__codes" id="fls2fa_codes">
            <?php foreach ($codes as $code) : ?>
                <li><?php echo esc_html($code); ?></li>
            <?php endforeach; ?>
        </ol>

        <div class="fls2fa__modal-actions">
            <button type="button" class="button" data-fls2fa-copy="1"><?php esc_html_e('Copy', 'fluent-security'); ?></button>
            <button type="button" class="button" data-fls2fa-download="1"><?php esc_html_e('Download', 'fluent-security'); ?></button>
            <button type="button" class="button button-primary fls2fa__close" data-fls2fa-close="1">
                <?php esc_html_e('I have saved them', 'fluent-security'); ?>
            </button>
            <span class="fls2fa__status-text" id="fls2fa_codes_status"></span>
        </div>
        <?php

        $this->closeModal();
    }

    /**
     * The two switches that are buttons above, for a browser running no JavaScript.
     *
     * Both are read by TotpProfileHandler::handleUpdate() on save, and both predate the
     * card - the buttons call the same operations over ajax. Kept because turning a
     * factor off is the half of this screen that somebody may need in a hurry, on
     * whatever browser they have, and because an administrator rescuing an account
     * should not be stopped by a script that failed to load.
     *
     * @param $context array
     * @return void
     */
    private function renderNoScriptControls($context)
    {
        if (!$context['totp_enrolled'] && !$context['has_enrolled_device']) {
            return;
        }

        ?>
        <noscript>
            <div class="fls2fa__noscript">
                <p><?php esc_html_e('JavaScript is switched off, so the buttons above cannot act. Tick what you need and save this profile instead.', 'fluent-security'); ?></p>
                <?php if ($context['totp_enrolled']) : ?>
                    <p>
                        <label>
                            <input type="checkbox" name="fls_totp_disable" value="yes"/>
                            <?php
                            if ($context['is_self']) {
                                esc_html_e('Turn off the authenticator app for my account', 'fluent-security');
                            } else {
                                esc_html_e('Turn off the authenticator app for this user', 'fluent-security');
                            }
                            ?>
                        </label>
                    </p>
                <?php endif; ?>
                <?php if ($context['is_self'] && $context['has_enrolled_device']) : ?>
                    <p>
                        <label>
                            <input type="checkbox" name="fls_totp_regenerate_recovery" value="yes"/>
                            <?php esc_html_e('Generate a new set of recovery codes (this invalidates the old ones)', 'fluent-security'); ?>
                        </label>
                    </p>
                <?php endif; ?>
            </div>
        </noscript>
        <?php
    }

    /**
     * @param $notice array|false
     * @return void
     */
    private function renderNotice($notice)
    {
        // A set of codes is a panel of its own rather than a line of text - see above.
        if (!$notice || !empty($notice['codes']) || empty($notice['message'])) {
            return;
        }

        $type = isset($notice['type']) ? $notice['type'] : 'info';

        ?>
        <div class="fls2fa__banner fls2fa__banner--<?php echo esc_attr($type === 'error' ? 'error' : 'info'); ?>">
            <?php echo self::icon($type === 'error' ? 'alert' : 'check'); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup ?>
            <p><?php echo esc_html($notice['message']); ?></p>
        </div>
        <?php
    }

    /**
     * @param $id string
     * @param $title string
     * @param $flag string 'auto' to have the script open this one on load, 'latent' for
     *                     a panel that is a target for the script and nothing to read
     *                     without it
     * @return void
     */
    private function openModal($id, $title, $flag = '')
    {
        ?>
        <div class="fls2fa-modal<?php echo $flag === 'latent' ? ' fls2fa-modal--latent' : ''; ?>"
             id="<?php echo esc_attr($id); ?>" role="dialog" aria-modal="true"
             aria-labelledby="<?php echo esc_attr($id); ?>-title"
            <?php echo $flag === 'auto' ? ' data-fls2fa-auto="1"' : ''; ?>>
            <div class="fls2fa-modal__dialog">
                <div class="fls2fa-modal__head">
                    <h3 id="<?php echo esc_attr($id); ?>-title"><?php echo esc_html($title); ?></h3>
                    <button type="button" class="fls2fa-modal__x fls2fa__close" data-fls2fa-close="1"
                            aria-label="<?php esc_attr_e('Close', 'fluent-security'); ?>">&times;</button>
                </div>
                <div class="fls2fa-modal__body">
        <?php
    }

    /**
     * @return void
     */
    private function closeModal()
    {
        ?>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * @param $name string
     * @return string
     */
    private static function icon($name)
    {
        $paths = [
            'app'      => '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>',
            'key'      => '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M18 12v3M15 12v2"/>',
            'lifebuoy' => '<path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>',
            'mail'     => '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/>',
            'alert'    => '<path d="M12 3.5 21 19.5H3z"/><path d="M12 10v4M12 16.8v.2"/>',
            'check'    => '<circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.5 2.5L16 9.5"/>'
        ];

        if (!isset($paths[$name])) {
            return '';
        }

        return '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor"'
            . ' stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
            . $paths[$name]
            . '</svg>';
    }

    /**
     * @return void
     */
    private function renderStyles()
    {
        ?>
        <style id="fls2fa-styles">
            .fls2fa { max-width: 760px; margin: 0 0 28px; }
            .fls2fa__intro { margin: 0 0 14px; color: #50575e; max-width: 62ch; }
            .fls2fa__card {
                background: #fff;
                border: 1px solid #dcdcde;
                border-radius: 6px;
                box-shadow: 0 1px 2px rgba(0, 0, 0, .04);
            }
            .fls2fa__row { padding: 14px 16px; border-top: 1px solid #f0f0f1; }
            .fls2fa__row:first-child { border-top: 0; }
            .fls2fa__line { display: flex; align-items: center; gap: 12px; }
            .fls2fa__icon {
                flex: 0 0 34px;
                display: flex;
                align-items: center;
                justify-content: center;
                width: 34px;
                height: 34px;
                border-radius: 8px;
                background: #f0f0f1;
                color: #646970;
            }
            .fls2fa__icon--on { background: #edfaef; color: #007017; }
            .fls2fa__icon--warn { background: #fcf5e6; color: #8a6116; }
            .fls2fa__body { flex: 1 1 auto; min-width: 0; }
            .fls2fa__name { display: block; font-weight: 600; color: #1d2327; line-height: 1.4; }
            .fls2fa__meta { display: block; color: #646970; font-size: 12px; line-height: 1.5; }
            .fls2fa__status {
                flex: 0 0 auto;
                font-size: 11px;
                font-weight: 600;
                line-height: 1.6;
                padding: 2px 9px;
                border-radius: 999px;
                white-space: nowrap;
                background: #f0f0f1;
                color: #50575e;
            }
            .fls2fa__status--on { background: #edfaef; color: #007017; }
            .fls2fa__status--warn { background: #fcf5e6; color: #7a5600; }
            .fls2fa__actions { flex: 0 0 auto; display: flex; align-items: center; gap: 8px; min-width: 92px; justify-content: flex-end; }
            .fls2fa__note { font-size: 12px; color: #8c8f94; }
            .fls2fa .fls2fa__danger { color: #b32d2e; border-color: #dcdcde; }
            .fls2fa .fls2fa__danger:hover,
            .fls2fa .fls2fa__danger:focus { color: #8c2427; border-color: #b32d2e; background: #fcf0f1; }
            .fls2fa .fls2fa__action { min-width: 92px; text-align: center; }

            .fls2fa__devices { margin: 12px 0 0; padding: 0 0 0 46px; list-style: none; }
            .fls2fa__device {
                display: flex;
                align-items: center;
                gap: 12px;
                margin: 0;
                padding: 8px 0;
                border-top: 1px solid #f6f7f7;
            }
            .fls2fa__device:first-child { border-top: 0; padding-top: 0; }
            .fls2fa__device-main { flex: 1 1 auto; min-width: 0; }
            .fls2fa__device-name { display: block; color: #1d2327; font-weight: 500; }
            .fls2fa__device-meta { display: block; color: #646970; font-size: 12px; }

            .fls2fa__hint { margin: 8px 0 0; color: #646970; font-size: 12px; }
            .fls2fa__hint--warn { color: #8a6116; }
            .fls2fa__devices + .fls2fa__hint { padding-left: 46px; }

            .fls2fa__banner {
                display: flex;
                gap: 10px;
                align-items: flex-start;
                margin: 0 0 14px;
                padding: 11px 14px;
                border: 1px solid #f0e2bf;
                border-left: 4px solid #dba617;
                border-radius: 4px;
                background: #fcf9f1;
                color: #4b4227;
            }
            .fls2fa__banner p { margin: 0; }
            .fls2fa__banner svg { flex: 0 0 18px; margin-top: 2px; color: #dba617; }
            .fls2fa__banner--info { border-color: #cfe3f5; border-left-color: #2271b1; background: #f3f8fd; color: #1d3f5b; }
            .fls2fa__banner--info svg { color: #2271b1; }
            .fls2fa__banner--error { border-color: #f3d0d1; border-left-color: #d63638; background: #fdf4f4; color: #5b2526; }
            .fls2fa__banner--error svg { color: #d63638; }

            .fls2fa__noscript {
                margin: 14px 0 0;
                padding: 12px 14px;
                border: 1px solid #dcdcde;
                border-radius: 4px;
                background: #fff;
            }
            .fls2fa__noscript p { margin: 0 0 8px; }
            .fls2fa__noscript p:last-child { margin-bottom: 0; }

            /* Without the script this is a panel on the page; the script turns it into a dialog. */
            .fls2fa-modal { margin: 16px 0 0; }
            .fls2fa-modal--latent { display: none; }

            /*
             * What the script is the only way to reach. A passkey ceremony is JavaScript
             * by definition, and the ajax buttons cannot act without it - so rather than
             * leave dead controls on the page, they are taken off it and the noscript
             * block below the card carries the two operations that can still be saved.
             */
            .fls2fa:not(.fls2fa--js) #fls2fa-passkey,
            .fls2fa:not(.fls2fa--js) [data-fls2fa-open="fls2fa-passkey"],
            .fls2fa:not(.fls2fa--js) [data-fls2fa-recovery],
            .fls2fa:not(.fls2fa--js) [data-fls2fa-totp-disable],
            .fls2fa:not(.fls2fa--js) .fls2fa__device-remove,
            .fls2fa:not(.fls2fa--js) .fls2fa__close { display: none; }
            .fls2fa-modal__dialog {
                background: #fff;
                border: 1px solid #dcdcde;
                border-radius: 6px;
                max-width: 440px;
            }
            .fls2fa-modal__head {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 10px;
                padding: 14px 18px;
                border-bottom: 1px solid #f0f0f1;
            }
            .fls2fa-modal__head h3 { margin: 0; font-size: 15px; line-height: 1.4; }
            .fls2fa-modal__x {
                display: none;
                padding: 0 4px;
                border: 0;
                background: none;
                color: #646970;
                font-size: 22px;
                line-height: 1;
                cursor: pointer;
            }
            .fls2fa-modal__body { padding: 18px; }
            .fls2fa__modal-lead { margin: 0 0 14px; color: #50575e; }
            .fls2fa__modal-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 18px; }
            .fls2fa__status-text { color: #646970; font-size: 12px; }
            .fls2fa__field-label { margin: 14px 0 4px; font-weight: 600; color: #1d2327; }
            .fls2fa__input { width: 100%; max-width: 220px; }
            #fls_totp_confirm_code { letter-spacing: 3px; font-size: 15px; }
            .fls2fa__qr {
                display: flex;
                justify-content: center;
                padding: 12px;
                border: 1px solid #f0f0f1;
                border-radius: 4px;
                background: #fff;
            }
            .fls2fa__details { margin: 14px 0 0; }
            .fls2fa__details summary { cursor: pointer; color: #2271b1; }
            .fls2fa__code-block {
                margin: 0;
                padding: 8px 10px;
                border: 1px solid #dcdcde;
                border-radius: 4px;
                background: #f6f7f7;
                font-family: Menlo, Consolas, monospace;
                font-size: 13px;
                line-height: 1.7;
                letter-spacing: 1px;
                word-break: break-all;
                user-select: all;
            }
            .fls2fa__code-block--small { font-size: 11px; letter-spacing: 0; }
            .fls2fa__codes {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 6px 10px;
                margin: 0;
                padding: 12px 14px;
                border: 1px solid #dcdcde;
                border-radius: 4px;
                background: #f6f7f7;
                list-style: none;
                counter-reset: fls2fa-code;
            }
            .fls2fa__codes li {
                margin: 0;
                font-family: Menlo, Consolas, monospace;
                font-size: 13px;
                letter-spacing: 1px;
                color: #1d2327;
            }

            .fls2fa--js .fls2fa-modal { display: none; margin: 0; }
            .fls2fa--js .fls2fa-modal.is-open {
                display: flex;
                position: fixed;
                inset: 0;
                z-index: 100100;
                align-items: flex-start;
                justify-content: center;
                padding: 48px 16px;
                overflow: auto;
                background: rgba(0, 0, 0, .45);
            }
            .fls2fa--js .fls2fa-modal__dialog {
                width: 100%;
                border: 0;
                box-shadow: 0 16px 48px rgba(0, 0, 0, .25);
            }
            .fls2fa--js .fls2fa-modal__x { display: block; }

            @media screen and (max-width: 782px) {
                .fls2fa__line { flex-wrap: wrap; }
                .fls2fa__body { flex: 1 1 60%; }
                .fls2fa__actions { min-width: 0; width: 100%; justify-content: flex-start; padding-left: 46px; }
                .fls2fa__devices, .fls2fa__devices + .fls2fa__hint { padding-left: 0; }
                .fls2fa__codes { grid-template-columns: 1fr; }
            }
        </style>
        <?php
    }

    /**
     * @param $context array
     * @return void
     */
    private function renderScript($context)
    {
        $data = [
            'ajaxUrl'  => admin_url('admin-ajax.php'),
            'userId'   => (int)$context['user']->ID,
            'canAdd'   => (bool)$context['passkey_can_add'],
            'filename' => sanitize_file_name(sprintf('recovery-codes-%s.txt', $context['user']->user_login)),
            'strings'  => [
                'unsupported'    => __('This browser cannot create passkeys.', 'fluent-security'),
                'prompting'      => __('Follow the prompt from your device…', 'fluent-security'),
                'saving'         => __('Saving…', 'fluent-security'),
                'cancelled'      => __('Cancelled.', 'fluent-security'),
                'working'        => __('Working…', 'fluent-security'),
                'copied'         => __('Copied.', 'fluent-security'),
                'removeKey'      => __('Remove this passkey? If it is the only one on the account, make sure there is still another way to sign in.', 'fluent-security'),
                'disableTotp'    => $context['is_self']
                    ? __('Turn off the authenticator app? Your account will be protected by its password alone unless another factor is set up.', 'fluent-security')
                    : __('Turn off the authenticator app for this user? Their account will be protected by its password alone unless another factor is set up.', 'fluent-security'),
                'replaceCodes'   => __('Generate a new set? The codes you have now stop working straight away.', 'fluent-security'),
                'makeCodes'      => __('Generate a set of recovery codes? They are shown once, so have somewhere to keep them.', 'fluent-security'),
                'codesReady'     => __('Here is your new set. The previous codes no longer work.', 'fluent-security')
            ]
        ];

        ?>
        <script id="fls2fa-script">
            (function () {
                var root = document.getElementById('fls2fa');

                if (!root) {
                    return;
                }

                var data = <?php echo wp_json_encode($data); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
                var strings = data.strings;
                var totpNonce = document.getElementById('_fls_totp_nonce');
                var passkeyNonce = document.getElementById('_fls_passkey_nonce');
                var opener = null;

                /*
                 * Said here rather than in the markup, so that a browser which never ran
                 * this leaves every panel on the page where it can still be used.
                 */
                root.classList.add('fls2fa--js');

                function modal(id) {
                    return document.getElementById(id);
                }

                function open(id) {
                    var element = modal(id);

                    if (!element) {
                        return;
                    }

                    opener = document.activeElement;
                    element.classList.add('is-open');

                    var field = element.querySelector('input, button');

                    if (field) {
                        field.focus();
                    }
                }

                function close(element) {
                    if (!element) {
                        return;
                    }

                    element.classList.remove('is-open');

                    if (opener && opener.focus) {
                        opener.focus();
                    }

                    opener = null;
                }

                function closeAll() {
                    Array.prototype.forEach.call(root.querySelectorAll('.fls2fa-modal.is-open'), close);
                }

                function post(action, nonceField, payload) {
                    var body = new FormData();

                    body.append('action', action);
                    body.append('user_id', data.userId);
                    body.append(nonceField.id, nonceField.value);

                    Object.keys(payload || {}).forEach(function (key) {
                        body.append(key, payload[key]);
                    });

                    return fetch(data.ajaxUrl, {method: 'POST', credentials: 'same-origin', body: body})
                        .then(function (response) {
                            return response.json();
                        })
                        .then(function (json) {
                            if (!json || !json.success) {
                                throw new Error((json && json.data && json.data.message) || 'Request failed');
                            }

                            return json.data;
                        });
                }

                function toBuffer(value) {
                    var normalised = String(value).replace(/-/g, '+').replace(/_/g, '/');
                    var remainder = normalised.length % 4;

                    if (remainder) {
                        normalised += new Array(5 - remainder).join('=');
                    }

                    var binary = window.atob(normalised);
                    var bytes = new Uint8Array(binary.length);

                    for (var i = 0; i < binary.length; i++) {
                        bytes[i] = binary.charCodeAt(i);
                    }

                    return bytes;
                }

                function toBase64Url(buffer) {
                    var bytes = new Uint8Array(buffer);
                    var binary = '';

                    for (var i = 0; i < bytes.length; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }

                    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                }

                root.addEventListener('click', function (event) {
                    var trigger = event.target.closest('[data-fls2fa-open], [data-fls2fa-close]');

                    if (!trigger) {
                        return;
                    }

                    event.preventDefault();

                    if (trigger.hasAttribute('data-fls2fa-close')) {
                        close(trigger.closest('.fls2fa-modal'));
                        return;
                    }

                    open(trigger.getAttribute('data-fls2fa-open'));
                });

                root.addEventListener('mousedown', function (event) {
                    if (event.target.classList.contains('fls2fa-modal')) {
                        close(event.target);
                    }
                });

                document.addEventListener('keydown', function (event) {
                    if (event.key === 'Escape') {
                        closeAll();
                    }
                });

                Array.prototype.forEach.call(root.querySelectorAll('[data-fls2fa-auto]'), function (element) {
                    open(element.id);
                });

                /*
                 * Turning a factor off, and drawing a new set of codes. Both are the same
                 * operations the checkboxes in the noscript block ask for on save; doing
                 * them from here means an administrator taking a lost phone off an account
                 * does not have to save somebody else's whole profile to do it.
                 */
                function confirmedPost(button, message, action, nonceField, payload) {
                    if (!window.confirm(message)) {
                        return null;
                    }

                    button.disabled = true;

                    return post(action, nonceField, payload).catch(function (error) {
                        button.disabled = false;
                        window.alert(error && error.message ? error.message : '');

                        throw error;
                    });
                }

                root.addEventListener('click', function (event) {
                    var button = event.target.closest('[data-fls2fa-totp-disable], [data-fls2fa-passkey-remove], [data-fls2fa-recovery]');

                    if (!button) {
                        return;
                    }

                    event.preventDefault();

                    var request;

                    if (button.hasAttribute('data-fls2fa-passkey-remove')) {
                        request = confirmedPost(button, strings.removeKey, 'fluent_auth_passkey_delete', passkeyNonce, {
                            id: button.getAttribute('data-fls2fa-passkey-remove')
                        });
                    } else if (button.hasAttribute('data-fls2fa-totp-disable')) {
                        request = confirmedPost(button, strings.disableTotp, 'fluent_auth_totp_disable', totpNonce, {});
                    } else {
                        var asked = button.getAttribute('data-fls2fa-recovery') === 'new'
                            ? strings.makeCodes
                            : strings.replaceCodes;

                        request = confirmedPost(button, asked, 'fluent_auth_totp_recovery', totpNonce, {});

                        if (request) {
                            request.then(showCodes).catch(function () {});
                            return;
                        }
                    }

                    if (request) {
                        request.then(function () {
                            window.location.reload();
                        }).catch(function () {});
                    }
                });

                /**
                 * The one moment the codes exist in the clear, so the panel is filled in
                 * from the reply and the page is only reloaded once it has been closed.
                 */
                function showCodes(payload) {
                    var list = document.getElementById('fls2fa_codes');
                    var lead = document.getElementById('fls2fa_codes_lead');
                    var codes = (payload && payload.codes) || [];

                    if (!list) {
                        window.location.reload();
                        return;
                    }

                    list.innerHTML = '';

                    codes.forEach(function (code) {
                        var item = document.createElement('li');
                        item.textContent = code;
                        list.appendChild(item);
                    });

                    if (lead) {
                        lead.textContent = strings.codesReady;
                    }

                    var panel = modal('fls2fa-codes');

                    if (panel) {
                        panel.setAttribute('data-fls2fa-reload', '1');
                    }

                    open('fls2fa-codes');
                }

                var codesPanel = modal('fls2fa-codes');

                if (codesPanel) {
                    codesPanel.addEventListener('click', function (event) {
                        var button = event.target.closest('[data-fls2fa-copy], [data-fls2fa-download]');

                        if (!button) {
                            if (event.target.closest('[data-fls2fa-close]') && codesPanel.hasAttribute('data-fls2fa-reload')) {
                                window.location.reload();
                            }

                            return;
                        }

                        event.preventDefault();

                        var text = Array.prototype.map.call(
                            codesPanel.querySelectorAll('#fls2fa_codes li'),
                            function (item) {
                                return item.textContent;
                            }
                        ).join('\n');

                        var status = document.getElementById('fls2fa_codes_status');

                        if (button.hasAttribute('data-fls2fa-copy')) {
                            if (navigator.clipboard) {
                                navigator.clipboard.writeText(text).then(function () {
                                    if (status) {
                                        status.textContent = strings.copied;
                                    }
                                });
                            }

                            return;
                        }

                        var link = document.createElement('a');
                        link.href = URL.createObjectURL(new Blob([text], {type: 'text/plain'}));
                        link.download = data.filename;
                        link.click();
                        URL.revokeObjectURL(link.href);
                    });
                }

                var addButton = document.getElementById('fls_passkey_add');

                if (!data.canAdd || !addButton) {
                    return;
                }

                var status = document.getElementById('fls_passkey_status');

                function setStatus(text) {
                    if (status) {
                        status.textContent = text || '';
                    }
                }

                if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
                    addButton.disabled = true;
                    setStatus(strings.unsupported);
                    return;
                }

                addButton.addEventListener('click', function () {
                    addButton.disabled = true;
                    setStatus(strings.prompting);

                    var label = document.getElementById('fls_passkey_label');

                    post('fluent_auth_passkey_options', passkeyNonce, {}).then(function (payload) {
                        var options = payload.options;

                        options.challenge = toBuffer(options.challenge);
                        options.user.id = toBuffer(options.user.id);
                        options.excludeCredentials = (options.excludeCredentials || []).map(function (item) {
                            item.id = toBuffer(item.id);
                            return item;
                        });

                        return navigator.credentials.create({publicKey: options});
                    }).then(function (credential) {
                        setStatus(strings.saving);

                        var transports = credential.response.getTransports
                            ? credential.response.getTransports()
                            : [];

                        return post('fluent_auth_passkey_register', passkeyNonce, {
                            label: label ? label.value : '',
                            transports: JSON.stringify(transports || []),
                            response: JSON.stringify({
                                rawId: toBase64Url(credential.rawId),
                                clientDataJSON: toBase64Url(credential.response.clientDataJSON),
                                attestationObject: toBase64Url(credential.response.attestationObject)
                            })
                        });
                    }).then(function () {
                        window.location.reload();
                    }).catch(function (error) {
                        addButton.disabled = false;
                        setStatus(error && error.message ? error.message : strings.cancelled);
                    });
                });
            })();
        </script>
        <?php
    }
}
