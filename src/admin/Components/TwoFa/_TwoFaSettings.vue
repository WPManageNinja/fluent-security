<script type="text/babel">
import SecretEncryption from './_SecretEncryption.vue';
import SettingToggle from '../Settings/_SettingToggle.vue';

/**
 * What a password login has to produce after the password.
 *
 * Passkeys are no longer on this card - see _PasskeySettings.vue for why. What is left is
 * the pair of questions this screen kept running together: who *must* hold a second
 * factor, and who *may* set one up. They are separate settings with separate lists, and
 * for a long time the screen presented them as three method blocks with a role picker
 * each and then a fourth block, at the bottom, with a role picker that meant something
 * else entirely. Nothing said which picker was which, so the honest reading of the screen
 * was that FluentAuth had four overlapping role lists.
 *
 * The requirement is now first, because it is the policy and the methods are how the
 * policy is met. Read top to bottom it says: these roles must have one, and these are the
 * ways they can get one.
 *
 * The two kinds of list are genuinely different and are labelled as such rather than
 * smoothed over:
 *
 * - An authenticator app is *enrolled*. Its list names who may set one up, and until
 *   somebody does, nothing about their sign-in changes.
 * - An emailed code has nothing to enroll - the address is already on the account - so
 *   its list names who is asked for one at every sign-in. See
 *   EmailTwoFaMethod::isAvailableForUser().
 */
export default {
    name: 'TwoFaSettings',
    components: {
        SecretEncryption,
        SettingToggle
    },
    props: {
        recoveryHelpPreview: {type: Object, default: null},
        settings: {
            type: Object,
            required: true
        },
        user_roles: {
            type: Array,
            default: () => []
        }
    },
    computed: {
        /* Switched on, but offered to nobody - so it is not actually doing anything. */
        isEnabledForNobody() {
            return this.settings.totp_2fa === 'yes' && !(this.settings.totp_2fa_roles || []).length;
        },
        /*
         * Passkeys are set on the card above, but they are one of the three things that
         * can satisfy a requirement, so this screen has to be able to see them. A site
         * on plain http cannot run the ceremony at all, which is why the switch alone is
         * not the answer - see PasskeyTwoFaMethod::isSwitchedOn().
         */
        passkeyOn() {
            return this.settings.passkey_2fa === 'yes' && !!this.appVars.passkey_supported;
        },
        /* The two that prove a device, which is what the stronger floor accepts. */
        deviceMethodOn() {
            return this.passkeyOn || this.settings.totp_2fa === 'yes';
        },
        emailOn() {
            return this.settings.email2fa === 'yes';
        },
        /*
         * With all three down there is no second factor on this site, so there is nothing
         * to require - see DeviceRequirement::isEnforceable(), which reads exactly this
         * and stops the requirement standing. The block is disabled rather than hidden:
         * an owner who has already named roles needs to see that the setting is there and
         * why it is not doing anything.
         */
        anyMethodOn() {
            return this.deviceMethodOn || this.emailOn;
        },
        /* What the chosen floor can actually be met with, given what is switched on. */
        requirementEnforceable() {
            return this.settings.two_fa_required_level === 'any'
                ? this.anyMethodOn
                : this.deviceMethodOn;
        },
        hasAnyMethod() {
            return this.anyMethodOn;
        },
        /* At the relaxed floor an emailed code counts, but only where it is switched on. */
        emailCanSatisfy() {
            return this.settings.two_fa_required_level === 'any'
                && this.settings.email2fa === 'yes'
                && (this.settings.totp_required_roles || [])
                    .some(role => (this.settings.email2fa_roles || []).includes(role));
        },
        requiredRoleTitles() {
            return this.user_roles
                .filter(role => (this.settings.totp_required_roles || []).includes(role.id))
                .map(role => role.title);
        }
    },
    /*
     * Nothing to keep in step any more. The requirement used to have to be narrowed
     * whenever the allow list was, because requiring a role that was not allowed built a
     * policy the server refused - and, before it refused, a policy that silently did
     * nothing. Requiring now grants the methods that satisfy it, so the two lists are
     * independent and the requirement means what it says on its own.
     */
};
</script>

<template>
    <div class="fls_2fa_methods">

        <!--
            The distinction the whole card turns on, said once at the top rather than
            left to be inferred from role pickers that look alike.
        -->
        <p class="fls_2fa_lede">
            {{ $t('Switch on the methods this site offers, then choose who must hold one. Each method names the roles it applies to; the last block names the roles that cannot sign in without one.') }}
        </p>

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.totp_2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Authenticator App') }}</strong>
                    <span class="fls_tag is_round is_success">{{ $t('Strong') }}</span>
                    <p>
                        {{ $t('A code from an app on the user\'s phone. Once someone sets it up, they are asked for it every time they sign in.') }}
                    </p>
                </div>
                <el-switch v-model="settings.totp_2fa" active-value="yes" inactive-value="no"/>
            </div>

            <div v-if="settings.totp_2fa === 'yes'" class="fls_2fa_method_body">
                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles allowed to set one up')">
                            <el-select :placeholder="$t('Pick at least one role')" clearable :multiple="true"
                                       v-model="settings.totp_2fa_roles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p>{{ $t('These roles are invited to set one up after they sign in, and can decline. Leave it empty and nobody is offered it.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <!--
                    Said here rather than refused on save: switching it on and picking
                    nobody is a half-finished setting, not a mistake - but a switch that
                    reads as on while doing nothing is worth pointing at.
                -->
                <p v-if="isEnabledForNobody" class="fls_2fa_note">
                    <strong>{{ $t('Not offered to anyone yet') }}</strong>
                    {{ $t('It is on, but no role has been picked.') }}
                </p>


                <!--
                    Printed because it is meant to be handed out: a member who is kept out
                    of wp-admin has no menu that leads here, so the address is the way in.
                -->
                <el-form-item :label="$t('Setup page')">
                    <el-input readonly :model-value="appVars.totp_setup_url" @focus="$event.target.select()"/>
                    <p>{{ $t('Share this link with users who cannot reach wp-admin. It works for anyone who is signed in.') }}</p>
                </el-form-item>

                <!--
                    Where the secret is kept, rather than who may set one up - so it sits
                    below the policy fields rather than among them. It is also the only
                    thing on this screen that is not saved by the Save button, because the
                    key it needs is in wp-config.php.
                -->
                <SecretEncryption/>

                <p class="fls_action_note">
                    <router-link :to="{name: 'settings_two_fa_enrollment'}">
                        {{ $t('See who has set one up') }} &rarr;
                    </router-link>
                    <span>
                        {{ $t('See which users have one, and turn it off for anyone who has lost their phone.') }}
                    </span>
                </p>
            </div>
        </div>

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.email2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Email Code') }}</strong>
                    <span class="fls_tag is_round is_neutral">{{ $t('Basic') }}</span>
                    <p>
                        {{ $t('A code sent to the user\'s email address when they sign in. There is nothing for them to install.') }}
                    </p>
                </div>
                <el-switch v-model="settings.email2fa" active-value="yes" inactive-value="no"/>
            </div>

            <div v-if="settings.email2fa === 'yes'" class="fls_2fa_method_body">
                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles that get the code')">
                            <el-select :placeholder="$t('Choose at least one role')" clearable :multiple="true"
                                       v-model="settings.email2fa_roles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p>{{ $t('These roles are emailed a code every time they sign in, starting as soon as you save. Pick at least one role.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>
            </div>
        </div>

        <!--
            Last, because it depends on everything above it. A requirement can only stand
            over a method that is switched on - see DeviceRequirement::isEnforceable() -
            so putting it first meant opening the card on a disabled block telling the
            reader to go and do something further down. The reading order follows the
            dependency instead: turn on what the site offers, then say who must have it.
        -->
        <div class="fls_2fa_method"
             :class="{
                 'fls_2fa_method_on': requirementEnforceable && (settings.totp_required_roles || []).length,
                 'is-disabled': !anyMethodOn
             }">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Make it required') }}</strong>
                    <p>
                        {{ $t('Users in these roles cannot sign in until they have set one up. Leave it empty and it stays optional for everyone.') }}
                    </p>
                </div>
            </div>

            <div class="fls_2fa_method_body">
                <!--
                    Nothing is switched on, so there is nothing to require. Said before the
                    fields rather than after they are filled in, because a requirement set
                    over no method is not a stricter site - it is a setting that does
                    nothing while reading as though it does.
                -->
                <p v-if="!anyMethodOn" class="fls_2fa_note is_warn">
                    <strong>{{ $t('Nothing to require yet') }}</strong>
                    {{ $t('Every method is switched off. Turn one on above first.') }}
                </p>

                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles it is required for')">
                            <el-select :placeholder="anyMethodOn ? $t('Nobody is required') : $t('No method is switched on')"
                                       clearable :multiple="true" :disabled="!anyMethodOn"
                                       v-model="settings.totp_required_roles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p>{{ $t('These roles can set up a passkey or the authenticator app whenever it is switched on, even if they are not in its role list.') }}</p>
                        </el-form-item>
                    </el-col>
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('What they can use')">
                            <el-radio-group v-model="settings.two_fa_required_level" :disabled="!anyMethodOn">
                                <!--
                                    Each floor is offered only where something could meet
                                    it. Choosing one that nothing satisfies is the same
                                    empty requirement as setting one with every switch off.
                                -->
                                <el-radio label="device" :disabled="!deviceMethodOn">{{ $t('A passkey or the authenticator app only') }}</el-radio>
                                <el-radio label="any" :disabled="!anyMethodOn">{{ $t('Any method, including an emailed code') }}</el-radio>
                            </el-radio-group>
                            <p>{{ $t('Only the roles named above are held to this. It does not change what anybody else is offered.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <!--
                    On, but the chosen floor cannot be met by what is on. Separate from the
                    warning above because the fix is different: this one is answered either
                    by the other radio or by switching a device method on.
                -->
                <p v-if="anyMethodOn && !requirementEnforceable" class="fls_2fa_note is_warn">
                    <strong>{{ $t('Emailed codes do not count here') }}</strong>
                    {{ $t('Only emailed codes are switched on. Choose the second option, or turn on passkeys or the authenticator app above.') }}
                </p>

                <!--
                    Two different things happen depending on whether an emailed code can
                    already satisfy the floor, and saying the wrong one is worse than
                    saying nothing: an owner told that existing sessions are gated when
                    they are not will not go looking for the ones that got through.
                -->
                <p v-if="requirementEnforceable && requiredRoleTitles.length && !emailCanSatisfy" class="fls_2fa_note is_warn">
                    {{
                        $t('%s will have to set one up the next time they sign in. Anyone already signed in is locked out of the admin area until they do.', requiredRoleTitles.join(', '))
                    }}
                </p>

                <p v-if="requirementEnforceable && requiredRoleTitles.length && emailCanSatisfy" class="fls_2fa_note">
                    {{
                        $t('%s already get an emailed code, so nothing changes for them. Choose the first option to make them set up a passkey or the app instead.', requiredRoleTitles.join(', '))
                    }}
                </p>

                <!--
                    The honest cost of the weaker floor, said once and factually. An
                    emailed code and an emailed password reset are the same factor, so a
                    mailbox someone else can read defeats both at the same time.
                -->
                <p v-if="settings.two_fa_required_level === 'any' && requiredRoleTitles.length"
                   class="fls_2fa_note">
                    <strong>{{ $t('Emailed codes are the weakest option') }}</strong>
                    {{ $t('Anyone who can read the user\'s inbox can read the code. Roles without emailed codes switched on above still need a passkey or the app.') }}
                </p>
            </div>
        </div>


        <p v-if="!hasAnyMethod" class="fls_2fa_none">
            {{ $t('Everything here is off, so a password alone signs anyone in.') }}
        </p>

        <SettingToggle v-model="settings.show_lockout_help" recommend="no"
                       :label="$t('Show emergency recovery help on the two-factor screen')"
                        :description="$t('When enabled, administrators who cannot complete a challenge can expand instructions for the wp-config.php recovery switch.')">
            <template #label-help>
                <el-popover v-if="recoveryHelpPreview" trigger="click" placement="top"
                            :width="380" :title="$t('Recovery message preview')">
                    <template #reference>
                        <button type="button" class="fls_recovery_info"
                                :aria-label="$t('Preview emergency recovery message')">
                            <span aria-hidden="true">ⓘ</span>
                        </button>
                    </template>
                    <div class="fls_recovery_preview">
                        <strong>{{ recoveryHelpPreview.title }}</strong>
                        <p>{{ recoveryHelpPreview.intro }}</p>
                        <p>{{ recoveryHelpPreview.instructions }}</p>
                        <code>{{ recoveryHelpPreview.code }}</code>
                        <p>{{ recoveryHelpPreview.warning }}</p>
                    </div>
                </el-popover>
            </template>
        </SettingToggle>
    </div>
</template>

<style scoped lang="scss">
.fls_recovery_info {
    border: 0;
    background: transparent;
    color: var(--fls-text-secondary, #50575e);
    cursor: pointer;
    padding: 4px 6px;
    font-size: 16px;

    &:focus-visible {
        outline: 2px solid #2271b1;
        outline-offset: 2px;
    }
}

.fls_recovery_preview {
    font-size: 13px;
    line-height: 1.5;

    p { margin: 10px 0; }
    code {
        display: block;
        padding: 8px;
        background: #f0f0f1;
        color: #1d2327;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
    }
}
</style>
