<script type="text/babel">
/**
 * Passkeys, on a card of their own.
 *
 * They used to sit at the top of Two-Factor Authentication, which is where the feature
 * looks like it belongs and is not where it belongs. A passkey replaces the password
 * rather than following it: the authenticator checks a fingerprint, a face or a PIN
 * before it will sign, so one touch proves the device and the person together. Filing
 * that under "second factor" asks the reader to hold two contradictory ideas - this is
 * the step after your password, and this is instead of your password - and the screen
 * never said which.
 *
 * Separating them also lets each card state its own rule without hedging. This one is
 * about the strongest way into the site. The one below it is about what a password login
 * has to produce afterwards, where a passkey is one of the things that counts.
 */
export default {
    name: 'PasskeySettings',
    props: {
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
        isPasskeyEnabledForNobody() {
            /*
             * Not a warning while passkeys are the way in: the role list is bypassed
             * then, so an empty one is the expected state rather than a misconfiguration.
             */
            return this.settings.passkey_2fa === 'yes'
                && !this.isPasskeyPrimary
                && !(this.settings.passkey_2fa_roles || []).length;
        },
        isPasskeyPrimary() {
            return this.settings.passkey_primary_login === 'yes';
        },
        /*
         * Shown empty while the primary flow is on, because that is what the server does
         * with it - PasskeyTwoFaMethod::isAllowedForUser() stops consulting the list. The
         * stored value is left alone underneath, so switching the flow back off restores
         * whatever policy was there before rather than silently erasing it.
         */
        passkeyRoles: {
            get() {
                return this.isPasskeyPrimary ? [] : (this.settings.passkey_2fa_roles || []);
            },
            set(value) {
                this.settings.passkey_2fa_roles = value;
            }
        },
        /* WebAuthn does not exist outside a secure context, so neither does this switch. */
        passkeySupported() {
            return !!this.appVars.passkey_supported;
        }
    }
};
</script>

<template>
    <div class="fls_2fa_methods">

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.passkey_2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Allow passkeys') }}</strong>
                    <span class="fls_tag is_round is_success">{{ $t('Strongest') }}</span>
                    <p>
                        {{ $t('Sign in with a fingerprint, face or PIN through Touch ID, Windows Hello, a password manager or a security key. Each user sets up their own from their profile page.') }}
                    </p>
                </div>
                <el-switch v-model="settings.passkey_2fa" active-value="yes" inactive-value="no"
                           :disabled="!passkeySupported"/>
            </div>

            <!--
                Said before the switch is reached rather than after it fails. A site on
                plain http cannot run the ceremony at all, and the browser gives no error
                anyone but the user would ever see.
            -->
            <div v-if="!passkeySupported" class="fls_2fa_method_body">
                <p class="fls_2fa_note is_warn">
                    <strong>{{ $t('This site cannot use passkeys yet') }}</strong>
                    {{ $t('Passkeys only work on https sites. Move this site to https and come back.') }}
                </p>
            </div>

            <div v-else-if="settings.passkey_2fa === 'yes'" class="fls_2fa_method_body">
                <el-form-item>
                    <el-checkbox v-model="settings.passkey_primary_login" true-value="yes" false-value="no">
                        {{ $t('Let people sign in with a passkey') }}
                    </el-checkbox>
                    <p>
                        {{ $t('Adds a "Sign in with a passkey" button to the login form. Anyone without a passkey signs in as before.') }}
                    </p>
                </el-form-item>

                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles that can set one up')">
                            <el-select :placeholder="isPasskeyPrimary ? $t('Everyone') : $t('Pick at least one role')"
                                       clearable :multiple="true" :disabled="isPasskeyPrimary"
                                       v-model="passkeyRoles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <!--
                                The two halves of the same caption, and both used to be
                                written from the code's point of view rather than the
                                reader's - "naming a role is what turns this on" describes
                                what the setting does to the stored value, not what the
                                person is choosing.
                            -->
                            <p v-if="isPasskeyPrimary">
                                {{ $t('Every role can register a passkey while login with a passkey is on. Turn that off to choose which roles may.') }}
                            </p>
                            <p v-else>
                                {{ $t('Only these roles can set one up. Pick none and nobody can.') }}
                            </p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <p v-if="isPasskeyEnabledForNobody" class="fls_2fa_note">
                    <strong>{{ $t('Not offered to anyone yet') }}</strong>
                    {{ $t('Passkeys are on, but no role has been picked.') }}
                </p>
            </div>
        </div>
    </div>
</template>
