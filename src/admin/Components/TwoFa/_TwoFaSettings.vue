<script type="text/babel">
import SecretEncryption from './_SecretEncryption.vue';

export default {
    name: 'TwoFaSettings',
    components: {
        SecretEncryption
    },
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
        /* Switched on, but offered to nobody - so it is not actually doing anything. */
        isEnabledForNobody() {
            return this.settings.totp_2fa === 'yes' && !(this.settings.totp_2fa_roles || []).length;
        },
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
        },
        /*
         * A requirement counts as a method being on, because it is: requiring a factor
         * grants the means to set one up, so "roles required, every switch off" is a
         * complete and fully enforcing configuration. Without this the screen tells an
         * owner who has done exactly that they have no second factor at all.
         */
        hasAnyMethod() {
            return this.settings.totp_2fa === 'yes'
                || this.settings.email2fa === 'yes'
                || this.settings.passkey_2fa === 'yes'
                || (this.settings.totp_required_roles || []).length > 0;
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

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.passkey_2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Passkey') }}</strong>
                    <span class="fls_tag is_round is_success">{{ $t('Strongest') }}</span>
                    <p>
                        {{ $t('Touch ID, Windows Hello, a password manager or a security key. The browser ties it to this domain, so it cannot be used on a copy of your login page.') }}
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
                <el-alert type="warning" :closable="false" show-icon
                          :title="$t('This site cannot use passkeys yet')">
                    {{ $t('Passkeys need the site to be served over https. Once it is, this can be switched on.') }}
                </el-alert>
            </div>

            <div v-else-if="settings.passkey_2fa === 'yes'" class="fls_2fa_method_body">
                <el-form-item>
                    <el-checkbox v-model="settings.passkey_primary_login" true-value="yes" false-value="no">
                        {{ $t('Offer a passkey on the login form') }}
                    </el-checkbox>
                    <p>
                        {{ $t('Adds a "Sign in with a passkey" button above the username and password. People who have registered one sign in with a touch instead of typing anything; everyone else uses the form below it as before.') }}
                    </p>
                </el-form-item>

                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles allowed to register one')">
                            <el-select :placeholder="isPasskeyPrimary ? $t('Everyone') : $t('Pick at least one role')"
                                       clearable :multiple="true" :disabled="isPasskeyPrimary"
                                       v-model="passkeyRoles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p v-if="isPasskeyPrimary">
                                {{ $t('Not used while a passkey is offered on the login form. Signing in with one means anyone who can sign in can register one, so every role may.') }}
                            </p>
                            <p v-else>
                                {{ $t('Naming a role is what turns this on. With none named it applies to nobody.') }}
                            </p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <el-alert v-if="isPasskeyEnabledForNobody" type="info" :closable="false" show-icon
                          style="margin-bottom: 10px;"
                          :title="$t('Nobody can use this yet')">
                    {{ $t('Passkeys are switched on but offered to no role, so nothing changes for anyone. Pick the roles that should be able to register one.') }}
                </el-alert>

                <!--
                    True of the second factor step only. On the login form a passkey has
                    nothing to fall back *from* - the password is still on the same page -
                    so the rule that holds a lone passkey back there does not apply here.
                -->
                <el-alert type="info" :closable="false" show-icon style="margin-bottom: 10px;"
                          :title="$t('A single passkey is not asked for as a second step')">
                    {{ $t('Until someone has registered a second passkey, or set up an authenticator app, theirs is not used as the second step of a password login. One device on its own would lock them out of the account if it were lost.') }}
                    <template v-if="isPasskeyPrimary">
                        {{ $t('Signing in with the button on the login form is unaffected, because the password form is still there if the passkey cannot answer.') }}
                    </template>
                </el-alert>

                <el-alert v-if="isPasskeyPrimary" type="info" :closable="false" show-icon
                          style="margin-bottom: 10px;"
                          :title="$t('A passkey sign in is complete on its own')">
                    {{ $t('The authenticator checks a fingerprint, a face or a PIN before it will sign, so a passkey proves the device and the person in one step. Nobody signing in this way is asked for a second factor as well. Who must set one up is decided by the requirement below, and a passkey satisfies it.') }}
                </el-alert>

                <p class="fls_action_note">
                    <span>
                        {{ $t('Users register their own passkeys from their profile screen. Nobody can add one to somebody else\'s account, though an administrator can remove one.') }}
                    </span>
                </p>
            </div>
        </div>

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.totp_2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Authenticator App') }}</strong>
                    <span class="fls_tag is_round is_success">{{ $t('Strong') }}</span>
                    <p>
                        {{ $t('A rotating code from the user\'s phone. It proves a device, so it is always asked for.') }}
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
                            <p>{{ $t('Naming a role is what turns this on. With none named it applies to nobody.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <!--
                    Said here rather than refused on save: switching it on and picking
                    nobody is a half-finished setting, not a mistake - but a switch that
                    reads as on while doing nothing is worth pointing at.
                -->
                <el-alert v-if="isEnabledForNobody" type="info" :closable="false" show-icon
                          style="margin-bottom: 10px;"
                          :title="$t('Nobody can use this yet')">
                    {{ $t('The authenticator app is switched on but offered to no role, so nothing changes for anyone. Pick the roles that should be able to set one up.') }}
                </el-alert>


                <!--
                    Printed because it is meant to be handed out: a member who is kept out
                    of wp-admin has no menu that leads here, so the address is the way in.
                -->
                <el-form-item :label="$t('Setup page')">
                    <el-input readonly :model-value="appVars.totp_setup_url" @focus="$event.target.select()"/>
                    <p>{{ $t('For members who are kept out of wp-admin - no admin area needed.') }}</p>
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
                        {{ $t('Check enrollment across your users, and turn it off for anyone who has lost their device.') }}
                    </span>
                </p>
            </div>
        </div>

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.email2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Email Code') }}</strong>
                    <span class="fls_tag is_round is_neutral">{{ $t('Fallback') }}</span>
                    <p>
                        {{ $t('A code sent to the account address. It proves the mailbox, so a magic link skips it.') }}
                    </p>
                </div>
                <el-switch v-model="settings.email2fa" active-value="yes" inactive-value="no"/>
            </div>

            <div v-if="settings.email2fa === 'yes'" class="fls_2fa_method_body">
                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles that must use it')">
                            <el-select :placeholder="$t('Choose at least one role')" clearable :multiple="true"
                                       v-model="settings.email2fa_roles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p>{{ $t('At least one role is needed while this is on.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>
            </div>
        </div>

        <!--
            Its own section rather than a field inside the authenticator app, because it
            is no longer about that method. It says how strongly these accounts must be
            protected; which of the methods above a given user reaches for is decided by
            their browser at the moment they enroll, not here.
        -->
        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': (settings.totp_required_roles || []).length}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Require two-factor authentication') }}</strong>
                    <p>
                        {{ $t('Chosen roles must hold a second factor. They are asked to set one up when they sign in, and are not signed in until they have.') }}
                    </p>
                </div>
            </div>

            <div class="fls_2fa_method_body">
                <el-row :gutter="30">
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles that must have one')">
                            <el-select :placeholder="$t('Nobody is required')" clearable :multiple="true"
                                       v-model="settings.totp_required_roles" style="width: 100%;">
                                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p>{{ $t('Requiring a factor also offers these roles the means to set one up, whatever the switches above say.') }}</p>
                        </el-form-item>
                    </el-col>
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('What counts as a second factor')">
                            <el-radio-group v-model="settings.two_fa_required_level">
                                <el-radio label="device">{{ $t('A passkey or an authenticator app') }}</el-radio>
                                <el-radio label="any">{{ $t('Those, or an emailed code') }}</el-radio>
                            </el-radio-group>
                        </el-form-item>
                    </el-col>
                </el-row>

                <!--
                    Two different things happen depending on whether an emailed code can
                    already satisfy the floor, and saying the wrong one is worse than
                    saying nothing: an owner told that existing sessions are gated when
                    they are not will not go looking for the ones that got through.
                -->
                <el-alert v-if="requiredRoleTitles.length && !emailCanSatisfy" type="warning" :closable="false"
                          show-icon style="margin-bottom: 10px;">
                    {{
                        $t('%s will be asked to set up a second factor the next time they sign in, and will not be signed in until they have. Anyone already signed in keeps their session but cannot use the admin area or the site APIs until they set one up.', requiredRoleTitles.join(', '))
                    }}
                </el-alert>

                <el-alert v-if="requiredRoleTitles.length && emailCanSatisfy" type="info" :closable="false"
                          show-icon style="margin-bottom: 10px;">
                    {{
                        $t('%s already meet this with the emailed code they are sent at sign in, so nothing changes for them and nobody is asked to set anything up. Choose the stronger option above to have them hold a passkey or an authenticator app instead.', requiredRoleTitles.join(', '))
                    }}
                </el-alert>

                <!--
                    The honest cost of the weaker floor, said once and factually. An
                    emailed code and an emailed password reset are the same factor, so a
                    mailbox someone else can read defeats both at the same time.
                -->
                <el-alert v-if="settings.two_fa_required_level === 'any' && requiredRoleTitles.length"
                          type="info" :closable="false" show-icon style="margin-bottom: 10px;"
                          :title="$t('An emailed code is the weakest of the three')">
                    {{ $t('It protects against a stolen or reused password, but not against a compromised mailbox - which is also where password resets arrive. It counts only for roles that have emailed codes switched on below; the rest still have to set up a passkey or an app.') }}
                </el-alert>
            </div>
        </div>

        <p v-if="!hasAnyMethod" class="fls_2fa_none">
            {{ $t('No second factor is enabled, so a password is all that stands between an attacker and these accounts.') }}
        </p>
    </div>
</template>
