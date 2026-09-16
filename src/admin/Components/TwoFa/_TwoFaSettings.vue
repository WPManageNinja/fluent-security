<script type="text/babel">
import SecretEncryption from './_SecretEncryption.vue';

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
        /*
         * A requirement counts as a method being on, because it is: requiring a factor
         * grants the means to set one up, so "roles required, every switch off" is a
         * complete and fully enforcing configuration. Without this the screen tells an
         * owner who has done exactly that they have no second factor at all.
         *
         * Passkeys still count from here even though they are set on the card above -
         * this sentence is a verdict on the account, not on the card.
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

        <!--
            The distinction the whole card turns on, said once at the top rather than
            left to be inferred from four role pickers that look alike.
        -->
        <p class="fls_2fa_lede">
            {{ $t('Requiring a second factor and offering one are separate settings. The first block names the roles that must hold one; each method below names the roles that method applies to.') }}
        </p>

        <!--
            First, because it is the policy. Everything under it is a way of satisfying
            this, and a reader who starts with the methods has no way of telling that the
            role list in each one answers a different question from the role list here.
        -->
        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': (settings.totp_required_roles || []).length}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Require a second factor') }}</strong>
                    <p>
                        {{ $t('Chosen roles must hold a second factor. They are asked to set one up when they sign in, and are not signed in until they have. Leave it empty to make a second factor optional for everybody.') }}
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
                            <p>{{ $t('Requiring a factor also offers these roles the means to set one up, whatever the switches below say.') }}</p>
                        </el-form-item>
                    </el-col>
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('What counts as a second factor')">
                            <el-radio-group v-model="settings.two_fa_required_level">
                                <el-radio label="device">{{ $t('A passkey or an authenticator app') }}</el-radio>
                                <el-radio label="any">{{ $t('Those, or an emailed code') }}</el-radio>
                            </el-radio-group>
                            <p>{{ $t('Only the roles named above are held to this. It does not change what anybody else is offered.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <!--
                    Two different things happen depending on whether an emailed code can
                    already satisfy the floor, and saying the wrong one is worse than
                    saying nothing: an owner told that existing sessions are gated when
                    they are not will not go looking for the ones that got through.
                -->
                <p v-if="requiredRoleTitles.length && !emailCanSatisfy" class="fls_2fa_note is_warn">
                    {{
                        $t('%s will be asked to set up a second factor the next time they sign in, and will not be signed in until they have. Anyone already signed in keeps their session but cannot use the admin area or the site APIs until they set one up.', requiredRoleTitles.join(', '))
                    }}
                </p>

                <p v-if="requiredRoleTitles.length && emailCanSatisfy" class="fls_2fa_note">
                    {{
                        $t('%s already meet this with the emailed code they are sent at sign in, so nothing changes for them and nobody is asked to set anything up. Choose the stronger option above to have them hold a passkey or an authenticator app instead.', requiredRoleTitles.join(', '))
                    }}
                </p>

                <!--
                    The honest cost of the weaker floor, said once and factually. An
                    emailed code and an emailed password reset are the same factor, so a
                    mailbox someone else can read defeats both at the same time.
                -->
                <p v-if="settings.two_fa_required_level === 'any' && requiredRoleTitles.length"
                   class="fls_2fa_note">
                    <strong>{{ $t('An emailed code is the weakest of the three') }}</strong>
                    {{ $t('It protects against a stolen or reused password, but not against a compromised mailbox - which is also where password resets arrive. It counts only for roles that have emailed codes switched on below; the rest still have to set up a passkey or an app.') }}
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
                            <p>{{ $t('Offered, not imposed: these roles may set one up, and nothing changes for them until they do. Naming no role turns it on for nobody.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>

                <!--
                    Said here rather than refused on save: switching it on and picking
                    nobody is a half-finished setting, not a mistake - but a switch that
                    reads as on while doing nothing is worth pointing at.
                -->
                <p v-if="isEnabledForNobody" class="fls_2fa_note">
                    <strong>{{ $t('Nobody can use this yet') }}</strong>
                    {{ $t('The authenticator app is switched on but offered to no role, so nothing changes for anyone. Pick the roles that should be able to set one up.') }}
                </p>


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
                            <p>{{ $t('There is nothing to set up for this one, so it applies the moment you save: these roles are emailed a code at every sign-in. At least one role is needed while this is on.') }}</p>
                        </el-form-item>
                    </el-col>
                </el-row>
            </div>
        </div>

        <p v-if="!hasAnyMethod" class="fls_2fa_none">
            {{ $t('No second factor is enabled, so a password is all that stands between an attacker and these accounts.') }}
        </p>
    </div>
</template>
