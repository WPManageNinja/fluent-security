<script type="text/babel">
export default {
    name: 'TwoFaSettings',
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
        /**
         * A role can only be required to use an authenticator app if it is allowed one.
         * Offering the rest would only let someone build a policy the server rejects,
         * so the choice is narrowed instead of the mistake being explained afterwards.
         */
        requirableRoles() {
            const allowed = this.settings.totp_2fa_roles || [];

            return this.user_roles.filter(role => allowed.includes(role.id));
        },
        /* Switched on, but offered to nobody - so it is not actually doing anything. */
        isEnabledForNobody() {
            return this.settings.totp_2fa === 'yes' && !(this.settings.totp_2fa_roles || []).length;
        },
        requiredRoleTitles() {
            return this.user_roles
                .filter(role => (this.settings.totp_required_roles || []).includes(role.id))
                .map(role => role.title);
        }
    },
    watch: {
        /**
         * Narrowing who is allowed has to narrow who is required with it, or the policy
         * left behind is one the user cannot see on screen and cannot save. Clearing the
         * allowed list clears the required one outright - nobody can be made to hold
         * something nobody is offered.
         */
        'settings.totp_2fa_roles'(allowed) {
            this.settings.totp_required_roles = (this.settings.totp_required_roles || [])
                .filter(role => (allowed || []).includes(role));
        },
        'settings.totp_2fa'(enabled) {
            if (enabled !== 'yes') {
                this.settings.totp_required_roles = [];
            }
        }
    }
};
</script>

<template>
    <div class="fls_2fa_methods">

        <div class="fls_2fa_method" :class="{'fls_2fa_method_on': settings.totp_2fa === 'yes'}">
            <div class="fls_2fa_method_head">
                <div>
                    <strong>{{ $t('Authenticator App') }}</strong>
                    <span class="fls_tag is_round is_success">{{ $t('Strongest') }}</span>
                    <p>
                        {{ $t('A rotating code from an app on the user\'s phone. It proves a device, which neither an inbox nor a social account ever does, so it is asked for however the user signed in - including magic login and Google.') }}
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
                            <p>{{ $t('Users in these roles can set one up, on their profile or on the setup page below. Naming the roles is what turns this on - with none named it applies to nobody.') }}</p>
                        </el-form-item>
                    </el-col>
                    <el-col :md="12" :sm="24">
                        <el-form-item :label="$t('Roles that must set one up')">
                            <el-select :placeholder="$t('Nobody is forced')" clearable :multiple="true"
                                       v-model="settings.totp_required_roles" style="width: 100%;">
                                <el-option v-for="role in requirableRoles" :value="role.id" :label="role.title"
                                           :key="role.id"></el-option>
                            </el-select>
                            <p>{{ $t('Only roles allowed above can be listed here.') }}</p>
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

                <el-alert v-if="requiredRoleTitles.length" type="warning" :closable="false" show-icon
                          style="margin-bottom: 10px;">
                    {{
                        $t('%s will be sent to the setup page to set up an authenticator app, and cannot use the admin area until they have. They stay signed in while they do it, and the front end of the site is not affected.', requiredRoleTitles.join(', '))
                    }}
                </el-alert>

                <!--
                    Printed because it is meant to be handed out: a member who is kept out
                    of wp-admin has no menu that leads here, so the address is the way in.
                -->
                <el-form-item :label="$t('Setup page')">
                    <el-input readonly :model-value="appVars.totp_setup_url" @focus="$event.target.select()"/>
                    <p>{{ $t('Any signed in user can set up an authenticator app here without entering the admin area. Send it to members who are kept out of wp-admin.') }}</p>
                </el-form-item>

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
                        {{ $t('A one-time code sent to the account address. It proves the mailbox, so it is skipped after a magic link or a social login, which already proved the same thing. It is also the code sent when an account comes under attack.') }}
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

        <p v-if="settings.totp_2fa !== 'yes' && settings.email2fa !== 'yes'" class="fls_2fa_none">
            {{ $t('No second factor is enabled, so a password is all that stands between an attacker and these accounts.') }}
        </p>
    </div>
</template>
