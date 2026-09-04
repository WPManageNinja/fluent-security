<script type="text/babel">
import RoleChoice from './_RoleChoice.vue';

/**
 * Which second step to offer, and to whom.
 *
 * Offer is the operative word. Turning these on lets the chosen roles set a method up and
 * prompts them to; it does not make anybody unable to sign in without one. The setting that
 * would - `totp_required_roles` - is not on this screen and will not be: requiring a second
 * factor from a wizard, before anybody has enrolled, is how an administrator locks
 * themselves out of the site they installed this on ten minutes ago.
 */
export default {
    name: 'OnboardingTwoFactor',
    components: {RoleChoice},
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: Object,
            required: true
        },
        step: {
            type: Object,
            required: true
        },
        userRoles: {
            type: Array,
            default: () => []
        },
        recommended: {
            type: Object,
            default: () => ({})
        }
    },
    computed: {
        answer: {
            get() {
                return this.modelValue;
            },
            set(value) {
                this.$emit('update:modelValue', value);
            }
        },
        anyOn() {
            return !!(this.answer.totp || this.answer.email);
        },
        /** The checklist's own reasoning for this item, so the two never disagree. */
        check() {
            return (this.step.checks || [])[0] || null;
        }
    },
    methods: {
        update(key, value) {
            this.answer = {...this.answer, [key]: value};
        },
        validate() {
            if (this.anyOn && !(this.answer.roles || []).length) {
                return this.$t('Choose at least one role to offer this to.');
            }

            return '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_fields">

        <div class="fls_onb_opts">
            <label class="fls_onb_opt" :class="{'is-on': answer.totp}">
                <el-switch :model-value="answer.totp" @update:model-value="v => update('totp', v)"/>
                <span class="fls_onb_opt_text">
                    <span class="fls_onb_opt_title">
                        {{ $t('Authenticator app') }}
                        <span class="fls_onb_tag">{{ $t('Recommended') }}</span>
                    </span>
                    <span class="fls_onb_opt_note">
                        {{ $t('A code from an app on their phone. Works with no signal and cannot be intercepted in an inbox.') }}
                    </span>
                </span>
            </label>

            <label class="fls_onb_opt" :class="{'is-on': answer.email}">
                <el-switch :model-value="answer.email" @update:model-value="v => update('email', v)"/>
                <span class="fls_onb_opt_text">
                    <span class="fls_onb_opt_title">
                        {{ $t('Emailed code') }}
                        <span class="fls_onb_tag">{{ $t('Recommended') }}</span>
                    </span>
                    <span class="fls_onb_opt_note">
                        {{ $t('Nothing to install. Worth having on as well, so nobody is locked out when they change phone.') }}
                    </span>
                </span>
            </label>
        </div>

        <role-choice v-if="anyOn" :model-value="answer.roles" :user-roles="userRoles"
                     :label="$t('Offer it to')"
                     :hint="$t('These roles will be prompted to set a method up the next time they sign in.')"
                     @update:model-value="v => update('roles', v)"/>

        <p class="fls_onb_reassure">
            {{
                $t('Nobody is locked out by this. It lets the roles you chose set a method up — it never refuses a sign-in from somebody who has not.')
            }}
        </p>
    </div>
</template>
