<script type="text/babel">
import SettingToggle from '../../Settings/_SettingToggle.vue';
import RoleChoice from './_RoleChoice.vue';

/**
 * Which second step to offer, and to whom.
 *
 * Offer is the operative word. Turning these on lets the chosen roles set a method up and
 * prompts them to; it does not make anybody unable to sign in without one. The setting that
 * would - `totp_required_roles` - is not on this screen and will not be: requiring a second
 * factor from a wizard, before anybody has enrolled, is how an administrator locks
 * themselves out of the site they installed this on ten minutes ago.
 *
 * The switches are the settings screen's own, so a switch means the same thing in both
 * places, and `recommend` behaves the same way here as it does there: nothing is said while
 * the setting is what it should be, and a note appears once it is not. The wizard opens on
 * the recommended answer, so that note is the wizard telling you what you just turned off.
 */
export default {
    name: 'OnboardingTwoFactor',
    components: {SettingToggle, RoleChoice},
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
        }
    },
    methods: {
        update(key, value) {
            this.answer = {...this.answer, [key]: value};
        },
        validate() {
            if (this.anyOn && !(this.answer.roles || []).length) {
                return this.$t('Choose at least one role.');
            }

            return '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_fields">

        <!--
            Said once above the group rather than badged on every row. The switches use the
            settings screen's `recommend`, which stays quiet while a setting is what it
            should be and speaks up once it is not - right on a settings screen, where the
            reader chose the values, but on a first run nobody has been told where the
            values came from. One line covers that without a badge on each row.
        -->
        <p class="fls_onb_hint">
            {{ $t('The recommended methods are already on. Turn off any you do not want, then choose who gets them.') }}
        </p>

        <div class="fls_onb_opts">
            <div class="fls_onb_opt" :class="{'is-on': answer.totp}">
                <setting-toggle :model-value="answer.totp" :active-value="true" :inactive-value="false"
                                :recommend="true"
                                :label="$t('Authenticator app')"
                                :description="$t('A code from an app on their phone, such as Google Authenticator or Authy. No email needed.')"
                                @update:model-value="v => update('totp', v)"/>
            </div>

            <div class="fls_onb_opt" :class="{'is-on': answer.email}">
                <setting-toggle :model-value="answer.email" :active-value="true" :inactive-value="false"
                                :recommend="true"
                                :label="$t('Emailed code')"
                                :description="$t('A code sent to their email address each time they sign in. Nothing to set up.')"
                                @update:model-value="v => update('email', v)"/>
            </div>
        </div>

        <role-choice v-if="anyOn" :model-value="answer.roles" :user-roles="userRoles"
                     :label="$t('Who gets the second step')"
                     :hint="$t('With emailed codes on, these roles get a code at every sign-in. With an app on, they are invited to set one up after signing in.')"
                     @update:model-value="v => update('roles', v)"/>

        <p class="fls_onb_reassure">
            {{
                $t('Nobody is locked out by this. Setting up an app stays optional until you make it required in Settings.')
            }}
        </p>
    </div>
</template>
