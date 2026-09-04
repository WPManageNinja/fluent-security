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
                return this.$t('Choose at least one role to offer this to.');
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
            {{ $t('Set to what we recommend. Turn off anything this site does not need.') }}
        </p>

        <div class="fls_onb_opts">
            <div class="fls_onb_opt" :class="{'is-on': answer.totp}">
                <setting-toggle :model-value="answer.totp" :active-value="true" :inactive-value="false"
                                :recommend="true"
                                :label="$t('Authenticator app')"
                                :description="$t('A code from an app on their phone. It works with no signal, and it cannot be read out of an inbox.')"
                                @update:model-value="v => update('totp', v)"/>
            </div>

            <div class="fls_onb_opt" :class="{'is-on': answer.email}">
                <setting-toggle :model-value="answer.email" :active-value="true" :inactive-value="false"
                                :recommend="true"
                                :label="$t('Emailed code')"
                                :description="$t('Nothing to install. Worth having on as well, so nobody is stuck when they change phone.')"
                                @update:model-value="v => update('email', v)"/>
            </div>
        </div>

        <role-choice v-if="anyOn" :model-value="answer.roles" :user-roles="userRoles"
                     :label="$t('Offer it to')"
                     :hint="$t('These roles are asked to set a method up the next time they sign in.')"
                     @update:model-value="v => update('roles', v)"/>

        <p class="fls_onb_reassure">
            {{
                $t('This does not lock anyone out. The roles you pick are asked to set a method up. Nobody is refused a sign-in for not having one.')
            }}
        </p>
    </div>
</template>
