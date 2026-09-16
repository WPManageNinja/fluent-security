<script type="text/babel">
import SettingToggle from '../../Settings/_SettingToggle.vue';
import RoleChoice from './_RoleChoice.vue';

/**
 * Who gets emailed when a privileged account signs in, and where.
 *
 * The checklist carries this as advice rather than as a scored item, for a reason that
 * belongs on this screen too: alerts on roles that sign in all day fill a mailbox with
 * sign-ins nobody reads, and the one that mattered then arrives in a folder somebody wrote
 * a filter for. So the roles are chosen rather than assumed, and turning it off entirely is
 * a first-class answer rather than something to be talked out of.
 */
export default {
    name: 'OnboardingAlerts',
    components: {SettingToggle, RoleChoice},
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: Object,
            required: true
        },
        userRoles: {
            type: Array,
            default: () => []
        },
        adminEmail: {
            type: String,
            default: ''
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
        /** Shown in the field so the default reads as an address, not as a token. */
        emailValue() {
            const value = this.answer.email;

            return !value || value === '{admin_email}' ? '' : value;
        }
    },
    methods: {
        update(key, value) {
            this.answer = {...this.answer, [key]: value};
        },
        updateEmail(value) {
            // An empty field means "the site's administrator address", which is what the
            // shipped default already says. Storing the token keeps it following the site.
            this.update('email', (value || '').trim() || '{admin_email}');
        },
        validate() {
            if (!this.answer.enabled) {
                return '';
            }

            if (!(this.answer.roles || []).length) {
                return this.$t('Choose at least one role, or turn alerts off.');
            }

            const email = (this.answer.email || '').trim();

            if (email && email !== '{admin_email}' && email.indexOf('@') === -1) {
                return this.$t('That does not look like an email address.');
            }

            return '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_fields">

        <div class="fls_onb_opts">
            <div class="fls_onb_opt" :class="{'is-on': answer.enabled}">
                <setting-toggle :model-value="answer.enabled"
                                :active-value="true" :inactive-value="false"
                                :label="$t('Email me about sign-ins')"
                                :description="$t('One message per sign-in, for the roles you pick below.')"
                                @update:model-value="v => update('enabled', v)"/>
            </div>
        </div>

        <template v-if="answer.enabled">
            <role-choice :model-value="answer.roles" :user-roles="userRoles"
                         :label="$t('Tell me when these roles sign in')"
                         :hint="$t('Keep it to administrators and other powerful accounts. Alerts for roles that sign in all day stop getting read.')"
                         @update:model-value="v => update('roles', v)"/>

            <div class="fls_onb_field">
                <label class="fls_onb_label" for="fls_onb_email">{{ $t('Send them to') }}</label>
                <el-input id="fls_onb_email" type="email" :model-value="emailValue"
                          :placeholder="adminEmail"
                          @update:model-value="updateEmail"/>
                <p class="fls_onb_hint">
                    {{ $t('Leave empty to use the site\'s admin email address.') }}
                </p>
            </div>
        </template>
    </div>
</template>
