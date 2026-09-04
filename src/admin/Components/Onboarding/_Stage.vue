<script type="text/babel">
import AuthFormPreview from '../AuthCustomizer/_AuthFormPreview.vue';
import ConnectionPreview from './Previews/_ConnectionPreview.vue';
import EmailPreview from './Previews/_EmailPreview.vue';

/**
 * What the person signing in will actually see, beside the question that changes it.
 *
 * This is the whole argument for the screen. A toggle labelled "email codes" tells an
 * administrator what the setting is called; it does not tell them their users are about to
 * meet a second screen asking for a six digit number. So every question is answered next to
 * the page it changes - and the page is drawn from this site's own login design, not a
 * picture of a generic one, because the component doing the drawing is the same one the
 * login customizer paints with.
 *
 * It follows the answer rather than a toggle of its own: turn email codes off and the code
 * step disappears from the preview. A preview that has to be flipped by hand is a picture
 * of a feature, and this is meant to be a picture of a decision.
 */
export default {
    name: 'OnboardingStage',
    components: {
        AuthFormPreview,
        ConnectionPreview,
        EmailPreview
    },
    props: {
        step: {
            type: Object,
            required: true
        },
        answer: {
            type: Object,
            default: () => ({})
        },
        connection: {
            type: Object,
            default: () => ({})
        },
        /** The login customizer's saved design, or null until it has been fetched. */
        authSettings: {
            type: Object,
            default: null
        },
        siteName: {
            type: String,
            default: ''
        },
        adminEmail: {
            type: String,
            default: ''
        },
        userRoles: {
            type: Array,
            default: () => []
        }
    },
    computed: {
        kind() {
            return this.step.preview;
        },
        tab() {
            return this.kind === 'signup' ? 'signup' : 'login';
        },
        /**
         * The customizer's design for this tab. Falls back to an empty shape so the preview
         * renders as an unstyled login form rather than not at all - a site that has never
         * opened the designer still has a login page worth showing.
         */
        design() {
            const settings = this.authSettings && this.authSettings[this.tab];

            return settings || {banner: {hidden: true}, form: {}};
        },
        /** Whether this step's answer currently turns its protection on. */
        isOn() {
            if (this.kind === 'two_factor') {
                return !!(this.answer.totp || this.answer.email);
            }

            if (this.kind === 'signup') {
                return !!this.answer.secure_signup_form;
            }

            return true;
        },
        /**
         * The second step at sign-in, once the password has been accepted. Shown as the
         * screen it really is rather than as an extra field on the first one, because that
         * is the part an administrator has not pictured.
         */
        twoFactorFields() {
            if (!this.isOn) {
                return null;
            }

            return [
                {
                    type: 'text',
                    label: this.$t('Authentication code'),
                    placeholder: '● ● ● ● ● ●'
                }
            ];
        },
        twoFactorNotice() {
            if (this.answer.totp && this.answer.email) {
                return this.$t('Open your authenticator app, or use the code we emailed you.');
            }

            if (this.answer.totp) {
                return this.$t('Open your authenticator app and enter the code it shows.');
            }

            return this.$t('We have emailed you a code. It expires in a few minutes.');
        },
        /** How long an address is locked out for, said the way the notice says it. */
        lockoutMinutes() {
            return parseInt(this.answer.timing, 10) || 30;
        },
        lockoutAttempts() {
            return parseInt(this.answer.limit, 10) || 5;
        },
        signupFields() {
            if (!this.isOn) {
                return null;
            }

            return [
                {
                    type: 'text',
                    label: this.$t('Verification code'),
                    placeholder: '● ● ● ● ● ●'
                }
            ];
        },
        caption() {
            const captions = {
                connection: this.$t('What this site currently sees'),
                two_factor: this.isOn
                    ? this.$t('After the password — what your users will see')
                    : this.$t('Sign-in ends at the password'),
                lockout: this.$t('After too many failed attempts'),
                signup: this.isOn
                    ? this.$t('Creating an account — the verification step')
                    : this.$t('Creating an account'),
                email: this.$t('The alert, as it arrives')
            };

            return captions[this.kind] || '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_stage_inner">
        <p class="fls_onb_stage_cap">{{ caption }}</p>

        <connection-preview v-if="kind === 'connection'"
                            :connection="connection" :answer="answer"/>

        <email-preview v-else-if="kind === 'email'"
                       :answer="answer" :site-name="siteName" :admin-email="adminEmail"
                       :user-roles="userRoles"/>

        <div v-else class="fls_onb_screen" :class="{'is-off': !isOn}">
            <div class="fls_onb_chrome" aria-hidden="true">
                <span class="fls_onb_dot"></span>
                <span class="fls_onb_dot"></span>
                <span class="fls_onb_dot"></span>
                <span class="fls_onb_url">{{ appVars.site_url }}wp-login.php</span>
            </div>

            <div class="fls_onb_screen_body">

                <!-- Two-factor: the second screen, once a password has been accepted. -->
                <auth-form-preview v-if="kind === 'two_factor'"
                                   :settings="design" tab="login"
                                   :fields="twoFactorFields"
                                   :button-label="isOn ? $t('Verify') : ''">
                    <template v-if="isOn" #notice>
                        <div class="fls_onb_note is-info">{{ twoFactorNotice }}</div>
                    </template>
                    <template v-if="isOn" #after-form>
                        <div class="fs_form_extra" style="margin-top: 40px; display: block;">
                            <p>{{ $t('Use a different method') }}</p>
                        </div>
                    </template>
                </auth-form-preview>

                <!-- The attempt limit, shown as the message it produces. -->
                <auth-form-preview v-else-if="kind === 'lockout'"
                                   :settings="design" tab="login">
                    <template #notice>
                        <div class="fls_onb_note is-blocked">
                            {{
                                $t('Too many failed attempts. Try again in %s minutes.', lockoutMinutes)
                            }}
                        </div>
                    </template>
                </auth-form-preview>

                <!-- Signup, with or without the verification step in front of it. -->
                <auth-form-preview v-else-if="kind === 'signup'"
                                   :settings="design" tab="signup"
                                   :fields="signupFields"
                                   :button-label="isOn ? $t('Confirm email address') : ''">
                    <template v-if="isOn" #notice>
                        <div class="fls_onb_note is-info">
                            {{ $t('Check your inbox — we sent a code to confirm the address is yours.') }}
                        </div>
                    </template>
                </auth-form-preview>
            </div>
        </div>

        <p v-if="kind === 'lockout'" class="fls_onb_stage_foot">
            {{
                $t('Shown after %s failed attempts within %s minutes.', lockoutAttempts, lockoutMinutes)
            }}
        </p>
    </div>
</template>
