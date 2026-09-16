<script type="text/babel">
/**
 * WordPress's own login page, for a site that has not switched the customizer on.
 *
 * The wizard previews every question against the sign-in screen it changes. On a site
 * where the login customizer is off, that screen is wp-login.php as WordPress ships it -
 * the grey page, the logo, the white box - and showing the customizer's design there would
 * be a picture of a page no visitor will ever see. So this draws the stock page instead,
 * with the same slots and props as AuthFormPreview, and the stage swaps between the two on
 * the customizer's status alone.
 *
 * It is a drawing, not the real markup: the sizes and colours are wp-admin's login.css
 * read across by hand, at the canvas size the stage scales everything else to.
 */
export default {
    name: 'WpLoginPreview',
    props: {
        tab: {
            type: String,
            default: 'login'
        },
        /** Replaces the shipped field list, for a screen showing a different step. */
        fields: {
            type: Array,
            default: null
        },
        /** Overrides the submit button's label. */
        buttonLabel: {
            type: String,
            default: ''
        }
    },
    computed: {
        submitLabel() {
            if (this.buttonLabel) {
                return this.buttonLabel;
            }

            return this.tab == 'login' ? this.$t('Log In') : this.$t('Register');
        },
        currentFields() {
            if (this.fields) {
                return this.fields;
            }

            if (this.tab == 'signup') {
                return [
                    {type: 'text', label: this.$t('Username')},
                    {type: 'email', label: this.$t('Email')}
                ];
            }

            return [
                {type: 'text', label: this.$t('Username or Email Address')},
                {type: 'password', label: this.$t('Password')},
                {type: 'inline_checkbox', inline_label: this.$t('Remember Me')}
            ];
        },
        /* Only the stock register form carries WordPress's note about the confirmation email. */
        showsPassmail() {
            return this.tab == 'signup' && !this.fields;
        }
    }
};
</script>

<template>
    <div class="fls_onb_wp">
        <div class="fls_onb_wp_login">
            <h1 class="fls_onb_wp_logo" aria-hidden="true">
                <svg viewBox="0 0 64 64" width="84" height="84">
                    <path fill="#3c434a" d="M4.548 31.999c0 10.9 6.3 20.3 15.5 24.706L6.925 20.827C5.402 24.2 4.5 28 4.5 31.999zM50.531 30.614c0-3.394-1.219-5.742-2.264-7.57c-1.391-2.263-2.695-4.177-2.695-6.439c0-2.523 1.912-4.872 4.609-4.872c0.121 0 0.2 0 0.4 0.022C45.653 7.3 39.1 4.5 32 4.548c-9.591 0-18.027 4.921-22.936 12.4c0.645 0 1.3 0 1.8 0.033c2.871 0 7.316-0.349 7.316-0.349c1.479-0.086 1.7 2.1 0.2 2.3c0 0-1.487 0.174-3.142 0.261l9.997 29.735l6.008-18.017l-4.276-11.718c-1.479-0.087-2.879-0.261-2.879-0.261c-1.48-0.087-1.306-2.349 0.174-2.262c0 0 4.5 0.3 7.2 0.349c2.87 0 7.317-0.349 7.317-0.349c1.479-0.086 1.7 2.1 0.2 2.262c0 0-1.489 0.174-3.142 0.261l9.92 29.508l2.739-9.148C49.628 35.7 50.5 33 50.5 30.614zM32.481 34.4l-8.237 23.934c2.46 0.7 5.1 1.1 7.8 1.1c3.197 0 6.262-0.552 9.116-1.556c-0.072-0.118-0.141-0.243-0.196-0.379L32.481 34.4zM56.088 18.8c0.119 0.9 0.2 1.8 0.2 2.823c0 2.785-0.521 5.916-2.088 9.832l-8.385 24.242c8.161-4.758 13.65-13.6 13.65-23.728C59.451 27.2 58.2 22.7 56.1 18.83zM32 0c-17.645 0-32 14.355-32 32C0 49.6 14.4 64 32 64s32-14.355 32-32.001C64 14.4 49.6 0 32 0zM32 62.533c-16.835 0-30.533-13.698-30.533-30.534C1.467 15.2 15.2 1.5 32 1.5s30.534 13.7 30.5 30.532C62.533 48.8 48.8 62.5 32 62.533z"/>
                </svg>
            </h1>

            <slot name="notice"/>

            <div class="fls_onb_wp_form">
                <template v-for="(field, index) in currentFields" :key="index">
                    <p v-if="field.type == 'inline_checkbox'" class="fls_onb_wp_check">
                        <span class="fls_onb_wp_box"></span>{{ field.inline_label }}
                    </p>
                    <p v-else>
                        <label>{{ field.label }}</label>
                        <span class="fls_onb_wp_input">{{ field.placeholder || '' }}</span>
                    </p>
                </template>

                <p v-if="showsPassmail" class="fls_onb_wp_passmail">
                    {{ $t('Registration confirmation will be emailed to you.') }}
                </p>

                <p class="fls_onb_wp_submit">
                    <span class="fls_onb_wp_button">{{ submitLabel }}</span>
                </p>
            </div>

            <div class="fls_onb_wp_nav">
                <slot name="after-form">
                    <p v-if="tab == 'login'">{{ $t('Lost your password?') }}</p>
                    <p v-else>{{ $t('Log in | Lost your password?') }}</p>
                </slot>
            </div>
            <p class="fls_onb_wp_back">{{ $t('← Go to Website') }}</p>
        </div>
    </div>
</template>
