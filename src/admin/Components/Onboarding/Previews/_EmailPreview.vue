<script type="text/babel">
/**
 * The sign-in alert, as it will land in somebody's inbox.
 *
 * The alerts question is really a question about a mailbox: whether these are worth
 * receiving depends entirely on how many of them there will be and what they say. So the
 * message is shown rather than described, addressed to the address that was chosen, with
 * the roles that were chosen naming who sets one off.
 */
export default {
    name: 'EmailPreview',
    props: {
        answer: {
            type: Object,
            default: () => ({})
        },
        siteName: {
            type: String,
            default: ''
        },
        adminEmail: {
            type: String,
            default: ''
        },
        /** So the example account can be one of the roles actually being alerted on. */
        userRoles: {
            type: Array,
            default: () => []
        }
    },
    computed: {
        /*
         * The first role chosen, named the way this site names it. An example showing an
         * address for one role beside the title of another is the kind of small
         * incoherence that makes a reader stop trusting the whole preview.
         */
        exampleRole() {
            const chosen = (this.answer.roles || [])[0];
            const match = this.userRoles.find(role => role.id === chosen);

            return match ? match.title : this.$t('Administrator');
        },
        exampleAccount() {
            const chosen = (this.answer.roles || [])[0] || 'administrator';

            return chosen.replace(/[^a-z0-9]+/gi, '.').toLowerCase() + '@example.com';
        },
        /** `{admin_email}` is the shipped default and resolves at send time. */
        recipient() {
            const chosen = (this.answer.email || '').trim();

            if (!chosen || chosen === '{admin_email}') {
                return this.adminEmail;
            }

            return chosen;
        },
        site() {
            return this.siteName || this.$t('your site');
        },
        enabled() {
            return !!this.answer.enabled && (this.answer.roles || []).length > 0;
        },
        when() {
            const now = new Date();

            return now.toLocaleString(undefined, {
                hour: 'numeric',
                minute: '2-digit',
                day: 'numeric',
                month: 'short'
            });
        }
    }
};
</script>

<template>
    <div class="fls_onb_mail" :class="{'is-off': !enabled}">
        <div class="fls_onb_mail_head">
            <p class="fls_onb_mail_subject">
                {{ $t('New sign-in to %s', site) }}
            </p>
            <dl class="fls_onb_mail_meta">
                <div>
                    <dt>{{ $t('To') }}</dt>
                    <dd>{{ recipient || $t('your administrator address') }}</dd>
                </div>
                <div>
                    <dt>{{ $t('When') }}</dt>
                    <dd>{{ when }}</dd>
                </div>
            </dl>
        </div>

        <div class="fls_onb_mail_body">
            <p>{{ $t('Someone just signed in to %s.', site) }}</p>

            <dl class="fls_onb_mail_facts">
                <div>
                    <dt>{{ $t('Account') }}</dt>
                    <dd>{{ exampleAccount }}</dd>
                </div>
                <div>
                    <dt>{{ $t('Role') }}</dt>
                    <dd>{{ exampleRole }}</dd>
                </div>
                <div>
                    <dt>{{ $t('Address') }}</dt>
                    <dd>203.0.113.42</dd>
                </div>
                <div>
                    <dt>{{ $t('Method') }}</dt>
                    <dd>{{ $t('Login form') }}</dd>
                </div>
            </dl>

            <p class="fls_onb_mail_tail">
                {{ $t('If this was not you, change the password on that account now.') }}
            </p>
        </div>

        <p v-if="!enabled" class="fls_onb_mail_off">
            {{ $t('No alerts will be sent.') }}
        </p>
    </div>
</template>
