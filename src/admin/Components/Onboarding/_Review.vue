<script type="text/babel">
import digestFrequencies from '@/Bits/digestFrequencies';

export default {
    name: 'OnboardingReview',
    emits: ['edit', 'back', 'finish'],
    props: {
        steps: {type: Array, default: () => []},
        answers: {type: Object, default: () => ({})},
        userRoles: {type: Array, default: () => []},
        adminEmail: {type: String, default: ''},
        connection: {type: Object, default: () => ({})},
        saving: Boolean,
        error: {type: String, default: ''}
    },
    methods: {
        roles(ids = []) {
            return ids.map(id => {
                const role = this.userRoles.find(role => role.id === id);
                return role ? role.title : id;
            }).join(', ');
        },
        details(step) {
            const answer = this.answers[step.id] || {};
            switch (step.id) {
                case 'connection': {
                    const header = answer.proxy_ip_header || this.$t('Automatic');
                    if (this.connection.config_locked) return [this.$t('Managed in wp-config.php')];
                    return answer.mode === 'proxy'
                        ? [/* translators: %s is the list of trusted proxy addresses */ this.$t('Proxy address: %s', answer.trusted_proxies), /* translators: %s is the HTTP header name the visitor IP is read from, or Automatic */ this.$t('IP header: %s', header)]
                        : [this.$t('Your address is correct. Nothing to change.')];
                }
                case 'two_fa': {
                    const methods = [];
                    if (answer.totp) methods.push(this.$t('Authenticator app'));
                    if (answer.email) methods.push(this.$t('Emailed code'));
                    if (answer.passkey && this.appVars.passkey_supported) methods.push(this.$t('Passkey'));
                    return methods.length
                        ? [methods.join(' + '), /* translators: %s is a comma-separated list of user roles */ this.$t('Offered to: %s', this.roles(answer.roles))]
                        : [this.$t('No second step')];
                }
                case 'login_limit':
                    // translators: %1$s is the number of failed sign-in attempts, %2$s the number of minutes
                    return [this.$t('%1$s failed attempts within %2$s minutes', answer.limit, answer.timing)];
                case 'hardening':
                    return (step.checks || []).map(check => /* translators: %1$s is the name of a security setting, %2$s is On or Off */ this.$t('%1$s: %2$s', check.title, answer[check.key] ? this.$t('On') : this.$t('Off')));
                case 'alerts': {
                    const lines = [answer.enabled
                        ? /* translators: %s is a comma-separated list of user roles whose sign-ins trigger an alert */ this.$t('Sign-ins by: %s', this.roles(answer.roles))
                        : this.$t('Sign-in alerts off')];
                    lines.push(answer.digest
                        ? /* translators: %s is how often the summary report is sent, such as Weekly */ this.$t('Summary report: %s', digestFrequencies(this.$t)[answer.digest] || answer.digest)
                        : this.$t('No summary report'));
                    if (answer.enabled || answer.digest) {
                        lines.push(/* translators: %s is an email address */ this.$t('Send to: %s', !answer.email || answer.email === '{admin_email}' ? this.adminEmail : answer.email));
                    }
                    return lines;
                }
                default:
                    return [];
            }
        }
    }
};
</script>

<template>
    <main class="fls_onb_review">
        <p class="fls_eyebrow">{{ $t('Ready to apply') }}</p>
        <h1 class="fls_onb_headline" tabindex="-1">{{ $t('Does this look right?') }}</h1>
        <p class="fls_onb_why">{{ $t('Nothing is saved until you apply these.') }}</p>
        <ol class="fls_onb_review_list">
            <li v-for="(step, i) in steps" :key="step.id">
                <span class="fls_onb_review_number" aria-hidden="true">{{ i + 1 }}</span>
                <div>
                    <h2>{{ step.title }}</h2>
                    <p v-for="(line, j) in details(step)" :key="j">{{ line }}</p>
                </div>
                <el-button text :disabled="saving" :aria-label="/* translators: %s is the name of a setup step */ $t('Edit %s', step.title)" @click="$emit('edit', i)">{{ $t('Edit') }}</el-button>
            </li>
        </ol>
        <div v-if="error" class="fls_errors" role="alert">{{ error }}</div>
        <div class="fls_onb_actions">
            <el-button text :disabled="saving" @click="$emit('back')"><span aria-hidden="true">←</span> {{ $t('Back') }}</el-button>
            <el-button type="primary" class="fls_onb_next" :loading="saving" @click="$emit('finish')">{{ $t('Apply settings') }} <span aria-hidden="true">→</span></el-button>
        </div>
        <p class="fls_onb_save_note">{{ $t('You can change any of this later in Settings.') }}</p>
    </main>
</template>
