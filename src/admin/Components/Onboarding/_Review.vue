<script type="text/babel">
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
                        ? [this.$t('Trusted proxies: %s', answer.trusted_proxies), this.$t('IP header: %s', header)]
                        : [this.$t('Direct connection')];
                }
                case 'two_fa': {
                    const methods = [];
                    if (answer.totp) methods.push(this.$t('Authenticator app'));
                    if (answer.email) methods.push(this.$t('Emailed code'));
                    return methods.length
                        ? [methods.join(' + '), this.$t('Offered to: %s', this.roles(answer.roles))]
                        : [this.$t('Authenticator apps and emailed codes off')];
                }
                case 'login_limit':
                    return [this.$t('%s failed attempts within %s minutes', answer.limit, answer.timing)];
                case 'hardening':
                    return (step.checks || []).map(check => this.$t('%s: %s', check.title, answer[check.key] ? this.$t('On') : this.$t('Off')));
                case 'alerts':
                    return answer.enabled
                        ? [this.$t('Sign-ins by: %s', this.roles(answer.roles)), this.$t('Send to: %s', !answer.email || answer.email === '{admin_email}' ? this.adminEmail : answer.email)]
                        : [this.$t('Sign-in alerts off')];
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
        <h1 class="fls_onb_headline" tabindex="-1">{{ $t('Review your security settings') }}</h1>
        <p class="fls_onb_why">{{ $t('Check your choices below. Nothing has been saved yet.') }}</p>
        <ol class="fls_onb_review_list">
            <li v-for="(step, i) in steps" :key="step.id">
                <span class="fls_onb_review_number" aria-hidden="true">{{ i + 1 }}</span>
                <div>
                    <h2>{{ step.title }}</h2>
                    <p v-for="(line, j) in details(step)" :key="j">{{ line }}</p>
                </div>
                <el-button text :disabled="saving" :aria-label="$t('Edit %s', step.title)" @click="$emit('edit', i)">{{ $t('Edit') }}</el-button>
            </li>
        </ol>
        <div v-if="error" class="fls_errors" role="alert">{{ error }}</div>
        <div class="fls_onb_actions">
            <el-button text :disabled="saving" @click="$emit('back')"><span aria-hidden="true">←</span> {{ $t('Back') }}</el-button>
            <el-button type="primary" class="fls_onb_next" :loading="saving" @click="$emit('finish')">{{ $t('Apply settings') }} <span aria-hidden="true">→</span></el-button>
        </div>
        <p class="fls_onb_save_note">{{ $t('You can change these settings later in FluentAuth.') }}</p>
    </main>
</template>
