<script type="text/babel">
import StepRail from './_StepRail.vue';
import Stage from './_Stage.vue';
import Connection from './Steps/_Connection.vue';
import TwoFactor from './Steps/_TwoFactor.vue';
import LoginLimit from './Steps/_LoginLimit.vue';
import Hardening from './Steps/_Hardening.vue';
import Alerts from './Steps/_Alerts.vue';
import SummaryScreen from './_Summary.vue';
import ReviewScreen from './_Review.vue';

// Keep answers local until the administrator reviews and applies them.
export default {
    name: 'OnboardingWizard',
    components: {
        StepRail,
        Stage,
        Connection,
        TwoFactor,
        LoginLimit,
        Hardening,
        Alerts,
        SummaryScreen,
        ReviewScreen
    },
    data() {
        return {
            loading: true,
            saving: false,
            steps: [],
            answers: {},
            connection: {},
            recommended: {},
            userRoles: [],
            adminEmail: '',
            siteName: '',
            authSettings: null,
            index: 0,
            // Questions, review, then confirmation after the server applies the choices.
            phase: 'steps',
            applied: [],
            error: '',
            loadError: ''
        };
    },
    computed: {
        /** Which question component draws the current step. */
        stepComponents() {
            return {
                connection: 'Connection',
                two_fa: 'TwoFactor',
                login_limit: 'LoginLimit',
                hardening: 'Hardening',
                alerts: 'Alerts'
            };
        },
        railSteps() {
            return [...this.steps, {id: 'review', title: this.$t('Review')}];
        },
        railIndex() {
            return this.phase === 'review' ? this.steps.length : this.index;
        },
        current() {
            return this.steps[this.index] || null;
        },
        currentComponent() {
            return this.current ? this.stepComponents[this.current.id] : null;
        },
        isLast() {
            return this.index === this.steps.length - 1;
        },
        canGoBack() {
            return this.phase === 'review' || this.index > 0;
        },
        /**
         * The connection step refuses to be waved past in the one state where waving past
         * it breaks everything after it - see ProxyDetection::isAmbiguous(). Everywhere
         * else, and on every other screen, leaving is always available.
         */
        canLeave() {
            return !this.current || this.current.skippable;
        }
    },
    methods: {
        load() {
            this.loading = true;
            this.loadError = '';

            this.$get('onboarding')
                .then(response => {
                    this.steps = response.steps || [];
                    this.connection = response.connection || {};
                    this.recommended = response.recommended || {};
                    this.userRoles = response.user_roles || [];
                    this.adminEmail = response.admin_email || '';
                    this.siteName = response.site_name || '';

                    const answers = {};
                    this.steps.forEach(step => {
                        answers[step.id] = JSON.parse(JSON.stringify(step.answer));
                    });
                    this.answers = answers;
                    if (!this.steps.length) {
                        this.loadError = this.$t('No setup steps are available. Please try again.');
                    }
                })
                .catch(error => {
                    this.loadError = (error && error.message) || this.$t('Unable to load setup. Check your connection and try again.');
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /**
         * The login page as it is actually styled, so the preview beside every question is
         * this site's sign-in screen rather than a drawing of a generic one. Fetched
         * separately because it is the only thing on this screen the wizard does not own,
         * and a slow response for it should not hold up the questions.
         */
        loadAuthSettings() {
            this.$get('auth-customizer')
                .then(response => {
                    this.authSettings = response.settings;
                })
                .catch(() => {
                    // The preview falls back to plain styling; nothing here is worth an error.
                });
        },
        goNext() {
            if (this.loading || this.saving || !this.current || this.phase !== 'steps') {
                return;
            }

            this.error = '';

            const problem = this.$refs.step && this.$refs.step.validate
                ? this.$refs.step.validate()
                : '';

            if (problem) {
                this.error = problem;
                return;
            }

            if (!this.isLast) {
                this.index++;
                this.scrollUp();
                return;
            }

            this.phase = 'review';
            this.scrollUp();
        },
        goBack() {
            if (this.saving || !this.canGoBack) {
                return;
            }

            this.error = '';
            if (this.phase === 'review') {
                this.phase = 'steps';
                this.index = this.steps.length - 1;
            } else {
                this.index--;
            }
            this.scrollUp();
        },
        jumpTo(index) {
            // Only backwards. Skipping ahead past an unanswered question is how a wizard
            // ends up applying a default nobody read.
            if (!this.saving && index >= 0 && index < this.railIndex) {
                this.phase = 'steps';
                this.error = '';
                this.index = index;
                this.scrollUp();
            }
        },
        finish() {
            if (this.saving || this.phase !== 'review') {
                return;
            }

            this.saving = true;
            this.error = '';

            this.$post('onboarding/complete', {answers: this.answers})
                .then(response => {
                    this.applied = response.applied || [];
                    this.phase = 'done';
                    this.appVars.is_onboarding = false;
                    this.scrollUp();
                })
                .catch(error => {
                    this.error = (error && error.message) || this.$t('Something is wrong!');
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        leave() {
            if (this.saving || this.loading || !this.canLeave) {
                return;
            }

            this.saving = true;

            this.$post('onboarding/skip')
                .then(() => {
                    this.appVars.is_onboarding = false;
                    this.$router.push({name: 'dashboard'});
                })
                .catch(error => this.$handleError(error))
                .finally(() => {
                    this.saving = false;
                });
        },
        scrollUp() {
            this.$nextTick(() => {
                const heading = this.$el.querySelector('h1');
                if (heading) heading.focus({preventScroll: true});
                window.scrollTo({top: 0, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});
            });
        }
    },
    created() {
        this.load();
        this.loadAuthSettings();
    }
};
</script>

<template>
    <div class="fls_onb">
        <header class="fls_onb_bar">
            <div class="fls_onb_bar_brand">
                <img :src="appVars.asset_url + '/images/logo.png'" alt="FluentAuth"/>
                <span>{{ $t('Security setup') }}</span>
            </div>
            <div class="fls_onb_bar_end">
                <el-button v-if="phase !== 'done' && canLeave" text :disabled="saving || loading"
                           class="fls_onb_leave" @click="leave">
                    {{ $t('Set up later') }} <span aria-hidden="true">↗</span>
                </el-button>
            </div>
        </header>

        <nav v-if="!loading && !loadError && phase !== 'done'" class="fls_onb_progress" :aria-label="$t('Setup progress')">
            <step-rail :steps="railSteps" :index="railIndex" :disabled="saving" @jump="jumpTo"/>
        </nav>

        <div v-if="loading" class="fls_onb_loading" role="status" :aria-label="$t('Loading setup')">
            <el-skeleton :animated="true" :rows="8"/>
        </div>

        <div v-else-if="loadError" class="fls_onb_load_error">
            <h1 tabindex="-1">{{ $t('Setup could not be loaded') }}</h1>
            <p role="alert">{{ loadError }}</p>
            <el-button type="primary" @click="load">{{ $t('Try again') }}</el-button>
        </div>

        <summary-screen v-else-if="phase === 'done'" :applied="applied" :steps="steps"/>

        <review-screen v-else-if="phase === 'review'" :steps="steps" :answers="answers"
                       :user-roles="userRoles" :admin-email="adminEmail" :connection="connection"
                       :saving="saving" :error="error" @edit="jumpTo" @back="goBack" @finish="finish"/>

        <main v-else-if="current" class="fls_onb_body">
            <form class="fls_onb_ask" @submit.prevent="goNext">
                <div :key="current.id" class="fls_onb_ask_inner">
                    <p class="fls_eyebrow">{{ $t('Step %s of %s', index + 1, railSteps.length) }} <span aria-hidden="true"> / </span> {{ current.title }}</p>
                    <h1 class="fls_onb_headline" tabindex="-1">{{ current.headline }}</h1>
                    <p class="fls_onb_why">{{ current.why }}</p>

                    <component :is="currentComponent" ref="step" v-model="answers[current.id]"
                               :step="current" :connection="connection" :recommended="recommended"
                               :user-roles="userRoles" :admin-email="adminEmail"/>

                    <div v-if="error" class="fls_errors" role="alert">{{ error }}</div>
                    <div class="fls_onb_actions">
                        <el-button v-if="canGoBack" text class="fls_onb_back" :disabled="saving" @click="goBack">
                            <span aria-hidden="true">←</span> {{ $t('Back') }}
                        </el-button>
                        <el-button type="primary" native-type="submit" class="fls_onb_next" :loading="saving">
                            {{ isLast ? $t('Review settings') : $t('Continue') }} <span aria-hidden="true">→</span>
                        </el-button>
                    </div>
                    <p class="fls_onb_save_note">{{ $t('Nothing is saved until you review and apply it at the end.') }}</p>
                </div>
            </form>
            <aside class="fls_onb_stage" :aria-label="$t('Preview')">
                <div class="fls_onb_preview_label"><span class="dashicons dashicons-visibility" aria-hidden="true"></span>{{ $t('Preview') }}</div>
                <stage :step="current" :answer="answers[current.id]" :connection="connection"
                       :auth-settings="authSettings" :site-name="siteName" :admin-email="adminEmail" :user-roles="userRoles"/>
                <p class="fls_onb_preview_hint">{{ $t('Updates as you make your choices.') }}</p>
            </aside>
        </main>
    </div>
</template>
