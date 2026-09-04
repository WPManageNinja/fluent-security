<script type="text/babel">
import StepRail from './_StepRail.vue';
import Stage from './_Stage.vue';
import Connection from './Steps/_Connection.vue';
import TwoFactor from './Steps/_TwoFactor.vue';
import LoginLimit from './Steps/_LoginLimit.vue';
import Hardening from './Steps/_Hardening.vue';
import Alerts from './Steps/_Alerts.vue';
import SummaryScreen from './_Summary.vue';

/**
 * The first run.
 *
 * A new install has every protection off and a checklist explaining what is wrong, which
 * is a to-do list handed to somebody who has not been told what the words mean yet. This
 * walks through the same list one question at a time, showing what each answer does to the
 * page the site's own users sign in on.
 *
 * Three things this holds to, none of which the wizards it was measured against manage:
 *
 * - You can always see how much is left. The rail names every step and marks where you
 *   are, so it reads as a short list of questions rather than a funnel of unknown depth.
 *
 * - You can always leave. `Set this up later` sits in the header on every screen and
 *   writes nothing. A wizard you cannot leave is a wizard people uninstall.
 *
 * - Nothing is written until the end. Answers are held here and posted once, so closing
 *   the tab half way through leaves the site exactly as it was rather than partly
 *   configured in a way nobody chose. The server enforces the same thing - see the
 *   Onboarding service - because a rule that only exists in a browser is not a rule.
 *
 * The steps and the values they open on come from the server, so what the wizard
 * recommends and what the security checklist scores are the same answer.
 */
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
        SummaryScreen
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
            // `steps` while questions are being answered, then `done` once they are applied.
            phase: 'steps',
            applied: [],
            error: ''
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
            return this.index > 0;
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
                })
                .catch(error => this.$handleError(error))
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

            this.finish();
        },
        goBack() {
            if (!this.canGoBack) {
                return;
            }

            this.error = '';
            this.index--;
            this.scrollUp();
        },
        jumpTo(index) {
            // Only backwards. Skipping ahead past an unanswered question is how a wizard
            // ends up applying a default nobody read.
            if (index < this.index) {
                this.error = '';
                this.index = index;
                this.scrollUp();
            }
        },
        finish() {
            this.saving = true;
            this.error = '';

            this.$post('onboarding/complete', {answers: this.answers})
                .then(response => {
                    this.applied = response.applied || [];
                    this.phase = 'done';
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
            window.scrollTo({top: 0, behavior: 'smooth'});
        },
        /**
         * Enter moves on, the way it would in any form - but not while the caret is in a
         * textarea, and not from a button, which has its own meaning for the key.
         */
        onKeydown(event) {
            if (event.key !== 'Enter' || this.phase !== 'steps' || this.saving) {
                return;
            }

            const tag = (event.target.tagName || '').toLowerCase();

            if (tag === 'textarea' || tag === 'button' || tag === 'a') {
                return;
            }

            event.preventDefault();
            this.goNext();
        }
    },
    created() {
        this.load();
        this.loadAuthSettings();
    },
    mounted() {
        document.addEventListener('keydown', this.onKeydown);
    },
    beforeUnmount() {
        document.removeEventListener('keydown', this.onKeydown);
        // Whatever happened here, the app should not bounce back into the wizard.
        this.appVars.is_onboarding = false;
    }
};
</script>

<template>
    <div class="fls_onb">

        <header class="fls_onb_bar">
            <div class="fls_onb_bar_brand">
                <img :src="appVars.asset_url + '/images/logo.png'" alt="FluentAuth"/>
                <span>{{ $t('Setup') }}</span>
            </div>

            <step-rail v-if="phase === 'steps' && steps.length"
                       :steps="steps" :index="index" @jump="jumpTo"/>

            <div class="fls_onb_bar_end">
                <el-button v-if="phase === 'steps' && canLeave" text :disabled="saving"
                           class="fls_onb_leave" @click="leave">
                    {{ $t('Set this up later') }}
                </el-button>
            </div>
        </header>

        <div v-if="loading" class="fls_onb_loading">
            <el-skeleton :animated="true" :rows="8"/>
        </div>

        <summary-screen v-else-if="phase === 'done'" :applied="applied" :steps="steps"/>

        <div v-else-if="current" class="fls_onb_body">

            <div class="fls_onb_stage">
                <stage :step="current" :answer="answers[current.id]"
                       :connection="connection" :auth-settings="authSettings"
                       :site-name="siteName" :admin-email="adminEmail"
                       :user-roles="userRoles"/>
            </div>

            <div class="fls_onb_ask">
                <div class="fls_onb_ask_inner">
                    <p class="fls_onb_count">
                        {{ $t('Step %s of %s', index + 1, steps.length) }}
                    </p>

                    <h1 class="fls_onb_headline">{{ current.headline }}</h1>

                    <p class="fls_onb_why">{{ current.why }}</p>

                    <component :is="currentComponent" ref="step"
                               v-model="answers[current.id]"
                               :step="current" :connection="connection"
                               :recommended="recommended" :user-roles="userRoles"
                               :admin-email="adminEmail"/>

                    <p v-if="error" class="fls_onb_error">{{ error }}</p>

                    <div class="fls_onb_actions">
                        <el-button v-if="canGoBack" text class="fls_onb_back" @click="goBack">
                            {{ $t('Back') }}
                        </el-button>

                        <el-button type="primary" class="fls_onb_next"
                                   :loading="saving" @click="goNext">
                            {{ isLast ? $t('Apply these settings') : $t('Continue') }}
                        </el-button>
                    </div>

                    <!--
                        On a narrow screen the header has no room for this, so leaving
                        lives here instead. Never nowhere: a wizard with no way out is a
                        wizard people uninstall.
                    -->
                    <el-button v-if="canLeave" text :disabled="saving"
                               class="fls_onb_leave_foot" @click="leave">
                        {{ $t('Set this up later') }}
                    </el-button>
                </div>
            </div>
        </div>
    </div>
</template>
