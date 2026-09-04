<script type="text/babel">
/**
 * What setup actually changed, and where to go next.
 *
 * Every line here is something the server reported writing, not a list of features the
 * plugin has. That is the difference between a summary and a congratulation, and it is why
 * this screen does not tell anybody their site is secure: no plugin is in a position to
 * promise that, and a claim like it on the last screen of a wizard is the point at which a
 * security tool starts training people not to believe it.
 *
 * A site that answered no to everything sees a shorter, honest version rather than an
 * invented achievement.
 */
export default {
    name: 'OnboardingSummary',
    props: {
        applied: {
            type: Array,
            default: () => []
        },
        steps: {
            type: Array,
            default: () => []
        }
    },
    computed: {
        changedNothing() {
            return !this.applied.length;
        }
    }
};
</script>

<template>
    <div class="fls_onb_done">
        <div class="fls_onb_done_inner">

            <div class="fls_onb_done_symbol" aria-hidden="true"><span class="dashicons dashicons-yes"></span></div>
            <p class="fls_eyebrow">{{ $t('Setup complete') }}</p>

            <h1 class="fls_onb_headline" tabindex="-1">
                {{ $t('Your settings have been saved') }}
            </h1>

            <p v-if="changedNothing" class="fls_onb_done_lead">
                {{
                    $t('Your choices have been saved. Review the security checklist for any remaining recommendations.')
                }}
            </p>
            <p v-else class="fls_onb_done_lead">
                {{ $t('Your selected settings are now active. You can adjust them at any time in Settings.') }}
            </p>

            <ul v-if="!changedNothing" class="fls_onb_done_list">
                <li v-for="(line, i) in applied" :key="i">
                    <span class="dashicons dashicons-yes" aria-hidden="true"></span>
                    <span>{{ line }}</span>
                </li>
            </ul>

            <div class="fls_onb_done_next">
                <h2 class="fls_onb_done_next_title">{{ $t('Worth doing next') }}</h2>
                <ul class="fls_onb_done_next_list">
                    <li>
                        <router-link :to="{name: 'security_findings'}">{{ $t('Review the security checklist') }}</router-link>
                        <span>{{ $t('Everything setup did not cover, scored and explained.') }}</span>
                    </li>
                    <li>
                        <router-link :to="{name: 'settings_ip_rules'}">{{ $t('Add your own address to the allow list') }}</router-link>
                        <span>{{ $t('So the attempt limit can never lock you out of your own site.') }}</span>
                    </li>
                    <li>
                        <router-link :to="{name: 'security_scans'}">{{ $t('Set up file monitoring') }}</router-link>
                        <span>{{ $t('Scan WordPress files and review unexpected changes.') }}</span>
                    </li>
                </ul>
            </div>

            <div class="fls_onb_done_actions">
                <router-link class="el-button el-button--primary" :to="{name: 'dashboard'}">
                    {{ $t('Go to the dashboard') }}
                </router-link>
                <router-link class="el-button" :to="{name: 'settings_general'}">
                    {{ $t('Review every setting') }}
                </router-link>
            </div>
        </div>
    </div>
</template>
