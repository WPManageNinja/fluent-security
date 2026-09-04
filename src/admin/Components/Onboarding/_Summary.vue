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

            <p class="fls_onb_done_eyebrow">{{ $t('Setup complete') }}</p>

            <h1 class="fls_onb_done_title">
                {{ changedNothing ? $t('Nothing was changed.') : $t('Here is what changed.') }}
            </h1>

            <p v-if="changedNothing" class="fls_onb_done_lead">
                {{
                    $t('You went through setup without turning anything on. The security checklist keeps the same recommendations, whenever you want them.')
                }}
            </p>
            <p v-else class="fls_onb_done_lead">
                {{ $t('These settings are live now. Every one of them can be changed or turned back off.') }}
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
                        <span>{{ $t('Everything this wizard did not cover, scored and explained.') }}</span>
                    </li>
                    <li>
                        <router-link :to="{name: 'settings_ip_rules'}">{{ $t('Add your own address to the allow list') }}</router-link>
                        <span>{{ $t('So the attempt limit can never lock you out of your own site.') }}</span>
                    </li>
                    <li>
                        <router-link :to="{name: 'security_scans'}">{{ $t('Set up file monitoring') }}</router-link>
                        <span>{{ $t('Nothing else can tell you a file was edited after somebody got in.') }}</span>
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
