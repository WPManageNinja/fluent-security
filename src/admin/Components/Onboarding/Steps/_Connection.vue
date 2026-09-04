<script type="text/babel">
/**
 * Is the address this site sees actually yours?
 *
 * Deliberately not "are you behind a reverse proxy?". That is the question the setting
 * answers, and it is one most people running a website cannot answer about their own
 * hosting - so asking it directly produces a guess, and a wrong guess here quietly breaks
 * the attempt limit and makes an IP allow list exempt everybody.
 *
 * This asks a question with a checkable answer instead, against the address shown in the
 * preview beside it. Neither choice is preselected and neither is marked recommended,
 * because there is no recommended answer to a question about somebody else's server -
 * which is also why this step is absent from Helper::getRecommendedSettings().
 */
export default {
    name: 'OnboardingConnection',
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: Object,
            required: true
        },
        connection: {
            type: Object,
            default: () => ({})
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
        resolved() {
            return this.connection.resolved_ip || '';
        },
        /** The plugin already found evidence of something in front of this site. */
        suspectsProxy() {
            return !!this.connection.needs_attention;
        },
        configLocked() {
            return !!this.connection.config_locked;
        }
    },
    methods: {
        choose(mode) {
            if (this.configLocked) {
                return;
            }

            this.answer = {...this.answer, mode};
        },
        update(key, value) {
            this.answer = {...this.answer, [key]: value};
        },
        /**
         * Returns a problem to show, or an empty string. Trusting a forwarded header
         * without naming what may set it is the one configuration here that is worse than
         * leaving it alone, so it is the one thing this refuses to pass.
         */
        validate() {
            if (this.configLocked) {
                return '';
            }

            if (!this.answer.mode) {
                return this.$t('Choose one, so the plugin knows whether to trust a forwarded header.');
            }

            if (this.answer.mode === 'proxy' && !(this.answer.trusted_proxies || '').trim()) {
                return this.$t('Add the address of the proxy in front of this site.');
            }

            return '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_fields">

        <div v-if="configLocked" class="fls_onb_locked">
            {{ $t('This is set in wp-config.php, which wins over this screen. Nothing to do here.') }}
        </div>

        <template v-else>
            <div v-if="suspectsProxy" class="fls_onb_flag">
                {{
                    $t('This request reached the site from inside its own network, so something is relaying it. Until that is declared, every visitor looks like the same person.')
                }}
            </div>

            <div class="fls_onb_choices">
                <button type="button" class="fls_onb_choice"
                        :class="{'is-picked': answer.mode === 'direct'}"
                        :aria-pressed="answer.mode === 'direct'"
                        @click="choose('direct')">
                    <span class="fls_onb_choice_title">{{ $t('Yes, that is my address') }}</span>
                    <span class="fls_onb_choice_note">
                        {{ $t('Visitors reach this site directly. Nothing needs changing.') }}
                    </span>
                </button>

                <button type="button" class="fls_onb_choice"
                        :class="{'is-picked': answer.mode === 'proxy'}"
                        :aria-pressed="answer.mode === 'proxy'"
                        @click="choose('proxy')">
                    <span class="fls_onb_choice_title">{{ $t('No, that is not me') }}</span>
                    <span class="fls_onb_choice_note">
                        {{ $t('A proxy or CDN sits in front, so this is its address rather than a visitor\'s.') }}
                    </span>
                </button>
            </div>

            <p class="fls_onb_aside">
                {{ $t('Not sure?') }}
                <a href="https://www.whatismyip.com/" target="_blank" rel="noopener">
                    {{ $t('Look up your address') }}
                </a>
                {{ $t('and compare it with the one on the left.') }}
            </p>

            <div v-if="answer.mode === 'proxy'" class="fls_onb_reveal">
                <label class="fls_onb_label" for="fls_onb_proxies">
                    {{ $t('The proxy in front of this site') }}
                </label>
                <el-input id="fls_onb_proxies" :model-value="answer.trusted_proxies"
                          :placeholder="$t('e.g. 10.0.0.1, 192.168.1.0/24')"
                          @update:model-value="v => update('trusted_proxies', v)"/>
                <p class="fls_onb_hint">
                    {{
                        $t('Addresses or ranges, separated by commas. Only a request arriving from one of these will have its forwarded header believed.')
                    }}
                </p>

                <label class="fls_onb_label" for="fls_onb_header">
                    {{ $t('The header it announces visitors in') }}
                </label>
                <el-input id="fls_onb_header" :model-value="answer.proxy_ip_header"
                          placeholder="X-Forwarded-For"
                          @update:model-value="v => update('proxy_ip_header', v)"/>
                <p class="fls_onb_hint">
                    {{ $t('Leave this empty unless your host has told you otherwise.') }}
                </p>
            </div>
        </template>
    </div>
</template>
