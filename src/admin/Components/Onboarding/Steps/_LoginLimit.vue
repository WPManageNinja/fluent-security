<script type="text/babel">
/**
 * How many failed attempts, over how long.
 *
 * The only screen here tuning a number rather than turning something on, and the number is
 * a trade rather than a target: too high and guessing stays cheap, too low and the person
 * who genuinely forgot their password is locked out of their own site. So the preview beside
 * it shows the message the choice produces, and the presets are named for the trade rather
 * than for the values.
 */
export default {
    name: 'OnboardingLoginLimit',
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: Object,
            required: true
        },
        recommended: {
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
        presets() {
            const suggested = {
                limit: parseInt(this.recommended.login_try_limit, 10) || 5,
                timing: parseInt(this.recommended.login_try_timing, 10) || 30
            };

            return [
                {
                    id: 'relaxed',
                    title: this.$t('Relaxed'),
                    note: this.$t('For sites where people forget their passwords often.'),
                    limit: 10,
                    timing: 15
                },
                {
                    id: 'balanced',
                    title: this.$t('Balanced'),
                    note: this.$t('Suits most sites.'),
                    limit: suggested.limit,
                    timing: suggested.timing,
                    recommended: true
                },
                {
                    id: 'strict',
                    title: this.$t('Strict'),
                    note: this.$t('For sites where only a few people ever sign in.'),
                    limit: 3,
                    timing: 60
                }
            ];
        },
        activePreset() {
            const match = this.presets.find(preset => {
                return preset.limit === parseInt(this.answer.limit, 10)
                    && preset.timing === parseInt(this.answer.timing, 10);
            });

            return match ? match.id : 'custom';
        }
    },
    methods: {
        pick(preset) {
            this.answer = {limit: preset.limit, timing: preset.timing};
        },
        update(key, value) {
            const number = parseInt(value, 10);

            this.answer = {...this.answer, [key]: isNaN(number) ? '' : number};
        },
        validate() {
            const limit = parseInt(this.answer.limit, 10);
            const timing = parseInt(this.answer.timing, 10);

            if (isNaN(limit) || limit < 1 || limit > 100) {
                return this.$t('Pick between 1 and 100 attempts.');
            }

            if (isNaN(timing) || timing < 1 || timing > 1440) {
                return this.$t('Pick a window between 1 minute and a day.');
            }

            return '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_fields">

        <div class="fls_onb_presets">
            <button v-for="preset in presets" :key="preset.id" type="button"
                    class="fls_onb_preset"
                    :class="{'is-picked': activePreset === preset.id, 'has-tag': preset.recommended}"
                    :aria-pressed="activePreset === preset.id" @click="pick(preset)">
                <!--
                    The badge is rendered in every card and hidden where it does not
                    apply, so the line below it starts at the same height in all three.
                -->
                <span class="fls_onb_preset_head" aria-hidden="true">
                    <span class="fls_tag is_success is_round">{{ $t('Recommended') }}</span>
                </span>
                <span class="fls_onb_preset_title">
                    {{ preset.title }}
                    <span v-if="preset.recommended" class="fls_screen_reader">
                        {{ $t('Recommended') }}
                    </span>
                </span>
                <span class="fls_onb_preset_val">
                    {{ $t('%s tries in %s min', preset.limit, preset.timing) }}
                </span>
                <span class="fls_onb_preset_note">{{ preset.note }}</span>
            </button>
        </div>

        <div class="fls_onb_pair">
            <div class="fls_onb_pair_item">
                <label class="fls_onb_label" for="fls_onb_limit">{{ $t('Failed attempts') }}</label>
                <el-input id="fls_onb_limit" type="number" :min="1" :max="100"
                          :model-value="answer.limit"
                          @update:model-value="v => update('limit', v)"/>
            </div>
            <div class="fls_onb_pair_item">
                <label class="fls_onb_label" for="fls_onb_timing">{{ $t('Within (minutes)') }}</label>
                <el-input id="fls_onb_timing" type="number" :min="1" :max="1440"
                          :model-value="answer.timing"
                          @update:model-value="v => update('timing', v)"/>
            </div>
        </div>

        <p class="fls_onb_reassure">
            {{ $t('You can add your own address to the allow list later, so this can never shut you out of your own site.') }}
        </p>
    </div>
</template>
