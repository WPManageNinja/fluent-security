<script type="text/babel">
/**
 * The three defaults worth closing on most sites.
 *
 * One screen for three checks, because they are the same decision three times - something
 * WordPress leaves open that this site probably does not use - and asking them separately
 * would make the shortest question in the flow into the longest part of it.
 *
 * Each row's title and reasoning come from the security checklist rather than being written
 * again here, so a site is never told one thing in setup and something else afterwards by
 * the screen that reports the same item still outstanding.
 */
export default {
    name: 'OnboardingHardening',
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: Object,
            required: true
        },
        step: {
            type: Object,
            required: true
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
        /**
         * The checklist's items, in the order the server listed them, each paired with the
         * answer key it sets. A check the server did not send simply is not shown.
         */
        rows() {
            return (this.step.checks || []).map(check => ({
                key: check.key,
                title: check.title,
                why: check.why,
                /* Already satisfied before setup started - worth saying rather than
                 * presenting as something the reader is about to switch on. */
                already: check.state === 'done'
            }));
        }
    },
    methods: {
        update(key, value) {
            this.answer = {...this.answer, [key]: value};
        },
        validate() {
            return '';
        }
    }
};
</script>

<template>
    <div class="fls_onb_fields">
        <div class="fls_onb_opts">
            <label v-for="row in rows" :key="row.key" class="fls_onb_opt"
                   :class="{'is-on': answer[row.key]}">
                <el-switch :model-value="answer[row.key]"
                           @update:model-value="v => update(row.key, v)"/>
                <span class="fls_onb_opt_text">
                    <span class="fls_onb_opt_title">
                        {{ row.title }}
                        <span v-if="row.already" class="fls_onb_tag is-quiet">
                            {{ $t('Already on') }}
                        </span>
                        <span v-else class="fls_onb_tag">{{ $t('Recommended') }}</span>
                    </span>
                    <span class="fls_onb_opt_note">{{ row.why }}</span>
                </span>
            </label>
        </div>

        <p class="fls_onb_reassure">
            {{
                $t('Leave one on if you use it. XML-RPC still carries the Jetpack and mobile apps on some sites, and turning it off there breaks them.')
            }}
        </p>
    </div>
</template>
