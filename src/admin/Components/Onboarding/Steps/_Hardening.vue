<script type="text/babel">
import SettingToggle from '../../Settings/_SettingToggle.vue';

/**
 * The three defaults worth closing on most sites.
 *
 * One screen for three checks, because they are the same decision three times - something
 * WordPress leaves open that this site probably does not use - and asking them separately
 * would make the shortest question in the flow into the longest part of it.
 *
 * Each row's title and reasoning come from the security checklist rather than being written
 * again here, so a site is never told one thing during setup and something else afterwards
 * by the screen reporting the same item still outstanding.
 */
export default {
    name: 'OnboardingHardening',
    components: {SettingToggle},
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
                /* Already satisfied before setup started - worth saying, rather than
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
        <!--
            Said once above the group rather than badged on every row. The switches use the
            settings screen's `recommend`, which stays quiet while a setting is what it
            should be and speaks up once it is not - right on a settings screen, where the
            reader chose the values, but on a first run nobody has been told where the
            values came from. One line covers that without a badge on each row.
        -->
        <p class="fls_onb_hint">
            {{ $t('The recommended ones are already on. Turn off any that would get in your way.') }}
        </p>

        <div class="fls_onb_opts">
            <div v-for="row in rows" :key="row.key" class="fls_onb_opt"
                 :class="{'is-on': answer[row.key]}">
                <setting-toggle :model-value="answer[row.key]"
                                :active-value="true" :inactive-value="false"
                                :recommend="true" :label="row.title" :description="row.why"
                                @update:model-value="v => update(row.key, v)">
                    <p v-if="row.already" class="fls_onb_already">
                        {{ $t('This one is already on.') }}
                    </p>
                </setting-toggle>
            </div>
        </div>

        <p class="fls_onb_reassure">
            {{
                $t('If you use Jetpack, a mobile app, or a tool that posts to this site for you, leave XML-RPC unblocked.')
            }}
        </p>
    </div>
</template>
