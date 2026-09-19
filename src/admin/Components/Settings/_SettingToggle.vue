<script type="text/babel">
/**
 * A setting that is on or off.
 *
 * Laid out as a `SettingRow` and not as a shape of its own: name and explanation on the
 * left, the control against the right edge. The switch used to sit beside its label
 * instead, which read well in a card of nothing but switches and badly in a card that
 * mixed them with anything else - Notifications alternated sides down its four rows, and
 * the page had two grammars for "here is a setting". One column of controls down the
 * right is worth more than each row being individually ideal.
 *
 * `recommend` is the value this ought to have. Nothing is shown while it holds; the note
 * only appears once the setting differs, so it reads as an exception rather than a
 * standing instruction on every row.
 */
import SettingRow from './_SettingRow.vue';

export default {
    name: 'SettingToggle',
    components: {SettingRow},
    props: {
        modelValue: {default: ''},
        label: {type: String, default: ''},
        description: {type: String, default: ''},
        hint: {type: String, default: ''},
        recommend: {default: null},
        activeValue: {default: 'yes'},
        inactiveValue: {default: 'no'},
        disabled: {type: Boolean, default: false}
    },
    emits: ['update:modelValue', 'change'],
    computed: {
        offRecommendation() {
            return this.recommend !== null && this.modelValue !== this.recommend;
        },
        recommendationText() {
            return this.recommend === this.activeValue
                ? this.$t('Recommended: on')
                : this.$t('Recommended: off');
        }
    }
};
</script>

<template>
    <SettingRow :description="description" :hint="hint"
                class="fls_row_toggle" :class="{'is-disabled': disabled}">
        <template #label>
            <span class="fls_row_title">
                {{ label }}
                <slot name="label-help"/>
                <span v-if="offRecommendation" class="fls_row_flag">{{ recommendationText }}</span>
            </span>
        </template>

        <el-switch :model-value="modelValue" :active-value="activeValue"
                   :inactive-value="inactiveValue" :disabled="disabled" :aria-label="label"
                   @update:model-value="v => { $emit('update:modelValue', v); $emit('change', v); }"/>

        <!--
            Anything a toggle reveals when it is on, under the row it belongs to. Passed
            unconditionally - the row itself works out whether it rendered anything.
        -->
        <template #below>
            <slot/>
        </template>
    </SettingRow>
</template>
