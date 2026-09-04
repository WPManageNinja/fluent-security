<script type="text/babel">
/**
 * A setting that is on or off.
 *
 * The switch sits with the label rather than across the row from it, because "on or off"
 * is the whole setting - putting a 40px control at the far end of an 800px row made the
 * eye travel the width of the page to connect a name to its state, and left the row's
 * height to whatever the description happened to wrap to.
 *
 * `recommend` is the value this ought to have. Nothing is shown while it holds; the note
 * only appears once the setting differs, so it reads as an exception rather than a
 * standing instruction on every row.
 */
export default {
    name: 'SettingToggle',
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
        isOn() {
            return this.modelValue === this.activeValue;
        },
        offRecommendation() {
            return this.recommend !== null && this.modelValue !== this.recommend;
        },
        recommendationText() {
            return this.recommend === this.activeValue
                ? this.$t('Recommended: on')
                : this.$t('Recommended: off');
        }
    },
    methods: {
        /** The label is a hit target too - a 40px switch is a small thing to aim at. */
        toggle() {
            if (this.disabled) {
                return;
            }

            const next = this.isOn ? this.inactiveValue : this.activeValue;

            this.$emit('update:modelValue', next);
            this.$emit('change', next);
        }
    }
};
</script>

<template>
    <div class="fls_toggle" :class="{'is-disabled': disabled}">
        <div class="fls_toggle_main">
            <el-switch :model-value="modelValue" :active-value="activeValue"
                       :inactive-value="inactiveValue" :disabled="disabled" :aria-label="label"
                       @update:model-value="v => { $emit('update:modelValue', v); $emit('change', v); }"/>

            <span class="fls_toggle_title" @click="toggle()">
                {{ label }}
                <span v-if="offRecommendation" class="fls_toggle_tag">{{ recommendationText }}</span>
            </span>
        </div>

        <div v-if="description || hint || $slots.default" class="fls_toggle_body">
            <p v-if="description">{{ description }}</p>
            <p v-if="hint" class="fls_toggle_hint">{{ hint }}</p>
            <slot/>
        </div>
    </div>
</template>
