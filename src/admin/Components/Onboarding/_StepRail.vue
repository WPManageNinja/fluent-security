<script type="text/babel">
/**
 * How far through the questions you are, and how many are left.
 *
 * Present because its absence is the single worst thing about the setup wizards this one
 * was measured against: they ask a question, then another, then another, and never say how
 * many there are. Not knowing whether you are one screen from the end or ten is what turns
 * a short setup into something people abandon half way.
 *
 * Steps already answered are buttons - going back to reconsider one is ordinary, and the
 * flow is short enough that a named list beats a Back button pressed four times. Steps
 * ahead are not, because arriving at a question by skipping the one before it is how a
 * default nobody read ends up applied.
 */
export default {
    name: 'StepRail',
    emits: ['jump'],
    props: {
        disabled: Boolean,
        steps: {
            type: Array,
            required: true
        },
        index: {
            type: Number,
            required: true
        }
    },
    methods: {
        stateOf(i) {
            if (i < this.index) {
                return 'done';
            }

            return i === this.index ? 'current' : 'ahead';
        }
    }
};
</script>

<template>
    <ol class="fls_onb_rail" :aria-label="$t('Setup steps')">
        <li v-for="(step, i) in steps" :key="step.id"
            class="fls_onb_rail_item" :class="'is-' + stateOf(i)">
            <component :is="i < index ? 'button' : 'span'"
                       class="fls_onb_rail_hit"
                       :disabled="i < index ? disabled : null"
                       :aria-label="step.title"
                       :type="i < index ? 'button' : null"
                       :aria-current="i === index ? 'step' : null"
                       @click="!disabled && i < index && $emit('jump', i)">
                <span class="fls_onb_rail_mark" aria-hidden="true">
                    <span v-if="i < index" class="dashicons dashicons-yes"></span>
                    <span v-else>{{ i + 1 }}</span>
                </span>
                <span class="fls_onb_rail_label">{{ step.title }}</span>
            </component>
        </li>
    </ol>
</template>
