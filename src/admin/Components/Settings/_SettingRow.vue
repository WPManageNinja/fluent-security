<script type="text/babel">
import {rendersSomething} from './slotContent';

/**
 * One setting: what it is on the left, the control for it on the right.
 *
 * The shape matters more than it looks. A column of labels can be scanned without
 * reading a word of the explanations, which is how someone finds the one thing they
 * came to change - so the text gets the width and the control gets only what it needs.
 *
 * `hint` is for the secondary line that used to sit under the control: "Recommended:
 * disabled", or a sentence restating the setting in terms of the values chosen. It
 * belongs with the text, because under a 44px switch it had nowhere to wrap.
 *
 * `below` is for what a setting reveals rather than what it is - the fields a toggle
 * opens up once it is on. They sit under the whole row, indented, so the control column
 * stays one column.
 */
export default {
    name: 'SettingRow',
    props: {
        label: {
            type: String,
            default: ''
        },
        description: {
            type: String,
            default: ''
        },
        hint: {
            type: String,
            default: ''
        },
        // For controls that need the full width, like a table or a group of cards.
        stacked: {
            type: Boolean,
            default: false
        }
    },
    methods: {
        /* A reveal is usually behind a `v-if`, so ask what it rendered, not whether it exists. */
        hasBelow() {
            return rendersSomething(this.$slots.below);
        }
    }
};
</script>

<template>
    <div class="fls_row" :class="{'fls_row_stacked': stacked}">
        <div class="fls_row_main">
            <div class="fls_row_label">
                <slot name="label">
                    <span class="fls_row_title">{{ label }}</span>
                </slot>
                <p v-if="description">{{ description }}</p>

                <p v-if="hint || $slots.hint" class="fls_row_hint">
                    <slot name="hint">{{ hint }}</slot>
                </p>
            </div>
            <div class="fls_row_control">
                <slot/>
            </div>
        </div>

        <div v-if="hasBelow()" class="fls_row_below">
            <slot name="below"/>
        </div>
    </div>
</template>
