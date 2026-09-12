<script type="text/babel">
import {rendersSomething} from './slotContent';

/**
 * One block of settings, framed the same way on every screen.
 *
 * `id` makes a block linkable: the dashboard checklist points straight at the setting
 * that would tick it, with `?section=<id>`. Cards nothing links to leave it off and just
 * take the frame.
 */
export default {
    name: 'SettingsCard',
    props: {
        id: {type: String, default: ''},
        title: {type: String, default: ''},
        description: {type: String, default: ''}
    },
    methods: {
        /**
         * Whether anything is actually being put in the card.
         *
         * A card whose rows are all behind a `v-if` - a provider that is switched off,
         * a block that is only for one server - still passed a slot, so the body was
         * rendered around nothing and left a strip of padding under the head that read
         * as a cut-off second row.
         */
        hasBody() {
            return rendersSomething(this.$slots.default);
        }
    }
};
</script>

<template>
    <section :id="id ? 'fls_section_' + id : null" class="fls_card" :class="{'fls_section': !!id}">
        <div v-if="title || $slots.actions" class="fls_card_head">
            <div v-if="$slots.icon" class="fls_card_head_icon">
                <slot name="icon"/>
            </div>

            <div class="fls_card_head_text">
                <h2>
                    {{ title }}
                    <slot name="badge"/>
                </h2>
                <p v-if="description">{{ description }}</p>
            </div>

            <div v-if="$slots.actions" class="fls_card_head_actions">
                <slot name="actions"/>
            </div>
        </div>

        <div v-if="hasBody()" class="fls_card_body">
            <slot/>
        </div>
    </section>
</template>
