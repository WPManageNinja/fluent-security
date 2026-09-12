<script type="text/babel">
import {Comment, Fragment, Text} from 'vue';

/**
 * One block of settings, framed the same way on every screen.
 *
 * `id` is only used by the pages the sidebar scrolls through - it is what ties a sidebar
 * entry to the block it jumps to, and the two are built from the same list, so a link
 * cannot point at a block that is not there. Screens with a route of their own leave it
 * off and just take the frame.
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
         * rendered around nothing and left an 8px strip of padding under the head that
         * read as a cut-off second row. `v-if="$slots.default"` does not see that: the
         * slot exists, it just renders a comment. So look at what came back.
         *
         * A method rather than a computed, because a slot has to be called during render.
         */
        hasBody() {
            return this.$slots.default ? this.nodesRenderSomething(this.$slots.default()) : false;
        },

        nodesRenderSomething(nodes) {
            return (nodes || []).some(node => {
                if (node.type === Comment) {
                    return false;
                }

                if (node.type === Text) {
                    return String(node.children || '').trim() !== '';
                }

                /* A `<template v-if>` holding several rows arrives as one fragment. */
                if (node.type === Fragment) {
                    return this.nodesRenderSomething(node.children);
                }

                return true;
            });
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
