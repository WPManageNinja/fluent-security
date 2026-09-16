<script type="text/babel">
/**
 * Which roles a protection applies to.
 *
 * A row of toggles rather than a multi-select, because the answer is short, the whole list
 * matters, and a closed dropdown hides the thing the reader is being asked to check. The
 * roles this site actually has, in the order the server sent them.
 */
export default {
    name: 'RoleChoice',
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: Array,
            default: () => []
        },
        userRoles: {
            type: Array,
            default: () => []
        },
        label: {
            type: String,
            default: ''
        },
        hint: {
            type: String,
            default: ''
        }
    },
    computed: {
        chosen() {
            return this.modelValue || [];
        }
    },
    methods: {
        has(id) {
            return this.chosen.indexOf(id) !== -1;
        },
        toggle(id) {
            const next = this.has(id)
                ? this.chosen.filter(role => role !== id)
                : this.chosen.concat([id]);

            this.$emit('update:modelValue', next);
        }
    }
};
</script>

<template>
    <div class="fls_onb_roles">
        <p v-if="label" class="fls_onb_label">{{ label }}</p>

        <div class="fls_onb_role_row">
            <button v-for="role in userRoles" :key="role.id" type="button"
                    class="fls_onb_role" :class="{'is-picked': has(role.id)}"
                    :aria-pressed="has(role.id)" @click="toggle(role.id)">
                {{ role.title }}
            </button>
        </div>

        <p v-if="hint" class="fls_onb_hint">{{ hint }}</p>
    </div>
</template>
