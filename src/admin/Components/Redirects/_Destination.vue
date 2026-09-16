<script type="text/babel">
/**
 * Where a redirect points.
 *
 * A blank URL box asks the reader to know two things by heart - the exact address of the
 * dashboard, and what leaving it empty does. Neither is guessable, and both are only
 * discovered by signing out and back in. So the common destinations are named options and
 * "leave it to WordPress" is one of the choices rather than the absence of one; typing an
 * address is still there for everything else.
 */
const CUSTOM = '__custom__';

/*
 * "Leave it to whatever applies next" is stored as an empty string, but it cannot be an
 * option worth an empty string: Element Plus reads that as nothing selected and shows its
 * placeholder, so the one choice that needed explaining was the one with no label on it.
 */
const DEFAULT = '__default__';

/* A stored value is just a URL, so which option it came from is worked out by matching. */
function presetFor(presets, value) {
    return presets.find(preset => preset.url === value);
}

export default {
    name: 'RedirectDestination',
    props: {
        modelValue: {
            type: String,
            default: ''
        },
        presets: {
            type: Array,
            default: () => []
        },
        // What an empty value means here - it differs between the defaults and a rule.
        emptyLabel: {
            type: String,
            default: ''
        }
    },
    emits: ['update:modelValue'],
    data() {
        const preset = presetFor(this.presets, this.modelValue);

        return {
            CUSTOM,
            DEFAULT,
            choice: !this.modelValue ? DEFAULT : (preset ? preset.url : CUSTOM),
            custom: (!this.modelValue || preset) ? '' : this.modelValue
        };
    },
    computed: {
        /* Named options are friendly but vague, so the address they stand for is shown. */
        chosenUrl() {
            return (this.choice === CUSTOM || this.choice === DEFAULT) ? '' : this.choice;
        }
    },
    watch: {
        custom(value) {
            if (this.choice === CUSTOM) {
                this.$emit('update:modelValue', value);
            }
        }
    },
    methods: {
        onChoice(choice) {
            if (choice === DEFAULT) {
                this.$emit('update:modelValue', '');
                return;
            }

            if (choice !== CUSTOM) {
                this.$emit('update:modelValue', choice);
                return;
            }

            this.$emit('update:modelValue', this.custom);
            this.$nextTick(() => this.$refs.custom && this.$refs.custom.focus());
        }
    }
};
</script>

<template>
    <div class="fls_destination">
        <el-select v-model="choice" @change="onChoice">
            <el-option :value="DEFAULT" :label="emptyLabel || $t('Let WordPress decide')"/>
            <el-option v-for="preset in presets" :key="preset.url"
                       :value="preset.url" :label="preset.label"/>
            <el-option :value="CUSTOM" :label="$t('Somewhere else…')"/>
        </el-select>

        <el-input v-if="choice === CUSTOM" ref="custom" v-model="custom"
                  :placeholder="appVars.site_url + 'members/'"/>

        <span v-if="chosenUrl" class="fls_destination_url">{{ chosenUrl }}</span>
        <span v-else-if="choice === CUSTOM" class="fls_destination_url">
            {{ $t('A full address, or a path like /members/.') }}
        </span>
    </div>
</template>
