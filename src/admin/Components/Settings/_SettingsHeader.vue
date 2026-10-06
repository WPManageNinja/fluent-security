<script type="text/babel">
export default {
    name: 'SettingsHeader',
    props: {
        heading: {
            type: String,
            default: ''
        },
        description: {
            type: String,
            default: ''
        },
        saving: {
            type: Boolean,
            default: false
        },
        showSave: {
            type: Boolean,
            default: true
        },
        saveText: {
            type: String,
            default: ''
        },
        /*
         * Saving before the data has arrived posts an empty payload over whatever is
         * stored. On the social login endpoint that clears the client IDs and secrets,
         * so this is a guard rather than a nicety.
         */
        disabled: {
            type: Boolean,
            default: false
        }
    },
    emits: ['save']
};
</script>

<template>
    <div class="fls_settings_header">
        <!-- Capped to the same width as the cards below, so Save sits over their edge. -->
        <div class="fls_settings_header_inner">
            <div>
                <h1>{{ heading }}</h1>
                <p v-if="description" class="fls_settings_header_desc">{{ description }}</p>
            </div>

            <div class="fls_settings_header_actions">
                <slot name="actions"/>

                <!--
                    Large rather than small: this is the one control that commits the whole
                    screen, and at 24px it sat on the bar looking like a table's row action.
                    Anything a page puts in the actions slot beside it matches the size, and
                    the secondary ones there are borderless so only Save reads as a button.
                -->
                <el-button v-if="showSave" type="primary" size="large" :loading="saving"
                           :disabled="disabled" @click="$emit('save')">
                    {{ saveText || $t('Save') }}
                </el-button>
            </div>
        </div>
    </div>
</template>
