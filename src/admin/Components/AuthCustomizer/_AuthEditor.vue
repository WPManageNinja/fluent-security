<template>
    <el-aside class="fcom_full_editor_side lockscreen_editor auth_editor" width="300px">
        <slot name="before_meta"></slot>
        <auth-meta :currentTab="currentTab" :settings="settings" :savingCount="savingCount" />
    </el-aside>
    <el-main class="fcom_full_editor_main lockscreen_editor auth_editor">
        <auth-form-preview :settings="settings" :tab="currentTab" editable
                           @update:title="applyTitle"/>
    </el-main>
</template>

<script type="text/babel">
import AuthMeta from './_AuthMeta.vue';
import AuthFormPreview from './_AuthFormPreview.vue';

export default {
    name: 'AuthEditor',
    emits: ['updateAuthSettings'],
    props: ['currentTab', 'savingCount', 'authSettings'],
    components: {
        AuthMeta,
        AuthFormPreview
    },
    data() {
        return {
            settings: this.authSettings[this.currentTab],
        }
    },
    watch: {
        currentTab() {
            this.settings = this.authSettings[this.currentTab];
        },
        savingCount() {
            this.saveSettings();
        },
        authSettings() {
            this.settings = this.authSettings[this.currentTab];
        }
    },
    methods: {
        /**
         * The canvas reports what was typed into a heading; writing it is this screen's
         * job, because this is where the settings being edited actually live.
         */
        applyTitle({section, title}) {
            if (this.settings[section]) {
                this.settings[section].title = title;
            }
        },
        saveSettings() {
            this.saving = true;
            this.$post('auth-customizer', {
                settings: this.authSettings,
            })
                .then(response => {
                    this.$notify.success(response.message);
                    this.$emit('updateAuthSettings', response.settings);
                })
                .catch((error) => {
                    this.$handleError(error);
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    }
}
</script>
