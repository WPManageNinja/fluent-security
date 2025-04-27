<template>
    <el-aside class="fcom_full_editor_side lockscreen_editor auth_editor" width="300px">
        <slot name="before_meta"></slot>
        <auth-meta :currentTab="currentTab" :settings="settings" :savingCount="savingCount" />
    </el-aside>
    <el-main class="fcom_full_editor_main lockscreen_editor auth_editor">
        <div class="fcom_editor_content" :style="contentStyles">
            <div v-if="!settings.banner?.hidden" class="fcom_auth_wrap" :style="backgroundStyles(settings.banner)">
                <div class="fcom_auth_content">
                    <div class="fcom_auth_image" v-if="settings.banner?.logo">
                        <img :src="settings.banner?.logo" :alt="settings.banner?.title" />
                    </div>
                    <div class="fcom_auth_title">
                        <h2 :style="titleStyles(settings.banner)" contenteditable="true" @mouseleave="updateTitle($event, settings.banner)">
                            {{ settings.banner?.title }}
                        </h2>
                    </div>
                    <div class="fcom_auth_description" v-if="settings.banner?.description" :style="descriptionStyles(settings.banner)">
                        <p v-html="settings.banner.description"></p>
                    </div>
                </div>
            </div>
            <div class="fcom_auth_wrap" :style="backgroundStyles(settings.form)">
                <div class="fcom_auth_content form_content">
                    <div class="fcom_auth_form_header">
                        <div class="fcom_auth_title">
                            <h2 :style="titleStyles(settings.form)" contenteditable="true" @mouseleave="updateTitle($event, settings.form)">
                                {{ settings.form?.title }}
                            </h2>
                        </div>
                        <div class="fcom_auth_description" v-if="settings.form?.description" :style="descriptionStyles(settings.form)">
                            <p v-html="settings.form.description"></p>
                        </div>
                    </div>
                    <el-form style="user-select: none; pointer-events: none;" v-if="currentFields" label-position="top" class="fcom_auth_form">
                        <div v-for="field in currentFields" :key="field.name">
                            <el-form-item v-if="['text', 'email', 'number', 'textarea', 'password'].includes(field.type)" :label="field.label">
                                <el-input :type="field.type" :placeholder="field.placeholder"/>
                            </el-form-item>
                            <el-form-item v-if="field.type == 'inline_checkbox' && !field.disabled">
                                <el-checkbox class="fcom_checkbox">
                                    <span v-html="field.inline_label"></span>
                                </el-checkbox>
                            </el-form-item>
                        </div>
                        <el-form-item>
                            <el-button :style="buttonStyles(settings.form)">
                                <span v-if="currentTab == 'login'">Login</span>
                                <span v-else>Register</span>
                            </el-button>
                        </el-form-item>
                    </el-form>

                    <div style="margin-top: 40px; display: block;" class="fs_form_extra">
                        <p v-if="currentTab == 'login'">Register | Lost your password?</p>
                        <p v-else>Log in | Lost your password?</p>
                        <p>← Go to Website</p>
                    </div>
                </div>
            </div>
        </div>
    </el-main>
</template>

<script type="text/babel">
import AuthMeta from './_AuthMeta.vue';

export default {
    name: 'AuthEditor',
    emits: ['updateAuthSettings'],
    props: ['currentTab', 'savingCount', 'authSettings'],
    components: {
        AuthMeta
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
    computed: {
        contentStyles() {
            return {
                flexDirection: this.settings.banner?.position == 'left' ? 'row' : 'row-reverse'
            };
        },
        backgroundStyles() {
            return (field) => {
                return {
                    backgroundSize: 'cover',
                    backgroundImage: `url(${field?.background_image})`,
                    backgroundColor: field?.background_color
                };
            };
        },
        titleStyles() {
            return (field) => {
                return {
                    color: field?.title_color
                };
            };
        },
        descriptionStyles() {
            return (field) => {
                return {
                    color: field?.text_color
                };
            };
        },
        buttonStyles() {
            return (field) => {
                return {
                    backgroundColor: field?.button_color,
                    color: field?.button_label_color
                };
            };
        },
        currentFields() {

            if(this.currentTab == 'signup') {
                return [
                    {
                        type: 'text',
                        label: 'Username'
                    },
                    {
                        type: 'email',
                        label: 'Email Address'
                    },
                    {
                        type: 'text',
                        label: 'Your Full Name'
                    },
                    {
                        type: 'password',
                        label: 'Password'
                    },
                    {
                        type: 'password',
                        label: 'Re-Enter Password'
                    },
                    {
                        type: 'inline_checkbox',
                        inline_label: 'I agree to the terms and conditions',
                        disabled: false
                    }
                ]
            }

            return [
                {
                    type: 'text',
                    label: 'Username or Email Address'
                },
                {
                    type: 'password',
                    label: 'Password'
                },
                {
                    type: 'inline_checkbox',
                    inline_label: 'Remember Me',
                    disabled: false
                }
            ];
        }
    },
    methods: {
        updateTitle(event, field) {
            field.title = event.target.innerText;
        },
        updateButtonLabel(event, field) {
            field.button_label = event.target.innerText;
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
