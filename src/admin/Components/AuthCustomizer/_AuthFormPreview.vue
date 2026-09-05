<script type="text/babel">
/**
 * This site's login or signup page, drawn from the settings that style the real one.
 *
 * Two screens render it. The customizer, where it is the canvas being edited and the
 * headings are typed into directly; and the setup wizard, where it is there to answer the
 * question a settings label cannot - what the person signing in will actually meet once
 * this is switched on.
 *
 * It was the customizer's own markup first. Pulling it out is what lets the wizard show a
 * real login page instead of a drawing of a generic one: the colours, the logo, the
 * headings and the button are this site's, because they are read from the same settings
 * that paint wp-login.
 *
 * `editable` is the customizer's mode - it makes the two headings contenteditable and
 * reports what was typed. Everywhere else the preview is inert, and the form inside it is
 * inert in both (`pointer-events: none`), because it is a picture of a form rather than
 * one you can fill in.
 *
 * The slots are how a wizard screen layers a state on top: a notice above the form, a
 * field appended to it, a replacement for the links underneath. A screen that needs none
 * of them gets the page exactly as it ships.
 */
export default {
    name: 'AuthFormPreview',
    emits: ['update:title'],
    props: {
        /** One tab's worth of customizer settings: `{banner: {...}, form: {...}}`. */
        settings: {
            type: Object,
            required: true
        },
        tab: {
            type: String,
            default: 'login'
        },
        /** Customizer only: type into the headings rather than just read them. */
        editable: {
            type: Boolean,
            default: false
        },
        /** Replaces the shipped field list, for a screen showing a different step. */
        fields: {
            type: Array,
            default: null
        },
        /** Overrides the submit button's label. */
        buttonLabel: {
            type: String,
            default: ''
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
        submitLabel() {
            if (this.buttonLabel) {
                return this.buttonLabel;
            }

            return this.tab == 'login' ? this.$t('Login') : this.$t('Register');
        },
        currentFields() {
            if (this.fields) {
                return this.fields;
            }

            if (this.tab == 'signup') {
                return [
                    {
                        type: 'text',
                        label: this.$t('Username')
                    },
                    {
                        type: 'email',
                        label: this.$t('Email Address')
                    },
                    {
                        type: 'text',
                        label: this.$t('Your Full Name')
                    },
                    {
                        type: 'password',
                        label: this.$t('Password')
                    },
                    {
                        type: 'password',
                        label: this.$t('Re-Enter Password')
                    },
                    {
                        type: 'inline_checkbox',
                        inline_label: this.$t('I agree to the terms and conditions'),
                        disabled: false
                    }
                ];
            }

            return [
                {
                    type: 'text',
                    label: this.$t('Username or Email Address')
                },
                {
                    type: 'password',
                    label: this.$t('Password')
                },
                {
                    type: 'inline_checkbox',
                    inline_label: this.$t('Remember Me'),
                    disabled: false
                }
            ];
        }
    },
    methods: {
        /*
         * The heading is edited in place rather than through a field in the sidebar, so
         * what is typed has to be read back off the element. Reported upwards rather than
         * written here - the preview does not own the settings it is drawn from.
         */
        updateTitle(event, section) {
            this.$emit('update:title', {section, title: event.target.innerText});
        }
    }
};
</script>

<template>
    <div class="fcom_editor_content" :style="contentStyles">
        <div v-if="!settings.banner?.hidden" class="fcom_auth_wrap" :style="backgroundStyles(settings.banner)">
            <div class="fcom_auth_content">
                <div class="fcom_auth_image" v-if="settings.banner?.logo">
                    <img :src="settings.banner?.logo" :alt="settings.banner?.title"/>
                </div>
                <div class="fcom_auth_title">
                    <h2 :style="titleStyles(settings.banner)" :contenteditable="editable"
                        @mouseleave="editable && updateTitle($event, 'banner')">
                        {{ settings.banner?.title }}
                    </h2>
                </div>
                <div class="fcom_auth_description" v-if="settings.banner?.description"
                     :style="descriptionStyles(settings.banner)">
                    <p v-html="settings.banner.description"></p>
                </div>
            </div>
        </div>

        <div class="fcom_auth_wrap" :style="backgroundStyles(settings.form)">
            <div class="fcom_auth_content form_content">
                <div class="fcom_auth_form_header">
                    <div class="fcom_auth_title">
                        <h2 :style="titleStyles(settings.form)" :contenteditable="editable"
                            @mouseleave="editable && updateTitle($event, 'form')">
                            {{ settings.form?.title }}
                        </h2>
                    </div>
                    <div class="fcom_auth_description" v-if="settings.form?.description"
                         :style="descriptionStyles(settings.form)">
                        <p v-html="settings.form.description"></p>
                    </div>
                </div>

                <slot name="notice"/>

                <el-form style="user-select: none; pointer-events: none;" v-if="currentFields"
                         label-position="top" class="fcom_auth_form">
                    <div v-for="field in currentFields" :key="field.name">
                        <el-form-item
                            v-if="['text', 'email', 'number', 'textarea', 'password'].includes(field.type)"
                            :label="field.label">
                            <el-input :type="field.type" :placeholder="field.placeholder"
                                      :model-value="field.value || ''"/>
                        </el-form-item>
                        <el-form-item v-if="field.type == 'inline_checkbox' && !field.disabled">
                            <el-checkbox class="fcom_checkbox">
                                <span v-html="field.inline_label"></span>
                            </el-checkbox>
                        </el-form-item>
                    </div>

                    <slot name="form-append"/>

                    <el-form-item>
                        <el-button :style="buttonStyles(settings.form)">
                            <span>{{ submitLabel }}</span>
                        </el-button>
                    </el-form-item>
                </el-form>

                <div style="margin-top: 40px; display: block;" class="fs_form_extra">
                    <slot name="after-form">
                        <p v-if="tab == 'login'">{{ $t('Register | Lost your password?') }}</p>
                        <p v-else>{{ $t('Log in | Lost your password?') }}</p>
                        <p>{{ $t('← Go to Website') }}</p>
                    </slot>
                </div>
            </div>
        </div>
    </div>
</template>
