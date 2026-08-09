<script type="text/babel">
import EmailbodyContainer from "./EmailbodyContainer.vue";
import WPEditor from "./_wp_editor.vue";
import SettingsHeader from '../Settings/_SettingsHeader.vue';
import SettingsCard from '../Settings/_SettingsCard.vue';
import SettingRow from '../Settings/_SettingRow.vue';

export default {
    name: 'TemplateSettings',
    components: {WPEditor, EmailbodyContainer, SettingsHeader, SettingsCard, SettingRow},
    data() {
        return {
            settings: null,
            defaultContent: '',
            loading: false,
            saving: false,
            defaultColors: {},
            /*
             * Grouped the way they read in the preview - the page, then the message on
             * it, then the quoted blocks inside that - so the list is walked in the same
             * order as the thing beside it. `target` is the element in the sample each
             * one actually colours, used to scroll the preview to it.
             */
            groups: [
                {
                    title: 'Page',
                    target: '.body_wrap',
                    colors: [
                        {key: 'body_bg', label: 'Background', hint: 'Behind the message.'},
                        {
                            key: 'footer_content_color',
                            label: 'Footer text',
                            hint: 'The small print below the message.',
                            // Its own target: the footer is at the far end of the email.
                            target: '.footer_table'
                        }
                    ]
                },
                {
                    title: 'Message',
                    target: '.content_wrap',
                    colors: [
                        {key: 'content_bg', label: 'Background', hint: 'The card the message sits on.'},
                        {key: 'content_color', label: 'Text', hint: 'Body copy.'}
                    ]
                },
                {
                    /*
                     * These two style `blockquote`, which the emails use for indented
                     * detail blocks - login details, an account address, a long URL.
                     * They are not the button: every button is an <a> with its colours
                     * written inline in that email's own body, so it is changed per
                     * email under Content, not here.
                     */
                    title: 'Quoted blocks',
                    target: 'blockquote',
                    note: 'The indented boxes holding details like a username or a link.',
                    colors: [
                        {key: 'highlight_bg', label: 'Background', hint: 'Behind the quoted block.'},
                        {key: 'highlight_color', label: 'Text', hint: 'Inside it.'}
                    ]
                }
            ]
        }
    },
    computed: {
        /** True once every colour matches the shipped default, which is when Reset is a no-op. */
        isDefault() {
            if (!this.settings || !Object.keys(this.defaultColors).length) {
                return true;
            }

            /*
             * Compared as hex, because a default stored as `rgb(...)` and the hex the
             * picker writes back are the same colour and should not read as a change.
             */
            return Object.keys(this.defaultColors)
                .every(key => this.hex(this.settings[key]) === this.hex(this.defaultColors[key]));
        }
    },
    methods: {
        fetchSettings() {
            this.loading = true;

            this.$get('wp-default-emails/template-settings')
                .then(response => {
                    this.settings = response.settings;
                    this.defaultContent = response.default_content;
                    this.defaultColors = response.default_colors;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        saveSettings() {
            // Nothing loaded means nothing to save - posting now would overwrite with blanks.
            if (!this.settings) {
                return;
            }

            this.saving = true;

            this.$post('wp-default-emails/save-template-settings', {settings: this.settings})
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        setDefaultColors() {
            for (let key in this.defaultColors) {
                this.settings[key] = this.defaultColors[key];
            }
        },
        /** Scrolls the preview to whatever the setting being edited actually colours. */
        reveal(group, color) {
            const target = (color && color.target) || group.target;

            if (this.$refs.preview && target) {
                this.$refs.preview.reveal(target);
            }
        },
        /**
         * The stored value, shown as a hex code.
         *
         * Some of the shipped defaults are `rgb(249, 250, 251)` rather than a hex code,
         * which read as one odd row in a column of `#RRGGBB`. Only the display is
         * normalised - rewriting what is stored would change a saved setting just for
         * having looked at the screen.
         */
        hex(value) {
            if (!value) {
                return '';
            }

            const parts = String(value).match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);

            if (!parts) {
                return String(value).toUpperCase();
            }

            return '#' + parts.slice(1, 4)
                .map(n => Number(n).toString(16).padStart(2, '0'))
                .join('')
                .toUpperCase();
        }
    },
    mounted() {
        this.fetchSettings();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Email Template Design')"
                        :description="$t('How every system email looks, and who it comes from.')"
                        :saving="saving" :disabled="!settings" @save="saveSettings()">
            <template #actions>
                <el-button size="small" @click="$router.push({name: 'settings_emails'})">
                    {{ $t('Back to emails') }}
                </el-button>
            </template>
        </SettingsHeader>

        <div class="fls_settings_content" v-loading="loading">
            <el-skeleton v-if="!settings" :animated="true" :rows="6"/>

            <el-form v-else label-position="top">
                <SettingsCard :title="$t('Design')"
                              :description="$t('Applied to every system email at once. The preview updates as you pick.')">
                    <template #actions>
                        <el-button size="small" :disabled="isDefault" @click="setDefaultColors()">
                            {{ $t('Reset colours') }}
                        </el-button>
                    </template>

                    <div class="fls_design">
                        <div class="fls_design_controls">
                            <div v-for="group in groups" :key="group.title" class="fls_swatch_group">
                                <h3 class="fls_eyebrow">{{ $t(group.title) }}</h3>
                                <p v-if="group.note" class="fls_swatch_group_note">{{ $t(group.note) }}</p>

                                <div v-for="color in group.colors" :key="color.key" class="fls_swatch"
                                     @click="reveal(group, color)">
                                    <el-color-picker v-model="settings[color.key]" :show-alpha="false"
                                                     color-format="hex"
                                                     @active-change="(picked) => { settings[color.key] = picked; }"/>
                                    <div class="fls_swatch_text">
                                        <span class="fls_swatch_label">{{ $t(color.label) }}</span>
                                        <span class="fls_swatch_hint">{{ $t(color.hint) }}</span>
                                    </div>
                                    <code class="fls_swatch_value">{{ hex(settings[color.key]) }}</code>
                                </div>
                            </div>
                        </div>

                        <!-- Stays in view while the colours beside it are changed. -->
                        <div class="fls_design_preview">
                            <span class="fls_eyebrow">{{ $t('Preview') }}</span>
                            <emailbody-container v-if="defaultContent" ref="preview"
                                                 :style_config="settings" :content="defaultContent"/>
                        </div>
                    </div>
                </SettingsCard>

                <SettingsCard :title="$t('Footer')"
                              :description="$t('Appears at the bottom of every system email.')">
                    <SettingRow stacked :label="$t('Footer text')">
                        <WPEditor :height="80" v-model="settings.footer_text"/>
                    </SettingRow>
                </SettingsCard>

                <SettingsCard :title="$t('Sender')"
                              :description="$t('Leave these empty to keep whatever WordPress or your mail plugin already uses.')">
                    <SettingRow :label="$t('From address')">
                        <el-input v-model="settings.from_email" :placeholder="$t('Enter email address')"/>
                    </SettingRow>

                    <SettingRow :label="$t('From name')">
                        <el-input type="text" v-model="settings.from_name" :placeholder="$t('Enter from name')"/>
                    </SettingRow>

                    <SettingRow :label="$t('Reply-to address')"
                                :description="$t('Where a reply goes, if that is not the sending address.')">
                        <el-input v-model="settings.reply_to_email" :placeholder="$t('Enter reply email address')"/>
                    </SettingRow>

                    <SettingRow :label="$t('Reply-to name')">
                        <el-input type="text" v-model="settings.reply_to_name" :placeholder="$t('Enter reply to name')"/>
                    </SettingRow>
                </SettingsCard>
            </el-form>
        </div>
    </div>
</template>
