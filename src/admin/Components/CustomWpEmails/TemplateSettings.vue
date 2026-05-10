<template>
    <div class="box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div class="box_header" style="padding: 15px;font-size: 16px;">
                <div style="padding-top: 5px;" class="box_head">
                    {{ $t('Customize Your Email Template Design') }}
                </div>
                <div style="display: flex;" class="box_actions">
                    <el-button @click="saveSettings" type="primary">{{ $t('Save Settings') }}</el-button>
                </div>
            </div>
            <div v-loading="loading" class="box_body">
                <template v-if="settings">
                    <el-form v-model="settings" label-position="top">
                        <el-row :gutter="20">
                            <el-col :md="8" :sm="8" :xs="24">
                                <el-form-item :label="$t('Body Background Color')">
                                    <el-color-picker @active-change="(color) => { settings.body_bg = color; }"
                                                     v-model="settings.body_bg" :show-alpha="false"></el-color-picker>
                                </el-form-item>
                            </el-col>
                            <el-col :md="8" :sm="8" :xs="24">
                                <el-form-item :label="$t('Content Background Color')">
                                    <el-color-picker @active-change="(color) => { settings.content_bg = color; }"
                                                     v-model="settings.content_bg"
                                                     :show-alpha="false"></el-color-picker>
                                </el-form-item>
                            </el-col>
                            <el-col :md="8" :sm="8" :xs="24">
                                <el-form-item :label="$t('Content Text Color')">
                                    <el-color-picker @active-change="(color) => { settings.content_color = color; }"
                                                     v-model="settings.content_color"
                                                     :show-alpha="false"></el-color-picker>
                                </el-form-item>
                            </el-col>
                        </el-row>
                        <el-row :gutter="20">
                            <el-col :md="8" :sm="8" :xs="24">
                                <el-form-item :label="$t('Highlight Background')">
                                    <el-color-picker @active-change="(color) => { settings.highlight_bg = color; }"
                                                     v-model="settings.highlight_bg"
                                                     :show-alpha="false"></el-color-picker>
                                </el-form-item>
                            </el-col>
                            <el-col :md="8" :sm="8" :xs="24">
                                <el-form-item :label="$t('Highlight Text Color')">
                                    <el-color-picker @active-change="(color) => { settings.highlight_color = color; }"
                                                     v-model="settings.highlight_color"
                                                     :show-alpha="false"></el-color-picker>
                                </el-form-item>
                            </el-col>
                            <el-col :md="8" :sm="8" :xs="24">
                                <el-form-item :label="$t('Footer Text Color')">
                                    <el-color-picker
                                        @active-change="(color) => { settings.footer_content_color = color; }"
                                        v-model="settings.footer_content_color" :show-alpha="false"></el-color-picker>
                                </el-form-item>
                            </el-col>
                        </el-row>
                        <h3>
                            <span style="color: #999;">{{ $t('Preview') }}</span>
                            <el-button type="info" style="margin-left: 10px;" size="small"
                                       @click="showingPreview = !showingPreview">
                                <span v-if="!showingPreview">{{ $t('Show Preview') }}</span>
                                <span v-else>{{ $t('Hide Preview') }}</span>
                            </el-button>
                            <el-button @click="setDefaultColors()" style="float: right;" size="small">
                                {{$t('Set Default')}}
                            </el-button>
                        </h3>
                        <emailbody-container v-if="defaultContent && showingPreview" :style_config="settings"
                                             :content="defaultContent"/>

                        <el-form-item style="margin-top: 30px;" :label="$t('Footer Text')">
                            <WPEditor :height="80" v-model="settings.footer_text"/>
                        </el-form-item>

                        <el-row :gutter="20">
                            <el-col :md="12" :sm="12" :xs="24">
                                <el-form-item :label="$t('Send from email (optional)')">
                                    <el-input v-model="settings.from_email"
                                              :placeholder="$t('Enter email address')"></el-input>
                                </el-form-item>
                            </el-col>
                            <el-col :md="12" :sm="12" :xs="24">
                                <el-form-item :label="$t('Send from name (optional)')">
                                    <el-input type="text" v-model="settings.from_name"
                                              :placeholder="$t('Enter from name')"></el-input>
                                </el-form-item>
                            </el-col>
                        </el-row>
                        <el-row :gutter="20">
                            <el-col :md="12" :sm="12" :xs="24">
                                <el-form-item :label="$t('Reply to email (optional)')">
                                    <el-input v-model="settings.reply_to_email"
                                              :placeholder="$t('Enter reply email address')"></el-input>
                                </el-form-item>
                            </el-col>
                            <el-col :md="12" :sm="12" :xs="24">
                                <el-form-item :label="$t('Reply to name (optional)')">
                                    <el-input type="text" v-model="settings.reply_to_name"
                                              :placeholder="$t('Enter reply to name')"></el-input>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-form-item style="margin-top: 30px; text-align: right;">
                            <el-button @click="saveSettings" type="primary">{{ $t('Save Settings') }}</el-button>
                        </el-form-item>
                    </el-form>
                </template>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
import EmailbodyContainer from "./EmailbodyContainer.vue";
import WPEditor from "./_wp_editor.vue";

export default {
    name: 'TemplateSettings',
    components: {
        WPEditor,
        EmailbodyContainer
    },
    data() {
        return {
            settings: null,
            defaultContent: '',
            loading: false,
            saving: false,
            showingPreview: true,
            defaultColors: {}
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
            this.saving = true;
            this.$post('wp-default-emails/save-template-settings', {
                settings: this.settings,
            })
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
            let defaultColors = this.defaultColors;

            for (let key in defaultColors) {
                this.settings[key] = defaultColors[key];
            }
        }
    },
    mounted() {
        this.fetchSettings();
    }
}
</script>
