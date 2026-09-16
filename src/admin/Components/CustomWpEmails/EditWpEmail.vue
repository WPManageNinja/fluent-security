<script type="text/babel">
import WpEditor from './_wp_editor.vue';
import InputPopover from './MCE/InputPopover.vue';
import PreviewEmail from "./PreviewEmail.vue";
import SettingsHeader from '../Settings/_SettingsHeader.vue';
import SettingsCard from '../Settings/_SettingsCard.vue';
import SettingRow from '../Settings/_SettingRow.vue';

export default {
    name: 'EditWpEmail',
    components: {PreviewEmail, WpEditor, InputPopover, SettingsHeader, SettingsCard, SettingRow},
    props: {
        email_id: {
            type: String,
            required: true
        }
    },
    data() {
        return {
            email: null,
            settings: null,
            smartcodes: [],
            loading: false,
            saving: false,
            required_smartcodes: [],
            default_content: null,
            disableEditor: false,
            showPreview: false
        }
    },
    computed: {
        /** What each choice actually does, said once here rather than in three panels. */
        statusNote() {
            if (!this.settings) {
                return '';
            }

            if (this.settings.status === 'system') {
                return this.$t('WordPress sends this email exactly as it does today. Nothing here changes it.');
            }

            if (this.settings.status === 'disabled') {
                return this.$t('This email is not sent at all. Nobody is told when the event happens.');
            }

            return this.$t('Your subject and body below are sent instead of the WordPress default.');
        }
    },
    methods: {
        fetchEmail() {
            this.loading = true;

            this.$get('wp-default-emails/find-email', {email_id: this.email_id})
                .then(response => {
                    this.smartcodes = response.smartcodes;
                    this.email = response.email;
                    this.settings = response.settings;
                    this.default_content = response.default_content;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        saveEmail() {
            if (!this.settings) {
                return;
            }

            this.required_smartcodes = [];
            this.saving = true;

            this.$post('wp-default-emails/save-email-settings', {
                settings: this.settings,
                email_id: this.email_id
            })
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch((errors) => {
                    this.$handleError(errors);

                    if (errors?.data?.required_smartcodes) {
                        this.required_smartcodes = errors?.data?.required_smartcodes;
                    }
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        setDefaultContent() {
            this.disableEditor = true;
            this.settings.email.subject = this.default_content.email.subject;
            this.settings.email.body = this.default_content.email.body;

            this.$nextTick(() => {
                this.disableEditor = false;
                this.$notify.success(this.$t('Default content has been set successfully.'));
            });
        },
        previewEmail() {
            this.showPreview = true;
        }
    },
    mounted() {
        this.fetchEmail();
    }
}
</script>

<template>
    <div>
        <SettingsHeader :heading="email ? email.title : $t('Edit Email')"
                        :description="email ? email.description : ''"
                        :saving="saving" :disabled="!settings" @save="saveEmail()">
            <template #actions>
                <el-button link size="large" @click="$router.push({name: 'settings_emails'})">
                    {{ $t('Back to emails') }}
                </el-button>
            </template>
        </SettingsHeader>

        <div class="fls_settings_content" v-loading="loading">
            <el-skeleton v-if="!email || !settings" :animated="true" :rows="6"/>

            <el-form v-else label-position="top">
                <SettingsCard :title="$t('This email')">
                    <template #actions>
                        <el-tag type="info" disable-transitions>
                            {{ $t('To: %s', email.recipient) }}
                        </el-tag>
                    </template>

                    <SettingRow :label="$t('What to send')" :description="statusNote">
                        <el-radio-group v-model="settings.status">
                            <el-radio-button value="active" :label="$t('Your own')"/>
                            <el-radio-button value="system" :label="$t('WordPress default')"/>
                            <el-radio-button v-if="email.can_disable == 'yes'" value="disabled"
                                             :label="$t('Nothing')"/>
                        </el-radio-group>
                    </SettingRow>
                </SettingsCard>

                <SettingsCard v-if="settings.status == 'active'" :title="$t('Content')"
                              :description="$t('The placeholders in braces are filled in when the email is sent.')">
                    <template #actions>
                        <el-button v-if="default_content?.email?.body" size="small" @click="setDefaultContent()">
                            {{ $t('Start from the default') }}
                        </el-button>
                        <el-button v-if="default_content?.email?.body" size="small" @click="previewEmail()">
                            {{ $t('Preview') }}
                        </el-button>
                    </template>

                    <SettingRow stacked :label="$t('Subject')">
                        <input-popover input_size="large" :input_placeholder="$t('Your Email Subject')"
                                       v-model="settings.email.subject" :data="smartcodes"/>
                    </SettingRow>

                    <SettingRow stacked :label="$t('Body')">
                        <WpEditor v-if="!disableEditor" :editorShortcodes="smartcodes"
                                  v-model="settings.email.body"/>
                    </SettingRow>
                </SettingsCard>

                <el-alert v-if="settings.status == 'active' && required_smartcodes && required_smartcodes.length"
                          type="error" :closable="false" show-icon
                          :title="$t('This email needs these placeholders to work')">
                    <ul class="fls_required_codes">
                        <li v-for="(code, index) in required_smartcodes" :key="index">
                            <span v-html="'{{' + code + '}}'"></span>
                            {{ $t('or') }}
                            <span v-html="'##' + code + '##'"></span>
                        </li>
                    </ul>
                </el-alert>
            </el-form>
        </div>

        <el-dialog v-model="showPreview" :title="$t('Previewing Email')" :width="800"
                   :close-on-click-modal="true" :close-on-press-escape="true"
                   :before-close="() => { showPreview = false; }">
            <PreviewEmail v-if="showPreview" :email_id="email_id"
                          :email_data="{subject: settings?.email?.subject, body: settings?.email?.body}"/>
            <template #footer>
                <el-button type="primary" @click="showPreview = false">{{ $t('Close') }}</el-button>
            </template>
        </el-dialog>
    </div>
</template>
