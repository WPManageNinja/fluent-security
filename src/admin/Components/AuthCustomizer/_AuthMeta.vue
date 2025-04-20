<template>
    <div v-if="!editing" class="fcom_lockscreen_meta">
        <div class="fcom_meta_section lockscreen_meta">
            <div class="fcom_description" v-if="currentTab == 'login'">
                <p>{{ $t('Configure the appearance and behavior of your login form.') }}</p>
            </div>
            <div class="fcom_description" v-if="currentTab == 'signup'">
                <p>{{ $t('Configure the appearance and behavior of your signup form.') }}</p>
            </div>
        </div>
        <div class="fcom_meta_section lockscreen_meta">
            <div class="fcom_meta_label" v-if="currentTab == 'login'"> {{ $t('Customize Login') }}</div>
            <div class="fcom_meta_label" v-if="currentTab == 'signup'"> {{ $t('Customize Sign Up') }}</div>
            <div class="fcom_meta_content">
                <ul class="fcom_meta_block">
                    <template v-for="field in sortedFields">
                        <li :class="['fcom_block_list', { block_hidden: field.hidden }]">
                            <div @click="updateField(field)" class="fcom_block_label">
                                <el-icon class="fcom_el_icon">
                                    <component :is="getFieldIcon(field)"/>
                                </el-icon>
                                <p>{{ getLabel(field.type) }}</p>
                            </div>
                            <div class="fcom_meta_sorting">
                                <el-icon @click="togglePosition">
                                    <Top/>
                                </el-icon>
                                <el-icon @click="togglePosition">
                                    <Bottom/>
                                </el-icon>
                            </div>
                            <div class="fcom_block_action">
                                <el-icon @click="updateField(field)">
                                    <EditPen/>
                                </el-icon>
                                <template v-if="field.type == 'banner'">
                                    <el-icon v-if="field.hidden" @click="toggleHidden(field)">
                                        <Hide/>
                                    </el-icon>
                                    <el-icon v-else @click="toggleHidden(field)">
                                        <View/>
                                    </el-icon>
                                </template>
                            </div>
                        </li>
                    </template>
                </ul>
            </div>
        </div>
    </div>
    <div v-else class="fcom_lockscreen_meta">
        <div class="fcom_edit_title">
            <el-icon @click="backToFields">
                <Back/>
            </el-icon>
            <p>{{ currentEditingField }}</p>
        </div>
        <div class="fcom_edit_content">
            <template v-if="isBannerField || isFormField">
                <h3>{{ $t('Content') }}</h3>
                <el-form @submit.prevent="doNothing()" label-position="top" class="fcom_form_container">
                    <el-form-item v-if="isBannerField" :label="$t('Logo')" class="fcom_bg_image">
                        <BgImageUpload v-model="editingField.logo" :can_remove="true"/>
                    </el-form-item>

                    <el-form-item :label="$t('Title')">
                        <el-input v-model="editingField.title" :placeholder="$t('Title')"></el-input>
                    </el-form-item>

                    <el-form-item :label="$t('Description')">
                        <el-input type="textarea" :rows="4" placeholder="Description"
                                  v-model="editingField.description"/>
                    </el-form-item>
                </el-form>
                <div v-if="isBannerField" :label="$t('Design')">
                    <h3>{{ $t('Design') }}</h3>
                    <el-form @submit.prevent="doNothing()" label-position="top" class="fcom_form_container">
                        <el-form-item :label="$t('Background Image')" class="fcom_bg_image">
                            <BgImageUpload v-model="editingField.background_image" :can_remove="true"/>
                        </el-form-item>

                        <FComColorPicker
                            :help_msg="$t('The main background color of the form')"
                            :label="$t('Background Color')"
                            v-model="editingField.background_color"/>

                        <FComColorPicker
                            :help_msg="$t('The title color of the form')"
                            :label="$t('Title Color')"
                            v-model="editingField.title_color"/>

                        <FComColorPicker
                            :help_msg="$t('The text color of the form')"
                            :label="$t('Text Color')"
                            v-model="editingField.text_color"/>

                        <FComColorPicker
                            v-if="isFormField"
                            :help_msg="$t('The button text color of the form')"
                            :label="$t('Button Text Color')"
                            v-model="editingField.button_label_color"/>

                        <FComColorPicker
                            v-if="isFormField"
                            :help_msg="$t('The button background color of the form')"
                            :label="$t('Button Background')"
                            v-model="editingField.button_color"/>
                    </el-form>
                </div>
            </template>
        </div>
    </div>
</template>

<script type="text/babel">
import BgImageUpload from "./_BgImageUpload.vue";
import FComColorPicker from './_FluentColorPicker.vue';
import {Top, Bottom, Hide, View, Back, Picture, Memo, Tickets, EditPen} from '@element-plus/icons-vue';

export default {
    name: 'AuthMeta',
    components: {BgImageUpload, FComColorPicker, Top, Bottom, Hide, View, Back, Picture, Memo, Tickets, EditPen},
    props: ['currentTab', 'settings', 'savingCount'],
    data() {
        return {
            editing: false,
            editTab: 'content',
            isDirty: false,
            editingField: null,
            formField: 'terms'
        }
    },
    watch: {
        currentTab() {
            this.editTab = 'content';
            this.editing = false;
            this.editingField = null;
            this.isDirty = false;
        },
        savingCount() {
            this.editing = false;
            this.editingField = null;
            this.isDirty = false;
        },
        editingField() {
            this.editTab = 'content';
        },
        'editingField.description'(newVal, oldVal) {
            if (newVal && oldVal && newVal !== oldVal && !this.isDirty) {
                this.isDirty = true;
            }
        }
    },
    computed: {
        getFieldIcon() {
            return (field) => {
                const icons = {
                    banner: 'Picture',
                    form: 'Memo',
                    fields: 'Tickets'
                };
                return icons[field.type] || 'Picture';
            }
        },
        sortedFields() {
            return Object.values(this.settings).sort((a, b) => {
                if (a.position === 'left') return -1;
                if (b.position === 'left') return 1;
                return 0;
            });
        },
        isBannerField() {
            return this.editingField.type == 'banner';
        },
        isFormField() {
            return this.editingField.type == 'form';
        },
        currentEditingField() {
            if (this.isBannerField) {
                return this.$t('Banner Settings');
            }
            return this.$t('Form Settings');
        }
    },
    methods: {
        getLabel(type) {
            const labels = {
                banner: this.$t('Banner'),
                form: this.$t('Form')
            };
            return labels[type] || this.$t('Banner');
        },
        toggleHidden(field) {
            field.hidden = !field.hidden;
        },
        updateField(field) {
            this.editing = true;
            this.editingField = field;
        },
        backToFields() {
            this.editing = false;
            this.editingField = null;
            this.isDirty = false;
            this.editTab = 'content';
        },
        togglePosition() {
            const bannerPosition = this.settings.banner?.position;
            this.settings.banner.position = this.settings.form?.position;
            this.settings.form.position = bannerPosition;
        }
    }
}
</script>
