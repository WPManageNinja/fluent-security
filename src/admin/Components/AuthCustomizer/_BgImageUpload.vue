<template>
    <el-upload
        :action="action_url"
        :headers="headers"
        accept="image/*"
        class="fcom_bg_upload"
        :multiple="is_multiple"
        :data="additional_data"
        :show-file-list="false"
        :on-success="handleSuccess"
        :on-error="handleError"
    >
        <slot name="trigger">
            <slot name="default">
                <el-image :alt="$t('Image Preview')" v-if="imageUrl" :src="imageUrl"/>
                <el-button v-else class="fcom_btn_upload" text>{{ button_text }}</el-button>
            </slot>
        </slot>
    </el-upload>
    <el-button v-if="imageUrl && can_remove" class="fcom_bg_remove" text size="small" @click="removeImage">
        <el-icon><CloseBold /></el-icon>
    </el-button>
</template>

<script>
export default {
    name: 'BgImageUpload',
    emits: ['update:modelValue'],
    props: {
        modelValue: {
            type: String,
            required: false
        },
        button_text: {
            type: String,
            default: 'Upload Image'
        },
        can_remove: {
            type: Boolean,
            default: false
        },
        is_multiple: {
            type: Boolean,
            default: false
        },
        additional_data: {
            type: Object,
            default: () => ({})
        }
    },
    data() {
        return {
            imageUrl: this.modelValue
        }
    },
    computed: {
        action_url() {
            return this.appVars.rest.url + '/feeds/media-upload'
        },
        headers() {
            return {
                'X-WP-Nonce': this.appVars.rest.nonce
            }
        }
    },
    methods: {
        handleSuccess(response) {
            this.imageUrl = response.media.url;
            this.$emit('update:modelValue', this.imageUrl);
        },
        handleError(error) {
            this.$handleError(JSON.parse(error.message));
        },
        removeImage() {
            this.imageUrl = '';
            this.$emit('update:modelValue', '');
        }
    }
}
</script>
