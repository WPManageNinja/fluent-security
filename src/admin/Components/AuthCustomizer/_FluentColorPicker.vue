<template>
    <div class="fcom_color_item">
        <el-color-picker :predefine="appVars.suggestedColors" ref="colorPicker"
                         @active-change="(val) => { color = val }" v-model="color"/>
        <label style="cursor: pointer;" class="fcom_color_label" @click="showColorPicker">
            {{ label }}
        </label>

        <el-tooltip v-if="help_msg" :content="help_msg" placement="right">
            <el-icon class="fcom_tip">
                <InfoFilled/>
            </el-icon>
        </el-tooltip>
    </div>
</template>

<script>
import {InfoFilled} from "@element-plus/icons-vue";

export default {
    name: 'FComColorPicker',
    components: {InfoFilled},
    props: ['modelValue', 'label', 'help_msg'],
    emits: ['update:modelValue', 'change'],
    data() {
        return {
            color: this.modelValue
        };
    },
    watch: {
        color(val) {
            this.$emit('update:modelValue', val);
            this.$emit('change', val);
        }
    },
    methods: {
        showColorPicker() {
            this.$refs.colorPicker.show();
        }
    }
}
</script>
