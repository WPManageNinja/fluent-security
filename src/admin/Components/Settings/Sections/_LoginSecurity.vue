<script type="text/babel">
import SettingRow from '../_SettingRow.vue';

/**
 * The attempt limit is two numbers that mean nothing apart, so it is set as the one
 * sentence they make. As two labelled fields it took three rows - a field, a field, and
 * a hint underneath restating both as a sentence, which is the form admitting what it
 * should have been.
 *
 * It is the only setting here. The card used to carry a row saying the activity log is
 * always on, with a badge reading "Always on" where a control would be - a row that
 * could not be changed, in a form, which is a statement wearing a setting's clothes.
 */
export default {
    name: 'LoginSecuritySection',
    components: {SettingRow},
    props: {settings: {type: Object, required: true}}
};
</script>

<template>
    <SettingRow :description="$t('Counted per IP address. Each new attempt while blocked restarts the clock.')">
        <template #label>
            <span class="fls_sentence">
                {{ $t('Block an IP address after') }}
                <el-input type="number" :min="1" v-model="settings.login_try_limit"/>
                {{ $t('failed attempts within') }}
                <el-input type="number" :min="1" v-model="settings.login_try_timing"/>
                {{ $t('minutes') }}
            </span>
        </template>
    </SettingRow>
</template>
