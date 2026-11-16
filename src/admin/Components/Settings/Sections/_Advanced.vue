<script type="text/babel">
import SettingRow from '../_SettingRow.vue';
import InlineSentence from '../_InlineSentence.vue';

/**
 * Keeping roles out of wp-admin used to be two settings: a switch, and the list of roles
 * it applied to. The switch never carried any meaning of its own - switched on with no
 * roles chosen it did nothing, because both handlers return early on an empty list - so
 * it is gone and the list is the whole setting. `disable_admin_bar` is still stored; the
 * server derives it from the list on save, so the two cannot disagree.
 */
export default {
    name: 'AdvancedSection',
    components: {SettingRow, InlineSentence},
    props: {
        settings: {type: Object, required: true},
        low_level_roles: {type: Object, default: () => ({})}
    }
};
</script>

<template>
    <div>
        <SettingRow :description="$t('Use 0 to keep them forever.')">
            <template #label>
                <!-- translators: %s is a number field for days -->
                <InlineSentence :text="$t('Delete logs older than %s days')">
                    <template #field1>
                        <el-input type="number" :min="0" v-model="settings.auto_delete_logs_day"/>
                    </template>
                </InlineSentence>
            </template>
        </SettingRow>

        <SettingRow :label="$t('Keep these roles out of wp-admin')"
                    :description="$t('They land on the front page instead, with no admin bar. Anyone who can publish posts still gets in.')">
            <el-select clearable :multiple="true" v-model="settings.disable_bar_roles"
                       :placeholder="$t('Everyone can reach wp-admin')">
                <el-option v-for="(role, roleId) in low_level_roles" :value="roleId"
                           :label="role" :key="roleId"></el-option>
            </el-select>
        </SettingRow>
    </div>
</template>
