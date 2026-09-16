<script type="text/babel">
import SettingRow from '../_SettingRow.vue';
import SettingToggle from '../_SettingToggle.vue';

/**
 * The two settings that only apply once magic login is on hang off the switch that turns
 * it on, rather than appearing as two more rows of the card. Where a setting sits should
 * say what it depends on.
 */
export default {
    name: 'MagicLoginSection',
    components: {SettingRow, SettingToggle},
    props: {
        settings: {type: Object, required: true},
        user_roles: {type: Array, default: () => []}
    }
};
</script>

<template>
    <div>
        <SettingToggle v-model="settings.magic_login"
                       :label="$t('Enable magic login')"
                       :description="$t('Signing in from a link sent to the account address, with no password.')">
            <template v-if="settings.magic_login === 'yes'">
                <SettingRow :label="$t('Roles it is not offered to')"
                            :description="$t('Leave empty to offer it to everyone.')">
                    <el-select :placeholder="$t('Offered to every role')" clearable :multiple="true"
                               v-model="settings.magic_restricted_roles">
                        <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                                   :key="role.id"></el-option>
                    </el-select>
                </SettingRow>

                <SettingRow :label="$t('Make it the primary method')"
                            :description="$t('Shows the link form first, with the password form behind a link.')">
                    <el-switch v-model="settings.magic_link_primary" active-value="yes"
                               inactive-value="no"/>
                </SettingRow>
            </template>
        </SettingToggle>
    </div>
</template>
