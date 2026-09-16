<script type="text/babel">
import SettingRow from '../_SettingRow.vue';
import SettingToggle from '../_SettingToggle.vue';

export default {
    name: 'NotificationsSection',
    components: {SettingRow, SettingToggle},
    props: {
        settings: {type: Object, required: true},
        user_roles: {type: Array, default: () => []}
    },
    data() {
        return {
            digest_items: {
                daily: this.$t('Daily'),
                sun: this.$t('Every Sunday'),
                mon: this.$t('Every Monday'),
                tue: this.$t('Every Tuesday'),
                wed: this.$t('Every Wednesday'),
                thu: this.$t('Every Thursday'),
                fri: this.$t('Every Friday'),
                sat: this.$t('Every Saturday'),
                monthly: this.$t('Monthly, on the 1st')
            }
        }
    },
    computed: {
        wantsEmail() {
            return this.settings.notification_user_roles.length
                || this.settings.notify_on_blocked === 'yes'
                || this.settings.digest_summary;
        }
    }
};
</script>

<template>
    <div>
        <SettingRow :label="$t('Tell me when these roles sign in')"
                    :description="$t('You get an email each time someone with one of these roles signs in.')">
            <el-select clearable :multiple="true" v-model="settings.notification_user_roles"
                       :placeholder="$t('No sign-in notifications')">
                <el-option v-for="role in user_roles" :value="role.id" :label="role.title"
                           :key="role.id"></el-option>
            </el-select>
        </SettingRow>

        <SettingToggle v-model="settings.notify_on_blocked"
                       :label="$t('Tell me when someone is blocked')"
                       :description="$t('Emails you when the plugin blocks a login attempt. No more than one a minute, however many are blocked.')"/>

        <SettingRow :label="$t('Summary report')"
                    :description="$t('A count of successful, failed and blocked logins for the period. Nothing is sent if there were none.')">
            <el-select v-model="settings.digest_summary">
                <el-option value="" :label="$t('Do not send a summary')"></el-option>
                <el-option v-for="(day, dayName) in digest_items" :key="dayName"
                           :value="dayName" :label="day"></el-option>
            </el-select>
        </SettingRow>

        <SettingRow v-if="wantsEmail" :label="$t('Send them to')"
                    :description="$t('{admin_email} is the admin email from your site\'s General Settings. Separate several addresses with commas.')">
            <el-input type="text" v-model="settings.notification_email"/>
        </SettingRow>
    </div>
</template>
