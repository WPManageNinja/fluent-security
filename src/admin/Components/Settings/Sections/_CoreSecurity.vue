<script type="text/babel">
import SettingToggle from '../_SettingToggle.vue';

/**
 * Every setting here is stored as `disable_*` - the switch turns a restriction on, not a
 * feature. So each one is named after what switching it on does.
 *
 * They used to be named after the feature instead: a switch labelled "XML-RPC", on,
 * meant XML-RPC was off. The note under it read "switched on here means application
 * passwords are turned off", which is the label admitting it was backwards.
 *
 * Four switches with a line each, so they go two abreast rather than down a column of
 * full-width rows with most of each row empty.
 */
export default {
    name: 'CoreSecuritySection',
    components: {SettingToggle},
    props: {settings: {type: Object, required: true}}
};
</script>

<template>
    <div>
        <div class="fls_grid_2">
            <SettingToggle v-model="settings.disable_xmlrpc" recommend="yes"
                           :label="$t('Block XML-RPC requests')"
                           :description="$t('An older way for apps to sign in, now used mostly for guessing passwords. The WordPress mobile app may still need it.')"/>

            <!--
                No recommendation on purpose. Blocking these is sound hardening on a site
                that does not use them and breaks every integration on a site that does, so
                there is no answer to recommend - which is why "apply recommended" leaves
                them enabled, and why flagging them here would contradict it.
            -->
            <SettingToggle v-model="settings.disable_app_login"
                           :label="$t('Block application passwords')"
                           :description="$t('Outside apps and services connect with these. Turning this on disconnects them.')"/>

            <SettingToggle v-model="settings.disable_users_rest" recommend="yes"
                           :label="$t('Hide usernames from the public')"
                           :description="$t('By default anyone can look up your usernames, which gives an attacker half of what they need.')"/>

            <SettingToggle v-model="settings.secure_signup_form" recommend="yes"
                           :label="$t('Verify email addresses on signup')"
                           :description="$t('New users get a code by email and must enter it before the account is created.')"/>
        </div>

        <!--
            Under the whole grid rather than under the switch it belongs to, which is where
            it started. A column of the grid is about 430px, and seven lines of warning in
            one cell leave the cell beside it empty for the same seven lines - the reader
            gets a hole in the page as well as the warning. Full width it is two lines, and
            the title names the setting, so nothing is lost by the extra inch of distance.

            Shown only while the switch is on, the way the recommendation note is shown only
            while a setting differs from it: a consequence that is not happening yet is a
            warning nobody is still reading by the time it is.

            What it says is the part that surprises people. Nothing else on the screen says
            that passwords already issued stop working too, and an integration that has been
            running quietly for a year is exactly the one whose breakage gets blamed on
            something else.
        -->
        <el-alert v-if="settings.disable_app_login === 'yes'" type="warning"
                  :closable="false" show-icon class="fls_row_alert"
                  :title="$t('Anything connected with an application password will stop working')">
            {{ $t('Backup services, mobile apps and site management tools set up with one will stop working as soon as you save. Signing in through a browser is not affected.') }}
        </el-alert>
    </div>
</template>
