<script type="text/babel">
import SettingToggle from '../_SettingToggle.vue';

/**
 * Every setting here is stored as `disable_*` - the switch turns a restriction on, not a
 * feature. So each one is named after what switching it on does.
 *
 * They used to be named after the feature instead: a switch labelled "XML-RPC", on,
 * meant XML-RPC was off. The note under it read "switched on here means application
 * passwords are turned off", which is the label admitting it was backwards.
 */
export default {
    name: 'CoreSecuritySection',
    components: {SettingToggle},
    props: {settings: {type: Object, required: true}}
};
</script>

<template>
    <div>
        <SettingToggle v-model="settings.disable_xmlrpc" recommend="yes"
                       :label="$t('Block XML-RPC requests')"
                       :description="$t('An old remote publishing interface almost no site still uses. One request can carry many password guesses.')"/>

        <!--
            No recommendation on purpose. Blocking these is sound hardening on a site
            that does not use them and breaks every integration on a site that does, so
            there is no answer to recommend - which is why "apply recommended" leaves
            them enabled, and why flagging them here would contradict it.
        -->
        <SettingToggle v-model="settings.disable_app_login"
                       :label="$t('Block application passwords')"
                       :description="$t('These let external apps sign in over the REST API. Leave this off only if something connects that way.')"/>

        <SettingToggle v-model="settings.disable_users_rest" recommend="yes"
                       :label="$t('Hide usernames from the public')"
                       :description="$t('WordPress will otherwise hand out your usernames to anyone who asks, through the REST API, author id lookups and the user sitemap. Those names are half of every password guess.')"/>

        <SettingToggle v-model="settings.secure_signup_form" recommend="yes"
                       :label="$t('Verify email addresses on signup')"
                       :description="$t('Replaces the default registration form with one that confirms the address before the account can be used.')"/>
    </div>
</template>
