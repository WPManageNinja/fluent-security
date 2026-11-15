<script type="text/babel">
import SettingRow from '../_SettingRow.vue';
import SettingToggle from '../_SettingToggle.vue';
import InlineSentence from '../_InlineSentence.vue';

export default {
    name: 'SessionsSection',
    components: {SettingRow, SettingToggle, InlineSentence},
    props: {settings: {type: Object, required: true}}
};
</script>

<template>
    <div>
        <SettingRow :description="$t('Closing the browser also signs people out, unless the browser reopens the last session.')">
            <template #label>
                <!-- translators: %s is a number field for days -->
                <InlineSentence :text="$t('If Remember Me is off, sign people out after %s days')">
                    <template #field1>
                        <el-input type="number" :min="1" :max="365" v-model="settings.session_days"/>
                    </template>
                </InlineSentence>
            </template>
        </SettingRow>

        <SettingRow :description="$t('Sign-ins with Google, GitHub, Facebook or a passkey always use this length. So do new accounts after sign-up.')">
            <template #label>
                <!-- translators: %s is a number field for days -->
                <InlineSentence :text="$t('If Remember Me is on, keep people signed in for %s days')">
                    <template #field1>
                        <el-input type="number" :min="1" :max="365" v-model="settings.remember_days"/>
                    </template>
                </InlineSentence>
            </template>
        </SettingRow>

        <SettingToggle v-model="settings.remember_default"
                       :label="$t('Check Remember Me by default')"
                       :description="$t('Magic links follow this choice too. On a login form, people can still uncheck the box.')"/>

        <p class="fls_note">
            {{ $t('Changes apply to the next sign-in. People who are signed in now keep their current session.') }}
        </p>
    </div>
</template>
