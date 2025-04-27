<template>
    <div class="fcom_full_editor">
        <el-container>
            <el-header class="fcom_full_editor_header_wrap">
                <div class="fcom_full_editor_header">
                    <el-button @click="$router.push({name: 'auth_shortcodes'})" class="fcom_back_header">
                        <el-icon>
                            <ArrowLeftBold />
                        </el-icon>
                        <span>{{ $t('Back') }}</span>
                    </el-button>
                    <div class="fcom_editor_menu object_menu">
                        <ul class="fcom_space_menu_ul">
                            <li @click.prevent="currentTab = 'login'">
                                <a :class="{ 'router-link-exact-active': currentTab == 'login' }" href="#">
                                    {{ $t('Login') }}
                                </a>
                            </li>
                            <li @click.prevent="currentTab = 'signup'">
                                <a :class="{ 'router-link-exact-active': currentTab == 'signup' }" href="#">
                                    {{ $t('Sign Up') }}
                                </a>
                            </li>
                        </ul>
                    </div>
                    <div class="full_editor_actions">
                        <el-button type="primary" :disabled="saving" v-loading="saving"
                                   @click="saveSettings">
                            <span>{{ $t('Save Changes') }}</span>
                        </el-button>
                    </div>
                </div>
            </el-header>
            <el-container class="fcom_full_editor_container">
                <template v-if="!loading">
                    <auth-editor :currentTab="currentTab" :savingCount="savingCount" :auth-settings="authSettings"
                                 @updateAuthSettings="updateAuthSettings"/>
                </template>
                <template v-else>
                    <el-aside class="fcom_full_editor_side lockscreen_editor">
                        <el-skeleton :animated="true" :rows="5"/>
                    </el-aside>
                    <el-main class="fcom_full_editor_main lockscreen_editor">
                        <el-skeleton :animated="true" :rows="10"/>
                    </el-main>
                </template>
            </el-container>
        </el-container>
    </div>
</template>

<script type="text/babel">
import AuthEditor from "./_AuthEditor.vue";

export default {
    name: 'AuthCustomizer',
    emits: ['completed'],
    components: {
        AuthEditor
    },
    data() {
        return {
            saving: false,
            loading: false,
            currentTab: 'login',
            savingCount: 0,
            authSettings: {
                login: [],
                signup: []
            },
            hasPro: true
        }
    },
    methods: {
        getSettings() {
            this.loading = true;
            this.$get('auth-customizer')
                .then(response => {
                    this.authSettings = response.settings;
                })
                .catch((error) => {
                    this.$handleError(error);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        saveSettings() {
            this.savingCount++;
        },
        updateAuthSettings(settings) {
            this.authSettings = settings;
        }
    },
    mounted() {
        this.getSettings();
        // add class to body
        document.body.classList.add('fcom_full_editor_body');
    },
    beforeDestroy() {
        // remove class from body
        document.body.classList.remove('fcom_full_editor_body');
    },
}
</script>
