<template>
    <div class="dashboard box_wrapper">
        <div class="box dashboard_box box_narrow">
            <div v-loading="loading" class="box_header" style="padding: 15px;font-size: 16px;">
                {{ $t('Login/Signup Page Customizer') }}
                <div class="box_actions">

                </div>
            </div>
            <div v-if="settings" v-loading="saving" class="box_body">
                <el-form :data="settings" label-position="top">
                    <el-form-item class="fls_switch">
                        <el-switch @change="saveSettings" :disabled="saving" v-model="settings.status"
                                   active-value="yes" inactive-value="no"/>
                        {{ $t('Use Customized & Modern Style for Login/Signup Page') }}
                    </el-form-item>
                </el-form>
                
                <div v-if="settings.status == 'yes'" style="margin-top: 20px;">
                    <el-button @click="$router.push({name: 'auth_customizer'})" type="primary">
                        {{ $t('Open Login/Signup Page Customizer') }}
                    </el-button>
                </div>
            </div>
        </div>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'AuthCustomizerSettings',
    data() {
        return {
            settings: null,
            loading: false,
            saving: false,
        }
    },
    methods: {
        getSettings() {
            this.loading = true;
            this.$get('auth-customizer')
                .then(response => {
                    this.settings = response.settings;
                })
                .catch((error) => {
                    this.$handleError(error);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        saveSettings() {
            this.saving = true;
            this.$post('auth-customizer', {
                settings: this.settings
            })
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch((error) => {
                    this.$handleError(error);
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    },
    mounted() {
        this.getSettings();
    }
}
</script>
