<template>
    <div class="fls_rule">
        <div class="fls_rule_items">
            <div class="fls_rule_item">{{ $t('If') }}</div>
            <div style="min-width: 150px;" class="fls_rule_item">
                <el-select @change="resetValue()" v-model="rule.condition">
                    <el-option v-for="(provider, providerIndex) in providers"
                               :key="providerIndex"
                               :label="provider.title"
                               :value="providerIndex"></el-option>
                </el-select>
            </div>
            <template v-if="selectedRule">
                <div class="fls_rule_item">
                    {{ rule.operator }}
                </div>
                <div class="fls_rule_item fls_values">
                    <template v-if="selectedRule.type == 'role_selector'">
                        <el-select :multiple="selectedRule.is_multiple" v-model="rule.values">
                            <el-option v-for="(role, roleIndex) in roles"
                                       :key="roleIndex"
                                       :value="roleIndex" :label="role"></el-option>
                        </el-select>
                    </template>
                    <template v-else-if="selectedRule.type == 'capability_selector'">
                        <el-select :multiple="selectedRule.is_multiple" v-model="rule.values">
                            <el-option v-for="(cap, capIndex) in capabilities"
                                       :key="cap"
                                       :value="capIndex" :label="cap"></el-option>
                        </el-select>
                    </template>
                </div>
            </template>
            <template v-else>
                <div class="fls_rule_item">
                    {{ rule.operator }}
                </div>
                <div class="fls_rule_item fls_values">
                    <el-input :disabled="true" v-model="dummy_value"/>
                </div>
            </template>
        </div>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'RedirectRule',
    props: ['rule', 'providers', 'roles', 'capabilities'],
    data() {
        return {
            dummy_value: this.$t('Select Condition')
        }
    },
    computed: {
        selectedRule() {
            if (!this.rule.condition) {
                return false;
            }
            return this.providers[this.rule.condition];
        }
    },
    methods: {
        resetValue() {
            this.rule.values = [];
        }
    }
}
</script>
