<script type="text/babel">
import SettingsHeader from '../Settings/_SettingsHeader.vue';
import SettingsCard from '../Settings/_SettingsCard.vue';
import SettingRow from '../Settings/_SettingRow.vue';
import RuleCard from './_RuleCard.vue';
import Destination from './_Destination.vue';

/**
 * Login and logout redirects.
 *
 * The screen is one sentence read downwards: everyone goes here, unless they match one of
 * these. So the defaults come first and the exceptions follow, in the order they are
 * actually tested in - because the first match is the one used, and a list whose order
 * decides the outcome has to be re-orderable from the screen.
 *
 * The rules themselves are closed until opened (see _RuleCard.vue), and "Add rule" sits
 * under the list rather than in the card header: a new rule is appended to the bottom, so
 * that is where the button that makes one belongs. With eight rules on the page, a button
 * at the top means scrolling up to add and scrolling back down to fill it in.
 */
export default {
    name: 'LoginRedirectSettings',
    components: {SettingsHeader, SettingsCard, SettingRow, RuleCard, Destination},
    data() {
        return {
            settings: false,
            saving: false,
            errors: false,
            roles: {},
            user_capabilities: {},
            destinations: {login: [], logout: []},
            /*
             * Which rules are open. Kept by key rather than by index so that moving or
             * removing a rule does not leave a different one open in its place - and
             * keyed at all because `v-for` over an index re-uses the wrong component the
             * moment two rules swap places.
             */
            openKeys: [],
            lastKey: 0
        };
    },
    computed: {
        enabled() {
            return this.settings && this.settings.login_redirects === 'yes';
        },
        rules() {
            return (this.settings && this.settings.redirect_rules) || [];
        }
    },
    methods: {
        getSettings() {
            this.$get('auth-forms-settings')
                .then(response => {
                    this.roles = response.roles;
                    this.user_capabilities = response.user_capabilities;
                    this.destinations = response.destinations;

                    const settings = response.settings;
                    settings.redirect_rules = Object.values(settings.redirect_rules || [])
                        .map(rule => this.prepareRule(rule));

                    this.settings = settings;
                })
                .catch(errors => {
                    this.$handleError(errors);
                });
        },
        /* A rule as the screen needs it: an identity of its own, and conditions to loop. */
        prepareRule(rule) {
            return {
                _key: ++this.lastKey,
                login: rule.login || '',
                logout: rule.logout || '',
                conditions: Object.values(rule.conditions || []).map(condition => ({
                    condition: condition.condition || 'user_role',
                    // Stored and sent, though only one comparison has ever been supported.
                    operator: condition.operator || 'in',
                    values: Object.values(condition.values || [])
                }))
            };
        },
        addRule() {
            const rule = this.prepareRule({
                conditions: [{condition: 'user_role', operator: 'in', values: []}]
            });

            this.settings.redirect_rules.push(rule);
            this.openKeys.push(rule._key);
        },
        removeRule(index) {
            const [removed] = this.settings.redirect_rules.splice(index, 1);
            this.openKeys = this.openKeys.filter(key => key !== removed._key);
        },
        moveRule(index, direction) {
            const rules = this.settings.redirect_rules;
            const target = index + direction;

            if (target < 0 || target >= rules.length) {
                return;
            }

            rules.splice(target, 0, rules.splice(index, 1)[0]);
        },
        toggleRule(key) {
            this.openKeys = this.openKeys.includes(key)
                ? this.openKeys.filter(openKey => openKey !== key)
                : this.openKeys.concat(key);
        },
        saveSettings() {
            // Nothing loaded means nothing to save - posting now would overwrite with blanks.
            if (!this.settings) {
                return;
            }

            this.errors = false;
            this.saving = true;

            this.$post('auth-forms-settings', {
                redirect_settings: {
                    login_redirects: this.settings.login_redirects,
                    default_login_redirect: this.settings.default_login_redirect,
                    default_logout_redirect: this.settings.default_logout_redirect,
                    // Without the key the screen keeps to itself.
                    redirect_rules: this.rules.map(({_key, ...rule}) => rule)
                }
            })
                .then(response => {
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                    this.errors = errors.data;
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    },
    mounted() {
        this.getSettings();
    }
};
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('Login Redirects')"
                        :description="$t('Where people land after signing in and after signing out.')"
                        :saving="saving" :disabled="!settings" @save="saveSettings()"/>

        <div class="fls_settings_content">
            <el-skeleton v-if="!settings" :animated="true" :rows="6"/>

            <template v-else>
                <SettingsCard :title="$t('Custom redirects')"
                              :description="$t('With this off, WordPress decides where people go, which is usually the dashboard.')">
                    <template #actions>
                        <el-switch v-model="settings.login_redirects" active-value="yes" inactive-value="no"/>
                    </template>
                </SettingsCard>

                <template v-if="enabled">
                    <SettingsCard :title="$t('Everyone')"
                                  :description="$t('Where people go unless a rule below says otherwise.')">
                        <SettingRow :label="$t('After signing in')"
                                    :description="$t('Someone who was sent to the login page from a public page still goes back there afterwards.')">
                            <Destination v-model="settings.default_login_redirect"
                                         :presets="destinations.login"/>
                        </SettingRow>

                        <SettingRow :label="$t('After signing out')">
                            <Destination v-model="settings.default_logout_redirect"
                                         :presets="destinations.logout"/>
                        </SettingRow>
                    </SettingsCard>

                    <SettingsCard :title="$t('Exceptions')"
                                  :description="$t('Send particular people somewhere else instead.')">
                        <!--
                            Said above the list rather than under it: the order of these is
                            the whole behaviour, and it is not something to discover after
                            writing four rules that never fire.
                        -->
                        <p v-if="rules.length" class="fls_note">
                            {{ $t('The first rule that matches a person is the one used, so put the most specific rule at the top. Anyone who matches no rule follows the defaults above.') }}
                        </p>

                        <div v-if="rules.length" class="fls_rules">
                            <RuleCard v-for="(rule, ruleIndex) in rules" :key="rule._key"
                                      :rule="rule"
                                      :index="ruleIndex"
                                      :total="rules.length"
                                      :open="openKeys.includes(rule._key)"
                                      :roles="roles"
                                      :capabilities="user_capabilities"
                                      :destinations="destinations"
                                      @toggle="toggleRule(rule._key)"
                                      @remove="removeRule(ruleIndex)"
                                      @move="moveRule(ruleIndex, $event)"/>
                        </div>

                        <p v-else class="fls_note">
                            {{ $t('No rules yet. Everyone follows the defaults above.') }}
                        </p>

                        <div class="fls_rules_add">
                            <el-button @click="addRule()">{{ $t('Add rule') }}</el-button>
                        </div>
                    </SettingsCard>
                </template>

                <div class="fls_errors" v-if="errors">
                    <ul>
                        <li v-for="(error, errorKey) in errors" :key="errorKey" v-html="convertToText(error)"></li>
                    </ul>
                </div>
            </template>
        </div>
    </div>
</template>
