<script type="text/babel">
import SettingRow from '../Settings/_SettingRow.vue';
import Destination from './_Destination.vue';

/**
 * One redirect rule: who it applies to, and where they go.
 *
 * Closed by default, and closed it is still a sentence - "Administrator or Editor signs in
 * to Admin dashboard". That is the point of the summary: a site with eight rules is a list
 * to be read down and re-ordered, not eight open forms to scroll past. Anything wrong with
 * a rule is flagged on the closed row too, so a broken rule does not need opening to be
 * found.
 */
export default {
    name: 'RedirectRuleCard',
    components: {SettingRow, Destination},
    props: {
        rule: {type: Object, required: true},
        index: {type: Number, required: true},
        total: {type: Number, required: true},
        open: {type: Boolean, default: false},
        roles: {type: Object, default: () => ({})},
        capabilities: {type: Object, default: () => ({})},
        destinations: {type: Object, default: () => ({login: [], logout: []})}
    },
    emits: ['toggle', 'remove', 'move'],
    data() {
        return {
            /*
             * The two things a rule can be tested on. Both are facts about the person
             * signing in rather than about the request, which is why there is nothing
             * here about where they came from or what time it is.
             */
            conditionTypes: {
                user_role: this.$t('role'),
                user_capability: this.$t('capability')
            }
        };
    },
    computed: {
        /*
         * The rule in words. Roles and capabilities are gathered separately rather than
         * read out in the order they were added, because every condition has to be true
         * at once and only one arrangement of them is English: "Author who can edit_posts"
         * says what "can edit_posts and Author" was trying to.
         */
        whoText() {
            const roles = [];
            const capabilities = [];

            this.rule.conditions.forEach(condition => {
                const names = this.namesFor(condition.condition);
                const values = (condition.values || []).map(value => names[value] || value);

                if (!values.length) {
                    return;
                }

                (condition.condition === 'user_capability' ? capabilities : roles).push(this.joinAny(values));
            });

            const who = roles.join(' ' + this.$t('and') + ' ');
            const can = capabilities.join(' ' + this.$t('and') + ' ');

            if (who && can) {
                return this.$t('%1s who can %2s', who, can);
            }

            if (can) {
                return this.$t('Anyone who can %s', can);
            }

            return who || this.$t('Nobody yet');
        },
        loginLabel() {
            return this.destinationLabel(this.rule.login, 'login');
        },
        logoutLabel() {
            return this.destinationLabel(this.rule.logout, 'logout');
        },
        /*
         * The two ways a rule can be saved and still do nothing. Both are easy to create by
         * accident - add a rule, get called away, come back - and neither shows up anywhere
         * else, because a rule that never matches fails silently by design.
         */
        problem() {
            if (!this.rule.conditions.some(condition => (condition.values || []).length)) {
                return this.$t('Applies to no one');
            }

            if (!this.rule.login && !this.rule.logout) {
                return this.$t('No destination set');
            }

            return '';
        }
    },
    watch: {
        /* Opening the last rule on a long list should not leave its fields off-screen. */
        open(isOpen) {
            if (!isOpen) {
                return;
            }

            this.$nextTick(() => {
                this.$el.scrollIntoView({block: 'nearest', behavior: 'smooth'});
            });
        }
    },
    methods: {
        /* Any one of these will do, so the list is joined with "or" rather than commas. */
        joinAny(values) {
            if (values.length < 2) {
                return values[0] || '';
            }

            return values.slice(0, -1).join(', ') + ' ' + this.$t('or') + ' ' + values[values.length - 1];
        },
        namesFor(type) {
            return type === 'user_capability' ? this.capabilities : this.roles;
        },
        /* Named if it is one of the offered destinations, otherwise the address itself,
           with the site's own origin taken off so the interesting half is what is read. */
        destinationLabel(url, kind) {
            if (!url) {
                return '';
            }

            const preset = (this.destinations[kind] || []).find(item => item.url === url);

            if (preset) {
                return preset.label;
            }

            return url.replace(/^https?:\/\/[^/]+/, '') || url;
        },
        addCondition() {
            this.rule.conditions.push({
                condition: 'user_role',
                operator: 'in',
                values: []
            });
        },
        removeCondition(index) {
            this.rule.conditions.splice(index, 1);
        },
        /* Roles and capabilities are different lists, so the old picks cannot carry over. */
        resetValues(condition) {
            condition.values = [];
        }
    }
};
</script>

<template>
    <div class="fls_rule" :class="{is_open: open}">
        <div class="fls_rule_head">
            <button type="button" class="fls_rule_toggle" :aria-expanded="open ? 'true' : 'false'"
                    @click="$emit('toggle')">
                <span class="fls_rule_chevron dashicons"
                      :class="open ? 'dashicons-arrow-down-alt2' : 'dashicons-arrow-right-alt2'"></span>

                <span class="fls_rule_index">{{ index + 1 }}</span>

                <span class="fls_rule_sum">
                    <span class="fls_rule_who">{{ whoText }}</span>
                    <span v-if="loginLabel" class="fls_rule_dest">
                        <em>{{ $t('signs in to') }}</em> {{ loginLabel }}
                    </span>
                    <span v-if="logoutLabel" class="fls_rule_dest">
                        <em>{{ $t('signs out to') }}</em> {{ logoutLabel }}
                    </span>

                    <!-- Part of the summary rather than pinned beside it, so on a narrow
                         screen it wraps with the words instead of landing on top of them. -->
                    <span v-if="problem && !open" class="fls_tag is_warning">{{ problem }}</span>
                </span>
            </button>

            <div class="fls_rule_actions">
                <!-- Order is what decides which rule wins, so it is changed here rather
                     than by deleting a rule and adding it back in the right place. -->
                <el-button text :disabled="index === 0" :title="$t('Move up')"
                           @click="$emit('move', -1)">
                    <span class="dashicons dashicons-arrow-up-alt2"></span>
                </el-button>
                <el-button text :disabled="index === total - 1" :title="$t('Move down')"
                           @click="$emit('move', 1)">
                    <span class="dashicons dashicons-arrow-down-alt2"></span>
                </el-button>
                <el-button text :title="$t('Remove this rule')" @click="$emit('remove')">
                    <span class="dashicons dashicons-trash"></span>
                </el-button>
            </div>
        </div>

        <div v-if="open" class="fls_rule_body">
            <p class="fls_eyebrow">{{ $t('Who it applies to') }}</p>

            <div v-for="(condition, conditionIndex) in rule.conditions" :key="conditionIndex"
                 class="fls_condition">
                <span v-if="conditionIndex" class="fls_condition_join">{{ $t('and') }}</span>

                <div class="fls_condition_line">
                    <span class="fls_condition_word">{{ $t('their') }}</span>

                    <el-select v-model="condition.condition" class="fls_condition_type"
                               @change="resetValues(condition)">
                        <el-option v-for="(label, type) in conditionTypes" :key="type"
                                   :value="type" :label="label"/>
                    </el-select>

                    <span class="fls_condition_word">{{ $t('is one of') }}</span>

                    <!-- The picker and the button that removes it stay together, so a
                         line narrow enough to wrap does not leave the button stranded. -->
                    <div class="fls_condition_pick">
                        <el-select v-model="condition.values" class="fls_condition_values"
                                   multiple filterable collapse-tags-tooltip :max-collapse-tags="4"
                                   :placeholder="condition.condition === 'user_capability'
                                       ? $t('Pick one or more capabilities')
                                       : $t('Pick one or more roles')">
                            <el-option v-for="(label, value) in namesFor(condition.condition)"
                                       :key="value" :value="value" :label="label"/>
                        </el-select>

                        <el-button v-if="rule.conditions.length > 1" text
                                   :title="$t('Remove this condition')"
                                   @click="removeCondition(conditionIndex)">
                            <span class="dashicons dashicons-no-alt"></span>
                        </el-button>
                    </div>
                </div>

                <p v-if="!(condition.values || []).length" class="fls_rules_flag is_warning">
                    {{
                        rule.conditions.length > 1
                            ? $t('Nothing picked here, so this line is ignored.')
                            : $t('Pick at least one, or this rule never applies to anybody.')
                    }}
                </p>
            </div>

            <p class="fls_action_note">
                <a href="#" @click.prevent="addCondition()">{{ $t('Add another condition') }}</a>
                <span>{{ $t('Every line has to be true for the rule to apply.') }}</span>
            </p>

            <p class="fls_eyebrow">{{ $t('Where they go') }}</p>

            <SettingRow :label="$t('After signing in')"
                        :description="$t('Leave this as the default and they go where everyone else does.')">
                <Destination v-model="rule.login" :presets="destinations.login"
                             :empty-label="$t('Use the default')"/>
            </SettingRow>

            <SettingRow :label="$t('After signing out')"
                        :description="$t('Separate from sign-in. Leave this as the default and they go where everyone else does.')">
                <Destination v-model="rule.logout" :presets="destinations.logout"
                             :empty-label="$t('Use the default')"/>
            </SettingRow>
        </div>
    </div>
</template>
