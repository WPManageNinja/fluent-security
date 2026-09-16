<script type="text/babel">
import SettingsHeader from '../_SettingsHeader.vue';
import SettingsCard from '../_SettingsCard.vue';

/**
 * The IP allow and block lists.
 *
 * Its own screen with its own save, rather than a block on the general settings page.
 * Everything there lives in one option that is written whole by one Save button; these
 * lists are their own option with their own endpoint, and putting a second, independently
 * saved thing inside that form is how you end up with a Save button that saves some of
 * what is on screen.
 *
 * A text box per list, one address to a line. The question each list answers is "which
 * addresses?", and a row of fields per entry turns answering it into a form to fill in -
 * you cannot paste six addresses in from a log, and you have to decide what to call each
 * one before you can add it.
 *
 * The two lists are shown as one screen but they are not the same kind of thing, and the
 * copy says so: an allow list entry skips the attempt limit and nothing else.
 */
export default {
    name: 'IpRulesSettings',
    components: {SettingsHeader, SettingsCard},
    data() {
        return {
            loading: true,
            saving: false,
            allow: '',
            block: '',
            restricted_roles: [],
            roles: [],
            current_ip: '',
            current_ip_listed: false,
            allow_paused: false,
            restrictions_off: false,
            max_entries: 200
        }
    },
    methods: {
        fetchRules() {
            this.loading = true;

            this.$get('ip-rules')
                .then(response => {
                    this.applyState(response);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        applyState(state) {
            /*
             * Redrawn from what the server stored rather than left as typed, so a range
             * that was normalised or a line that was a duplicate shows as what it became.
             */
            this.allow = state.rules.allow.join('\n');
            this.block = state.rules.block.join('\n');
            this.restricted_roles = state.restricted_roles;
            this.roles = state.roles;
            this.current_ip = state.current_ip;
            this.current_ip_listed = state.current_ip_listed;
            this.allow_paused = state.allow_paused;
            this.restrictions_off = state.restrictions_off;
            this.max_entries = state.max_entries;
        },
        /* The current address, appended - it is the one people came here to add. */
        addCurrentIp() {
            this.allow = (this.allow.trim() + '\n' + this.current_ip).trim();
        },
        saveRules() {
            this.saving = true;

            this.$post('ip-rules', {
                rules: {allow: this.allow, block: this.block},
                restricted_roles: this.restricted_roles
            })
                .then(response => {
                    this.$notify.success(response.message);
                    this.applyState(response);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        }
    },
    mounted() {
        this.fetchRules();
    }
};
</script>

<template>
    <div>
        <SettingsHeader :heading="$t('IP Access Rules')"
                        :description="$t('Addresses that are never locked out, and addresses that are never let in.')"
                        :saving="saving" :disabled="loading" @save="saveRules()"/>

        <div class="fls_settings_content" v-loading="loading">
            <!--
                First thing on the screen, because a list that is not being applied looks
                exactly like one that is. Whoever added the constant to get back in is the
                same person who will later wonder why their block list does nothing.
            -->
            <el-alert v-if="restrictions_off" type="warning" :closable="false" show-icon
                      class="fls_row_alert"
                      :title="$t('IP rules are switched off in wp-config.php')">
                {{ $t('%s is set in wp-config.php, so the block list and the role restriction below are not being applied. Remove that line once your lists are fixed.', 'FLUENT_AUTH_DISABLE_IP_RESTRICTION') }}
            </el-alert>

            <SettingsCard :title="$t('Allowed addresses')"
                          :description="$t('These addresses are never locked out after too many failed logins.')">
                <!--
                    Said before the box rather than after it: somebody reading this to decide
                    whether an allow list is safe should not have to scroll past the field
                    that adds one to find out what it does not do.
                -->
                <p class="fls_note">
                    {{ $t('This only skips the lockout. Two-factor still applies and every attempt is still logged.') }}
                </p>

                <el-alert v-if="allow_paused" type="warning" :closable="false" show-icon
                          class="fls_row_alert"
                          :title="$t('This list is not being applied right now')">
                    {{ $t('Every visitor currently reaches this site from the same address, because a proxy in front of it has not been set up here. Until it is, this list is ignored, since allowing that one address would allow everyone.') }}
                    <router-link :to="{name: 'settings_general', query: {section: 'visitor_ip'}}">
                        {{ $t('Set up the proxy') }}
                    </router-link>
                </el-alert>

                <el-input v-model="allow" type="textarea" :rows="6" spellcheck="false"
                          class="fls_rules_box" placeholder="203.0.113.4&#10;198.51.100.0/24"/>

                <p class="fls_note">
                    {{ $t('One address or range per line, at most %s.', max_entries) }}
                    <template v-if="current_ip_listed">
                        {{ $t('Your current address is %s, and it is on this list.', current_ip) }}
                    </template>
                    <template v-else>
                        {{ $t('Your current address is %s.', current_ip) }}
                        <a href="#" @click.prevent="addCurrentIp()">{{ $t('Add it') }}</a>
                    </template>
                </p>
            </SettingsCard>

            <SettingsCard :title="$t('Only let some roles sign in from allowed addresses')"
                          :description="$t('These roles can only sign in from an address in the list above. Other roles are not affected.')">
                <div class="fls_row fls_row_stacked">
                    <div class="fls_row_label">
                        <label>{{ $t('Restricted roles') }}</label>
                        <p>
                            {{ $t('Anyone in these roles is refused from any other address, however they sign in.') }}
                        </p>
                    </div>
                    <div class="fls_row_control">
                        <el-select v-model="restricted_roles" multiple filterable
                                   :placeholder="$t('No role is restricted')">
                            <el-option v-for="role in roles" :key="role.id"
                                       :value="role.id" :label="role.title"/>
                        </el-select>
                    </div>
                </div>

                <!--
                    Shown before saving rather than as a rejection afterwards. Turning this
                    on from an address that is not on the list locks you out of the screen
                    that would let you undo it.
                -->
                <el-alert v-if="restricted_roles.length && !current_ip_listed" type="error"
                          :closable="false" show-icon class="fls_row_alert"
                          :title="$t('Your own address is not on the allowed list')">
                    {{ $t('Saving this would lock you out straight away, so it will be refused. Add %s to the allowed addresses first.', current_ip) }}
                </el-alert>

                <p class="fls_note">
                    {{ $t('If the allowed list is ever emptied, this restriction stops applying instead of locking everyone out. Adding %s to wp-config.php switches it off, along with the block list.', 'FLUENT_AUTH_DISABLE_IP_RESTRICTION') }}
                </p>
            </SettingsCard>

            <SettingsCard :title="$t('Blocked addresses')"
                          :description="$t('These addresses can never sign in, even with the right password.')">
                <el-input v-model="block" type="textarea" :rows="6" spellcheck="false"
                          class="fls_rules_box" placeholder="45.148.10.72&#10;45.148.10.0/24"/>

                <!--
                    The one rule on this screen that can be aimed at the person writing it,
                    so the way back in is written down next to it rather than left to be
                    found in the documentation of a site they can no longer open.
                -->
                <p class="fls_note">
                    {{ $t('One address or range per line, up to %s. The dashboard shows the addresses with the most failed logins and a Block button next to each.', max_entries) }}
                </p>

                <p class="fls_note">
                    {{ $t('You cannot block your own address. If you are ever locked out anyway, add %s to wp-config.php to switch every IP rule off and get back in.', 'FLUENT_AUTH_DISABLE_IP_RESTRICTION') }}
                </p>
            </SettingsCard>
        </div>
    </div>
</template>
