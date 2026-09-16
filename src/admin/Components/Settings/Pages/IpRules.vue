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
                      :title="$t('Address rules are switched off in wp-config.php')">
                {{ $t('%s is set, so nothing is being refused by address: the block list is not applied and neither is the role restriction below. Remove the constant once the lists are right again.', 'FLUENT_AUTH_DISABLE_IP_RESTRICTION') }}
            </el-alert>

            <SettingsCard :title="$t('Allow list')"
                          :description="$t('These addresses are never locked out by the failed attempt limit.')">
                <!--
                    Said before the box rather than after it: somebody reading this to decide
                    whether an allow list is safe should not have to scroll past the field
                    that adds one to find out what it does not do.
                -->
                <p class="fls_note">
                    {{ $t('Being on this list skips the failed attempt limit and nothing else. It is not a trusted network: two-factor authentication still applies, and every attempt is still written to the log.') }}
                </p>

                <el-alert v-if="allow_paused" type="warning" :closable="false" show-icon
                          class="fls_row_alert"
                          :title="$t('The allow list is paused')">
                    {{ $t('Something in front of this site is relaying requests, and no proxy has been declared - so every visitor arrives as the same address. Exempting that address would exempt everyone, so nothing on this list is being applied.') }}
                    <router-link :to="{name: 'settings_general', query: {section: 'visitor_ip'}}">
                        {{ $t('Set up the proxy') }}
                    </router-link>
                </el-alert>

                <el-input v-model="allow" type="textarea" :rows="6" spellcheck="false"
                          class="fls_rules_box" placeholder="203.0.113.4&#10;198.51.100.0/24"/>

                <p class="fls_note">
                    {{ $t('One address or range per line, at most %s.', max_entries) }}
                    <template v-if="current_ip_listed">
                        {{ $t('Your address right now is %s, which this list covers.', current_ip) }}
                    </template>
                    <template v-else>
                        {{ $t('Your address right now is %s.', current_ip) }}
                        <a href="#" @click.prevent="addCurrentIp()">{{ $t('Add it') }}</a>
                    </template>
                </p>
            </SettingsCard>

            <SettingsCard :title="$t('Restrict sign-in to the allow list')"
                          :description="$t('Pick the roles that may only sign in from an address on the allow list above. Everyone else is unaffected.')">
                <div class="fls_row fls_row_stacked">
                    <div class="fls_row_label">
                        <label>{{ $t('Restricted roles') }}</label>
                        <p>
                            {{ $t('Anyone in these roles signing in from anywhere else is refused - by password, by magic link, by social login and over the REST API alike.') }}
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
                          :title="$t('Your own address is not on the allow list')">
                    {{ $t('Saving this would lock you out immediately, so it will be refused. Add %s to the allow list first.', current_ip) }}
                </el-alert>

                <p class="fls_note">
                    {{ $t('If the allow list is ever emptied, the restriction stops applying rather than locking everyone out. A %s constant in wp-config.php turns it off outright, along with the block list below.', 'FLUENT_AUTH_DISABLE_IP_RESTRICTION') }}
                </p>
            </SettingsCard>

            <SettingsCard :title="$t('Block list')"
                          :description="$t('These addresses are refused before a password is even checked.')">
                <el-input v-model="block" type="textarea" :rows="6" spellcheck="false"
                          class="fls_rules_box" placeholder="45.148.10.72&#10;45.148.10.0/24"/>

                <!--
                    The one rule on this screen that can be aimed at the person writing it,
                    so the way back in is written down next to it rather than left to be
                    found in the documentation of a site they can no longer open.
                -->
                <p class="fls_note">
                    {{ $t('One address or range per line, at most %s. The dashboard lists the addresses trying hardest to get in, with a button to block each one.', max_entries) }}
                </p>

                <p class="fls_note">
                    {{ $t('Your own address cannot be added here - saving refuses it. If you are ever locked out by a rule anyway, because your address changed or somebody else added it, %s in wp-config.php switches every address rule off.', 'FLUENT_AUTH_DISABLE_IP_RESTRICTION') }}
                </p>
            </SettingsCard>
        </div>
    </div>
</template>
