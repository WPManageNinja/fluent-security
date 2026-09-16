<script type="text/babel">
import SettingRow from './Settings/_SettingRow.vue';

export default {
    name: 'ProxySettings',
    components: {SettingRow},
    props: {
        settings: {
            type: Object,
            required: true
        },
        detection: {
            type: Object,
            default: () => ({status: 'none', headers: []})
        },
        config_locked: {
            type: Boolean,
            default: false
        }
    },
    data() {
        return {
            revealed: false
        }
    },
    computed: {
        status() {
            return this.detection.status || 'none';
        },
        /*
         * A proxy that is there and declared is good news; one that is there and not is a
         * problem. Everything else - no sign of one, or a hint that is not evidence - is
         * neither, and is coloured as neither.
         */
        stateTone() {
            const tones = {
                cloudflare: 'is_success',
                detected: 'is_warning'
            };

            return tones[this.status] || 'is_neutral';
        },
        /*
         * Nothing is relaying this site's requests, or Cloudflare is and handles itself.
         * Almost every WordPress site is in one of those two states, and in neither is
         * there anything to read, decide or type - so the panel is one line saying which
         * one it is, and the diagnostic that argues the case is not drawn at all.
         *
         * Not removed, though: "no evidence" is not proof, and somebody who knows a proxy
         * is there needs a way in. The line carries it.
         */
        quiet() {
            if (this.revealed || this.config_locked) {
                return false;
            }

            if (this.settings.trusted_proxies || this.settings.proxy_ip_header) {
                return false;
            }

            return this.status === 'none' || this.status === 'cloudflare';
        },
        quietTitle() {
            return this.status === 'cloudflare'
                ? this.$t('Visitor addresses come from Cloudflare')
                : this.$t('Visitors connect to this site directly');
        },
        /*
         * Carries the address, which is the one fact the diagnostic this replaces was
         * worth reading for. Everything else it said was an argument for a conclusion
         * that now fits in the title.
         */
        quietNote() {
            if (this.status === 'cloudflare') {
                return this.$t('Nothing to set up here unless another proxy sits between Cloudflare and your server.');
            }

            return this.$t('Nothing to set up here. Your own visit arrived from %s.', this.detection.remote_addr || '—');
        },
        /* Cloudflare is a proxy already, so there is nothing to set up - only to add to. */
        quietAction() {
            return this.status === 'cloudflare'
                ? this.$t('Add another proxy')
                : this.$t('This site is behind a proxy');
        },
        headline() {
            const map = {
                detected: this.$t('A proxy sits in front of this site'),
                cloudflare: this.$t('Cloudflare detected'),
                possible: this.$t('This site might be behind a proxy'),
                none: this.$t('No proxy detected')
            };

            return map[this.status] || map.none;
        },
        summary() {
            if (this.status === 'detected') {
                if (this.detection.configured) {
                    return this.$t('Traffic arrives from %s, and a proxy is listed below. Check that the address recorded for you looks right.', this.detection.remote_addr);
                }

                return this.$t('Traffic reaches this site from %s, an address inside your own server\'s network, so a proxy is passing it on. Until that proxy is listed below, every visitor looks like the same person.', this.detection.remote_addr);
            }

            if (this.status === 'cloudflare') {
                return this.$t('Visitor addresses come from Cloudflare automatically. Only fill in the fields below if another proxy sits between Cloudflare and your server.');
            }

            if (this.status === 'possible') {
                return this.$t('This request carried the kind of information a proxy adds, but anyone can send that, so it proves nothing. Only list a proxy below if you know one is there.');
            }

            return this.$t('Visitors connect directly, so their addresses are already correct and there is nothing to set up.');
        },
        /**
         * The only case worth interrupting somebody for: the attempt limit is counting
         * every visitor as one person, and nothing else on the site would say so.
         */
        needsAttention() {
            return !!this.detection.needs_attention;
        },
        canSuggest() {
            return !this.config_locked
                && this.detection.suggested_proxy
                && this.settings.trusted_proxies !== this.detection.suggested_proxy;
        }
    },
    methods: {
        applySuggestion() {
            this.settings.trusted_proxies = this.detection.suggested_proxy;

            if (this.detection.suggested_header) {
                this.settings.proxy_ip_header = this.detection.suggested_header;
            }

            this.$notify.info(this.$t('Filled in from your own visit. Check it, then save.'));
        }
    }
};
</script>

<template>
    <div class="fls_proxy" :class="{'is_quiet': quiet}">
        <!--
            The 99% case, in one row: what is being read, and the way in if that is wrong.
        -->
        <SettingRow v-if="quiet" :label="quietTitle" :description="quietNote">
            <el-button size="small" @click="revealed = true">
                {{ quietAction }}
            </el-button>
        </SettingRow>

        <template v-else>
            <p class="fls_proxy_headline">
                <span class="fls_tag is_round" :class="stateTone">{{ headline }}</span>
            </p>

            <p>{{ summary }}</p>

            <el-alert v-if="needsAttention" type="warning" :closable="false" show-icon
                      style="margin-bottom: 10px;">
                {{
                    $t('Failed logins are counted per address. While every visitor looks like %s, one person\'s failed attempts can lock everyone out.', detection.remote_addr)
                }}
            </el-alert>

            <div class="fls_proxy_facts">
                <span>
                    <em class="fls_eyebrow">{{ $t('Connection from') }}</em>
                    <code>{{ detection.remote_addr || '—' }}</code>
                </span>
                <span>
                    <em class="fls_eyebrow">{{ $t('Recorded as your IP') }}</em>
                    <code>{{ detection.resolved_ip || '—' }}</code>
                </span>
                <span v-if="detection.vendor">
                    <em class="fls_eyebrow">{{ $t('Looks like') }}</em>
                    <code>{{ detection.vendor }}</code>
                </span>
            </div>

            <div v-if="detection.headers && detection.headers.length" class="fls_proxy_headers">
                <em class="fls_eyebrow">{{ $t('Address headers on this request') }}</em>
                <ul>
                    <li v-for="header in detection.headers" :key="header.header">
                        <code>{{ header.header }}</code>: {{ header.value }}
                    </li>
                </ul>
            </div>

            <el-alert v-if="config_locked" type="info" :closable="false" show-icon
                      style="margin: 10px 0;">
                {{ $t('These are set in wp-config.php, so the fields below are ignored.') }}
            </el-alert>

            <p v-if="canSuggest" class="fls_action_note">
                <el-button size="small" type="primary" plain @click="applySuggestion()">
                    {{ $t('Use %s', detection.suggested_proxy) }}
                </el-button>
                <span>{{ $t('Fills in the fields below from your own visit. Nothing changes until you save.') }}</span>
            </p>

            <SettingRow :label="$t('Trusted proxies')"
                        :description="$t('The addresses your proxy connects from, usually listed in your host\'s documentation. One per line; a range like 10.0.0.0/8 works too.')">
                <el-input type="textarea" :rows="3" v-model="settings.trusted_proxies"
                          placeholder="127.0.0.1, 10.0.0.0/8"/>
            </SettingRow>

            <SettingRow :label="$t('Header your proxy puts the visitor\'s address in')"
                        :description="$t('Your proxy\'s documentation names it. Leave empty for X-Forwarded-For, which most proxies use.')">
                <el-input v-model="settings.proxy_ip_header" placeholder="X-Forwarded-For"/>
            </SettingRow>
        </template>
    </div>
</template>
