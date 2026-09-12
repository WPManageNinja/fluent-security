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
         * Cloudflare needs nothing configured, and a site with no sign of a proxy
         * needs nothing either - but "no evidence" is not proof, and a proxy that
         * strips its own headers would look exactly like this. So the fields are
         * folded away rather than taken off the page.
         */
        collapsed() {
            if (this.revealed || this.config_locked) {
                return false;
            }

            if (this.settings.trusted_proxies || this.settings.proxy_ip_header) {
                return false;
            }

            return this.status === 'none' || this.status === 'cloudflare';
        },
        headline() {
            const map = {
                detected: this.$t('This site is behind a reverse proxy'),
                cloudflare: this.$t('Cloudflare detected'),
                possible: this.$t('This site may be behind a reverse proxy'),
                none: this.$t('No reverse proxy detected')
            };

            return map[this.status] || map.none;
        },
        summary() {
            if (this.status === 'detected') {
                if (this.detection.configured) {
                    return this.$t('Requests reach WordPress from %s, and a trusted proxy is configured below.', this.detection.remote_addr);
                }

                return this.$t('Requests reach WordPress from %s, which is an address inside your own network, so something is relaying them. Until that relay is declared below, every visitor is recorded as the same IP address.', this.detection.remote_addr);
            }

            if (this.status === 'cloudflare') {
                return this.$t('Visitor addresses are read from Cloudflare automatically, and only for connections that actually came from a Cloudflare edge. There is nothing to configure unless another proxy sits between Cloudflare and this server.');
            }

            if (this.status === 'possible') {
                return this.$t('Forwarding headers are present, but they arrived over a public connection and any visitor can send them, so this is not proof. Only declare a proxy below if you know one is there.');
            }

            return this.$t('Requests reach WordPress directly from the visitor, so addresses are already accurate and nothing needs configuring here.');
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

            this.$notify.info(this.$t('Filled in from this request. Review it and save to apply.'));
        }
    }
};
</script>

<template>
    <div class="fls_proxy">
        <p class="fls_proxy_headline">
            <span class="fls_tag is_round" :class="stateTone">{{ headline }}</span>
        </p>

        <p style="margin-bottom: 10px;">{{ summary }}</p>

        <el-alert v-if="needsAttention" type="warning" :closable="false" show-icon style="margin-bottom: 10px;">
            {{
                $t('The login attempt limit works per IP address. While every visitor looks like %s, one person failing to log in counts against everybody.', detection.remote_addr)
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
            <em class="fls_eyebrow">{{ $t('Forwarding headers on this request') }}</em>
            <ul>
                <li v-for="header in detection.headers" :key="header.header">
                    <code>{{ header.header }}</code>: {{ header.value }}
                </li>
            </ul>
        </div>

        <p v-if="collapsed" class="fls_action_note">
            <a href="#" @click.prevent="revealed = true">{{ $t('Configure a reverse proxy anyway') }}</a>
            <span>{{ $t('Only needed if you know one is there and it is not being detected.') }}</span>
        </p>

        <template v-else>
            <el-alert v-if="config_locked" type="info" :closable="false" show-icon style="margin: 10px 0;">
                {{ $t('These values are defined in wp-config.php and take precedence over the fields below.') }}
            </el-alert>

            <p v-if="canSuggest" class="fls_action_note">
                <el-button size="small" type="primary" plain @click="applySuggestion()">
                    {{ $t('Use %s', detection.suggested_proxy) }}
                </el-button>
                <span>{{ $t('Fills these in from the request you are making now. Nothing is trusted until you save.') }}</span>
            </p>

            <SettingRow :label="$t('Trusted proxies')"
                        :description="$t('One per line. CIDR and IPv6 welcome. Empty means trust only the direct connection.')">
                <el-input type="textarea" :rows="3" v-model="settings.trusted_proxies"
                          placeholder="127.0.0.1, 10.0.0.0/8"/>
            </SettingRow>

            <SettingRow :label="$t('Header carrying the visitor IP')"
                        :description="$t('Only read for requests arriving from a trusted proxy above.')">
                <el-input v-model="settings.proxy_ip_header" placeholder="X-Forwarded-For"/>
            </SettingRow>
        </template>
    </div>
</template>
