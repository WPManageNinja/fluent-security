<script type="text/babel">
/**
 * The address this site currently thinks you are at, and the evidence behind it.
 *
 * The question this step asks - "is your site behind a proxy?" - is one most site owners
 * genuinely cannot answer, and guessing wrong quietly breaks the attempt limit and the IP
 * lists. So it is not the question that gets asked. This shows the address the plugin
 * resolved for the request that drew this screen, and asks whether that is them: a
 * comparison anybody can make, against a number they can look up in one click.
 *
 * The evidence is shown rather than summarised. A site being relayed from inside its own
 * network, with forwarding headers arriving, is a specific and checkable situation, and an
 * administrator who can see the headers can tell their host something useful.
 */
export default {
    name: 'ConnectionPreview',
    props: {
        connection: {
            type: Object,
            required: true
        },
        answer: {
            type: Object,
            default: () => ({})
        }
    },
    computed: {
        resolved() {
            return this.connection.resolved_ip || this.$t('unknown');
        },
        /** True once the answer says the resolved address is not the reader's own. */
        isProxy() {
            return this.answer.mode === 'proxy';
        },
        /**
         * What the resolved address would become once the declared proxy is trusted. Only
         * a forwarded header can change it, so with none present it stays as it is.
         */
        headers() {
            return this.connection.headers || [];
        },
        vendor() {
            return this.connection.vendor || '';
        },
        tone() {
            if (this.connection.needs_attention) {
                return 'is-warning';
            }

            return this.isProxy ? 'is-neutral' : 'is-ok';
        },
        verdict() {
            if (this.connection.needs_attention) {
                return this.$t('Every visitor is arriving as this one address.');
            }

            if (this.isProxy) {
                return this.$t('Once the proxy is declared, visitors will be told apart by the header it sends.');
            }

            return this.$t('Visitors are being told apart by the address they connect from.');
        }
    }
};
</script>

<template>
    <div class="fls_onb_conn" :class="tone">
        <p class="fls_onb_conn_lead">{{ $t('This site sees you at') }}</p>

        <p class="fls_onb_conn_ip">{{ resolved }}</p>

        <p class="fls_onb_conn_verdict">{{ verdict }}</p>

        <!--
            Always shown, not only when a proxy was detected. "Nothing in front of this
            site" is the finding on most sites, and stating it is what makes the address
            above checkable rather than merely asserted.
        -->
        <dl class="fls_onb_conn_evidence">
            <div class="fls_onb_conn_row">
                <dt>{{ $t('In front of this site') }}</dt>
                <dd>{{ vendor || (headers.length ? $t('Something is forwarding requests') : $t('Nothing detected')) }}</dd>
            </div>
            <div v-if="connection.remote_addr" class="fls_onb_conn_row">
                <dt>{{ $t('Connection from') }}</dt>
                <dd>
                    {{ connection.remote_addr }}
                    <span v-if="connection.remote_is_private" class="fls_onb_conn_flag">
                        {{ $t('inside your network') }}
                    </span>
                </dd>
            </div>
            <div v-if="headers.length" class="fls_onb_conn_row">
                <dt>{{ $t('Forwarding headers') }}</dt>
                <dd>
                    <span v-for="item in headers" :key="item.header" class="fls_onb_conn_header">
                        <b>{{ item.header }}</b>
                        <em>{{ item.value }}</em>
                    </span>
                </dd>
            </div>
        </dl>
    </div>
</template>
