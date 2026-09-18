<script type="text/babel">
/**
 * Another plugin is also finishing the logins this one is configured to finish.
 *
 * One component for one piece of news, shown wherever somebody would want to know: the
 * dashboard, because that is where they land, and the settings page, beside the switches it
 * is about. Not a findings row - the findings list is for things a site could do better, and
 * this is a switch not working.
 *
 * Two states. `blocking` means no filter exists for that plugin, so it really does take the
 * session over and sign-ins fail. Otherwise RivalStandDown heads it off and nothing is
 * broken, which is worth saying without the alarm - warning colours there would be claiming
 * a breakage that is not happening.
 *
 * Text, never v-html: the plugin names come from a filterable list, so they are somebody
 * else's input by the time they get here.
 */
export default {
    name: 'RivalNotice',
    props: {
        notice: {
            type: Object,
            default: null
        }
    },
    computed: {
        /*
         * Names the plugin when there is one, because that is the whole of the news. Making a
         * reader open something to find out which plugin hands them a fact they cannot act on.
         */
        title() {
            if (!this.notice) {
                return '';
            }

            const names = this.notice.names || [];

            if (names.length === 1) {
                return this.notice.blocking
                    ? this.$t('%s is also enforcing two-factor login', names[0])
                    : this.$t('%s is also set up for two-factor login', names[0]);
            }

            return this.notice.blocking
                ? this.$t('Other plugins are also enforcing two-factor login')
                : this.$t('Other plugins are also set up for two-factor login');
        },
        where() {
            return (this.notice && this.notice.where || []).join(' · ');
        }
    }
}
</script>

<template>
    <div v-if="notice" class="fls_2fa_conflict"
         :class="notice.blocking ? 'is_blocking' : 'is_handled'" role="alert">
        <h4>{{ title }}</h4>

        <p v-if="notice.blocking">{{ $t('__2fa_conflict_blocking_desc__') }}</p>
        <p v-else>{{ $t('__2fa_conflict_handled_desc__') }}</p>

        <p v-if="where" class="fls_2fa_conflict__where">
            {{ $t('Turn it off in:') }} {{ where }}
        </p>

        <a :href="notice.url" class="fls_2fa_conflict__action">
            {{ notice.names.length === 1 ? $t('Open its settings') : $t('Open plugins') }}
        </a>
    </div>
</template>
