<script type="text/babel">
/**
 * Another plugin is also finishing the logins this one is configured to finish.
 *
 * One component for one piece of news, shown wherever somebody would want to know: the
 * dashboard, because that is where they land, and the settings page, beside the switches it
 * is about. Not a findings row - the findings list is for things a site could do better, and
 * this is a switch not working.
 *
 * One state, because there is only one outcome. Two second factors on one site cannot both
 * finish a login: whichever runs second throws the first one's session away mid-request and
 * the user loops. An earlier version had a second, calmer state for the plugins this one could
 * ask to stand aside - that was removed along with the stand-down itself, which never worked on
 * the most widely installed rival. See RivalTwoFa.
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

            return names.length === 1
                ? this.$t('%s is also enforcing two-factor login', names[0])
                : this.$t('Other plugins are also enforcing two-factor login');
        },
        where() {
            return (this.notice && this.notice.where || []).join(' · ');
        }
    }
}
</script>

<template>
    <div v-if="notice" class="fls_2fa_conflict is_blocking" role="alert">
        <h4>{{ title }}</h4>

        <p>{{ $t('__2fa_conflict_blocking_desc__') }}</p>

        <p v-if="where" class="fls_2fa_conflict__where">
            {{ $t('Turn it off in:') }} {{ where }}
        </p>

        <a :href="notice.url" class="fls_2fa_conflict__action">
            {{ notice.names.length === 1 ? $t('Open its settings') : $t('Open plugins') }}
        </a>
    </div>
</template>
