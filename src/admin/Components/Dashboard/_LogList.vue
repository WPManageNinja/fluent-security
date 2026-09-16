<script type="text/babel">
import icons from './icons';

/*
 * A short preview of auth log rows.
 *
 * A list rather than a table: six rows with "view all" beside them do not need a header
 * row, sortable columns or column rules, and the table this replaced spent about a third
 * of the card's height on them.
 */
export default {
    name: 'LogList',
    props: {
        logs: {
            type: Array,
            required: true
        },
        emptyText: {
            type: String,
            default: ''
        }
    },
    data() {
        return {
            icons
        }
    },
    methods: {
        statusLabel(status) {
            return this.appVars.auth_statuses[status] || status;
        },
        /*
         * The username is the row's subject and the address is how you act on it, so both
         * are on the row. Anything longer - the agent string, the error code - is in the
         * logs table, which is one click away.
         */
        meta(log) {
            return [log.ip, log.browser].filter(part => !!part).join(' · ');
        }
    }
}
</script>

<template>
    <ul v-if="logs.length" class="fls_dash_list">
        <li v-for="log in logs" :key="log.id">
            <div class="fls_dash_list_main">
                <div class="fls_dash_list_title">
                    <span>{{ log.username || $t('No username') }}</span>
                    <span class="fls_tag" :class="'is_' + log.status">{{ statusLabel(log.status) }}</span>
                </div>
                <div class="fls_dash_list_meta">{{ meta(log) }}</div>
            </div>
            <div class="fls_dash_list_aside" :title="log.created_at">{{ log.time_ago }}</div>
        </li>
    </ul>

    <div v-else class="fls_empty">
        <span v-html="icons.empty"></span>
        {{ emptyText }}
    </div>
</template>
