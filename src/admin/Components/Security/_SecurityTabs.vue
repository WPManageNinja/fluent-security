<script type="text/babel">
/*
 * The two halves of the security screen.
 *
 * Findings is what needs doing; Monitoring is what is being watched and how completely. They
 * are the same destination because a reader arriving at "Security" has one of two questions,
 * and having to guess which of two menu items holds theirs is the thing this avoids.
 *
 * Rendered by both screens rather than by a layout above them: the two own different asides,
 * so the grid cannot be hoisted out of them without threading the aside back through a slot.
 */
export default {
    name: 'SecurityTabs',
    props: {
        /* Shown on the Findings tab so the count is visible from the other one. */
        openCount: {
            type: Number,
            default: 0
        }
    }
}
</script>

<template>
    <nav class="fls_sec_tabs" :aria-label="$t('Security sections')">
        <router-link :to="{name: 'security_findings'}" class="fls_sec_tab">
            {{ $t('Findings') }}
            <span v-if="openCount" class="fls_sec_tab_count">{{ openCount }}</span>
        </router-link>
        <router-link :to="{name: 'security_scans'}" class="fls_sec_tab">
            {{ $t('Monitoring') }}
        </router-link>
        <!--
            Last, and named for what it is for rather than for what it does. Nobody goes
            looking for "tools"; they go looking for what to do after a break-in.
        -->
        <router-link :to="{name: 'security_recovery'}" class="fls_sec_tab">
            {{ $t('Recovery') }}
        </router-link>
    </nav>
</template>
