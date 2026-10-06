<script type="text/babel">
import {counts, sectionFor} from './subNav';

/*
 * The section bar: the views of the destination you are on, drawn under the app bar.
 *
 * It renders nothing at all for a destination that has only one view, so the shell can
 * mount it unconditionally and the bar appears where a section exists and nowhere else.
 * What the sections are lives in subNav.js, beside the counts.
 */
export default {
    name: 'SubNav',
    data() {
        return {
            counts
        };
    },
    computed: {
        section() {
            return sectionFor(this.$route);
        }
    },
    methods: {
        /*
         * Which tab is lit, decided by route name rather than left to router-link: the tabs
         * are siblings rather than a parent and its children, so a tab that owns two routes
         * has no path for the link to match on.
         */
        isActive(item) {
            return item.names.indexOf(this.$route.name) !== -1;
        },
        countFor(item) {
            return item.count ? this.counts[item.count] : 0;
        }
    }
}
</script>

<template>
    <nav v-if="section" class="fls_sub_bar" :aria-label="$t(section.label)">
        <ul class="fls_sub_nav">
            <li v-for="item in section.items" :key="item.route">
                <router-link :to="{name: item.route}"
                             :class="{is_active: isActive(item)}"
                             :aria-current="isActive(item) ? 'page' : null">
                    {{ $t(item.title) }}
                    <span v-if="countFor(item)" class="fls_sub_nav_count">{{ countFor(item) }}</span>
                </router-link>
            </li>
        </ul>
    </nav>
</template>
