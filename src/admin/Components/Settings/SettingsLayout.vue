<script type="text/babel">
import {settingsNav, chevronIcon} from './nav';

export default {
    name: 'SettingsLayout',
    data() {
        return {
            nav: settingsNav(this),
            chevron: chevronIcon
        }
    },
    computed: {
        visibleNav() {
            return this.nav.filter(group => !group.when || group.when(this.appVars));
        }
    },
    methods: {
        /**
         * A group counts as current when the page showing belongs to it, so its
         * children stay open while you move between them.
         */
        isGroupActive(group) {
            const current = this.$route.name;

            if (group.route === current) {
                return true;
            }

            return (group.children || []).some(child => child.route === current);
        },
        /**
         * Honours ?section=... on arrival, for links that point at one block of settings.
         *
         * The dashboard's checklist links straight at the setting that would tick it. That
         * cannot be a URL fragment: the router owns the hash, and the element to scroll to
         * lives inside a pane that scrolls rather than the document, which is not
         * somewhere the browser's own fragment handling can reach. The section only exists
         * once the page has loaded its settings, so this waits for it rather than firing
         * once into an empty pane and giving up.
         */
        openRequestedSection(attempt = 0) {
            const id = this.$route.query.section;

            if (!id || !this.$refs.pane) {
                return;
            }

            const el = document.getElementById('fls_section_' + id);

            if (el) {
                // scroll-margin-top on the section keeps it clear of the sticky header.
                el.scrollIntoView({behavior: 'smooth', block: 'start'});
                return;
            }

            if (attempt < 20) {
                this.sectionTimer = setTimeout(() => this.openRequestedSection(attempt + 1), 100);
            }
        }
    },
    mounted() {
        this.$nextTick(() => this.openRequestedSection());
    },
    beforeUnmount() {
        clearTimeout(this.sectionTimer);
    },
    watch: {
        $route() {
            // The pane keeps its scroll position between screens; a new one starts at its top.
            if (this.$refs.pane) {
                this.$refs.pane.scrollTop = 0;
            }

            this.$nextTick(() => this.openRequestedSection());
        }
    }
};
</script>

<template>
    <div class="fls_settings">
        <div class="fls_settings_nav">
            <div class="fls_settings_nav_title">
                {{ $t('Settings') }}
            </div>

            <ul>
                <li v-for="group in visibleNav" :key="group.route"
                    :class="{'is-active': isGroupActive(group)}">
                    <router-link :to="{name: group.route}">
                        <span class="fls_nav_icon" v-html="group.icon"></span>
                        <span>{{ group.title }}</span>
                        <span v-if="group.children" class="fls_nav_chevron"
                              v-html="chevron"></span>
                    </router-link>

                    <!-- Separate screens, with their own data and their own saving. -->
                    <ul v-if="group.children && isGroupActive(group)" class="fls_settings_subnav">
                        <li v-for="child in group.children" :key="child.route">
                            <router-link :to="{name: child.route}">{{ child.title }}</router-link>
                        </li>
                    </ul>
                </li>
            </ul>
        </div>

        <div ref="pane" class="fls_settings_body">
            <router-view/>
        </div>
    </div>
</template>
