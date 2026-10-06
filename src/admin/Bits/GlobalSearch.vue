<script type="text/babel">
import {searchEntries, searchGroups, searchIndex} from './searchIndex';

/*
 * Type a place, go there.
 *
 * The plugin is four destinations and a dozen settings screens, which is small enough to
 * navigate by clicking and large enough that nobody remembers whether the proxy setting is
 * under Visitor IP or Advanced. So this indexes screens rather than fields - see
 * searchIndex.js for why it stops there - and the answer to "where is X" is the screen X is
 * on, opened at the right block.
 *
 * The trigger lives here with the dialog rather than in the bar, so the bar has one thing
 * to place and the keyboard shortcut and the button cannot disagree about what opens.
 */
export default {
    name: 'GlobalSearch',
    data() {
        return {
            open: false,
            query: '',
            index: [],
            selected: 0
        };
    },
    computed: {
        results() {
            return searchEntries(this.index, this.query);
        },
        /*
         * The results split into their groups, in the index's order, with empty groups
         * dropped. Flat for the keyboard and grouped for the eye, so `selected` stays an
         * offset into `results` and nothing has to map between two shapes.
         */
        groups() {
            let offset = 0;

            return searchGroups.map(name => {
                const items = this.results
                    .filter(entry => entry.group === name)
                    .map(entry => ({entry, position: 0}));

                return {name, items};
            }).filter(group => group.items.length > 0).map(group => {
                group.items.forEach(item => {
                    item.position = offset++;
                });

                return group;
            });
        }
    },
    methods: {
        show() {
            this.index = searchIndex(this);
            this.query = '';
            this.selected = 0;
            this.open = true;
        },
        onOpened() {
            this.$nextTick(() => {
                if (this.$refs.input) {
                    this.$refs.input.focus();
                }
            });
        },
        move(step) {
            const total = this.results.length;

            if (!total) {
                return;
            }

            /* Wraps, so holding one arrow key reaches everything without changing hands. */
            this.selected = (this.selected + step + total) % total;
            this.$nextTick(this.scrollToSelected);
        },
        scrollToSelected() {
            const list = this.$refs.list;
            const row = list ? list.querySelector('.is_selected') : null;

            if (!row) {
                return;
            }

            const top = row.offsetTop;
            const bottom = top + row.offsetHeight;

            if (top < list.scrollTop) {
                list.scrollTop = top;
            } else if (bottom > list.scrollTop + list.clientHeight) {
                list.scrollTop = bottom - list.clientHeight;
            }
        },
        choose(index) {
            const entry = this.results[index];

            if (!entry) {
                return;
            }

            this.open = false;
            this.$router.push(entry.to);
        },
        /*
         * `/` opens it, the way it opens FluentCart's.
         *
         * Not while something is being typed into, or the key would be unusable in every
         * field in the app - and not while another dialog is up, where it would open a
         * second one behind the first. `isContentEditable` catches the email editor, which
         * is neither an input nor a textarea.
         */
        onKeydown(e) {
            if (e.key !== '/' || this.open) {
                return;
            }

            if (e.metaKey || e.ctrlKey || e.altKey) {
                return;
            }

            const el = document.activeElement;

            if (el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))) {
                return;
            }

            if (this.overlayIsUp()) {
                return;
            }

            e.preventDefault();
            this.show();
        },
        /*
         * Whether a dialog, drawer or confirmation is already on screen.
         *
         * Element Plus keeps an overlay in the DOM once its dialog has been opened for the
         * first time, so the question is whether one is being *shown* rather than whether
         * one exists - and it has to be asked with `getClientRects`, because an overlay is
         * `position: fixed` and so has no `offsetParent` even when it is right in front of
         * you.
         */
        overlayIsUp() {
            const overlays = document.querySelectorAll('.el-overlay');

            for (const overlay of overlays) {
                if (overlay.getClientRects().length) {
                    return true;
                }
            }

            return false;
        }
    },
    watch: {
        /* A new query re-orders the list under the cursor, so the cursor goes back to the top. */
        query() {
            this.selected = 0;

            if (this.$refs.list) {
                this.$refs.list.scrollTop = 0;
            }
        }
    },
    mounted() {
        document.addEventListener('keydown', this.onKeydown);
    },
    beforeUnmount() {
        document.removeEventListener('keydown', this.onKeydown);
    }
};
</script>

<template>
    <div class="fls_search">
        <button type="button" class="fls_search_trigger" @click="show()"
                :aria-label="$t('Search')">
            <svg viewBox="0 0 20 20" fill="none" width="16" height="16">
                <path d="M14.583 14.583 18.333 18.333" stroke="currentColor" stroke-width="1.5"
                      stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M16.667 9.167a7.5 7.5 0 1 0-15 0 7.5 7.5 0 0 0 15 0Z" stroke="currentColor"
                      stroke-width="1.5" stroke-linejoin="round"/>
            </svg>
            <kbd>/</kbd>
        </button>

        <el-dialog v-model="open" class="fls_search_dialog" :append-to-body="true"
                   :show-close="false" :width="560" @opened="onOpened"
                   :aria-label="$t('Search')">
            <template #header>
                <div class="fls_search_field">
                    <svg viewBox="0 0 20 20" fill="none" width="18" height="18">
                        <path d="M14.583 14.583 18.333 18.333" stroke="currentColor" stroke-width="1.5"
                              stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M16.667 9.167a7.5 7.5 0 1 0-15 0 7.5 7.5 0 0 0 15 0Z" stroke="currentColor"
                              stroke-width="1.5" stroke-linejoin="round"/>
                    </svg>
                    <input ref="input" v-model="query" type="text"
                           :placeholder="$t('Search settings and pages')"
                           @keydown.down.prevent="move(1)"
                           @keydown.up.prevent="move(-1)"
                           @keydown.enter.prevent="choose(selected)"/>
                </div>
            </template>

            <div ref="list" class="fls_search_results">
                <template v-if="results.length">
                    <div v-for="group in groups" :key="group.name" class="fls_search_group">
                        <div class="fls_search_group_label">{{ $t(group.name) }}</div>

                        <ul>
                            <li v-for="item in group.items" :key="item.entry.title">
                                <button type="button"
                                        :class="{is_selected: item.position === selected}"
                                        @mousemove="selected = item.position"
                                        @click="choose(item.position)">
                                    <span class="fls_search_title">{{ item.entry.title }}</span>
                                    <span v-if="item.entry.subtitle" class="fls_search_sub">
                                        {{ item.entry.subtitle }}
                                    </span>
                                </button>
                            </li>
                        </ul>
                    </div>
                </template>

                <p v-else class="fls_search_empty">
                    {{ $t('Nothing here matches “%s”.', query) }}
                </p>
            </div>

            <template #footer>
                <ul class="fls_search_keys">
                    <li><kbd>↑</kbd><kbd>↓</kbd><span>{{ $t('to move') }}</span></li>
                    <li><kbd>↵</kbd><span>{{ $t('to open') }}</span></li>
                    <li><kbd>esc</kbd><span>{{ $t('to close') }}</span></li>
                </ul>
            </template>
        </el-dialog>
    </div>
</template>
