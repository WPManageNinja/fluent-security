<template>
    <div>
        <el-popover
            :ref="btn_ref"
            placement="bottom-start"
            offset="50"
            :width="400"
            popper-class="fcrm-smartcodes-popover el-dropdown-list-wrapper"
            :visible="visible"
        >
            <div class="el_pop_data_group">
                <div class="el_pop_data_headings">
                    <ul>
                        <li
                            v-for="(item,item_index) in data"
                            :data-item_index="item_index"
                            :key="item_index"
                            :class="(activeIndex == item_index) ? 'active_item_selected' : ''"
                            role="tab"
                            tabindex="0"
                            :aria-selected="activeIndex == item_index ? 'true' : 'false'"
                            @keydown.enter.prevent="activeIndex = item_index"
                            @keydown.space.prevent="activeIndex = item_index"
                            @click="activeIndex = item_index">
                            {{ item.title }}
                        </li>
                    </ul>

                    <div v-if="doc_url" class="pop_doc">
                        <a :href="doc_url" target="_blank" rel="noopener">{{$t('Learn More')}}</a>
                    </div>
                </div>
                <div class="el_pop_data_body">
                    <div v-for="(item,current_index) in data" :key="current_index">
                        <ul v-show="activeIndex == current_index"
                            :class="'el_pop_body_item_'+current_index">
                            <li v-for="(label,code) in item.shortcodes" :key="code"
                                        role="button"
                                        tabindex="0"
                                        @keydown.enter.prevent="insertShortcode(code)"
                                        @keydown.space.prevent="insertShortcode(code)"
                                        @click="insertShortcode(code)">
                                {{ label }}<span>{{ code }}</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <template #reference>
                <el-button class="editor-add-shortcode"
                           @click="visible = !visible"
                           :type="btnType"
                           v-html="buttonText"
                />
            </template>
        </el-popover>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'inputPopoverDropdownExtended',
    props: {
        data: Array,
        close_on_insert: {
            type: Boolean,
            default() {
                return true;
            }
        },
        buttonText: {
            type: String,
            default() {
                return 'Add SmartCodes';
            }
        },
        btnType: {
            type: String,
            default() {
                return 'default';
            }
        },
        btn_ref: {
            type: String,
            default() {
                return 'input-popover1';
            }
        },
        doc_url: {
            type: String,
            default() {
                return '';
            }
        }
    },
    data() {
        return {
            activeIndex: 0,
            visible: false
        }
    },
    methods: {
        selectEmoji(imoji) {
            this.insertShortcode(imoji.data);
        },
        insertShortcode(code) {
            this.$emit('command', code);
            if (this.close_on_insert) {
                this.visible = false;
            }
        }
    },
    mounted() {
    }
}
</script>
