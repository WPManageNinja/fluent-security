<template>
    <el-input :size="input_size" ref="inputElement" :placeholder="input_placeholder" v-model="localModel">
        <template #append>
            <el-popover
                placement="bottom-start"
                :offset="0"
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
                                @click="activeIndex = item_index">
                                {{ item.title }}
                            </li>
                        </ul>

                        <div v-if="doc_url" class="pop_doc">
                            <a :href="doc_url" target="_blank" rel="noopener">Learn More</a>
                        </div>
                    </div>
                    <div class="el_pop_data_body">
                        <div v-for="(item,current_index) in data" :key="current_index">
                            <ul v-show="activeIndex == current_index"
                                :class="'el_pop_body_item_'+current_index">
                                <li @click="insertShortcode(code)" v-for="(label,code) in item.shortcodes" :key="code">
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
        </template>
    </el-input>
</template>

<script type="text/babel">
export default {
    name: 'inputPopoverInput',
    props: {
        data: Array,
        modelValue: {
            type: String,
            default() {
                return '';
            }
        },
        close_on_insert: {
            type: Boolean,
            default() {
                return true;
            }
        },
        buttonText: {
            type: String,
            default() {
                return '+ SmartCode';
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
                return 'input-popover-input';
            }
        },
        doc_url: {
            type: String,
            default() {
                return '';
            }
        },
        input_placeholder: {
            type: String,
            default() {
                return '';
            }
        },
        input_size: {
            type: String,
            default() {
                return '';
            }
        }
    },
    watch: {
        localModel(newVal) {
            this.$emit('update:modelValue', newVal);
        },
    },
    data() {
        return {
            activeIndex: 0,
            visible: false,
            localModel: this.modelValue
        }
    },
    methods: {
        insertShortcode(code) {
            // Try multiple ways to get the input element
            let inputEl;

            // First, try the standard input reference
            if (this.$refs.inputElement && this.$refs.inputElement.$el) {
                inputEl = this.$refs.inputElement.$el.querySelector('input')
            }

            // If that fails, try getting the native input directly
            if (!inputEl) {
                const refs = this.$refs;
                for (let ref in refs) {
                    if (refs[ref] && refs[ref].$el && refs[ref].$el.tagName === 'INPUT') {
                        inputEl = refs[ref].$el
                        break
                    }
                }
            }

            // If we still can't find the input, fall back to simple append
            if (!inputEl) {
                this.localModel += ' ' + code;

                // Close popover if required
                if (this.close_on_insert) {
                    this.visible = false
                }

                return
            }

            if(!this.localModel) {
                this.localModel = code + '' + ' ';

                // Close popover if required
                if (this.close_on_insert) {
                    this.visible = false
                }

                this.$nextTick(() => {
                    inputEl.focus();
                });
                return;
            }

            // Get current selection/cursor position
            const startPos = inputEl.selectionStart || this.localModel.length
            const endPos = inputEl.selectionEnd || this.localModel.length
            const currentValue = this.localModel

            // Construct new value
            const newValue =
                currentValue.substring(0, startPos) +
                code +
                currentValue.substring(endPos)

            // Update model
            this.localModel = newValue

            // Set cursor position after the inserted code
            this.$nextTick(() => {
                // Try to set selection range
                try {
                    inputEl.setSelectionRange(
                        startPos + code.length,
                        startPos + code.length
                    )
                    inputEl.focus()
                } catch (error) {
                    console.warn('Could not set selection range', error)
                }
            })

            // Close popover if required
            if (this.close_on_insert) {
                this.visible = false
            }
        }
    }
}
</script>
