<template>
    <div class="wp_vue_editor_wrapper">
        <popover v-if="editorShortcodes && editorShortcodes.length" class="popover-wrapper"
                 :class="{'popover-wrapper-plaintext': !hasWpEditor}" :data="editorShortcodes"
                 @command="handleCommand"></popover>
        <textarea v-if="hasWpEditor" class="wp_vue_editor" :id="editor_id">{{ plain_content }}</textarea>
        <textarea v-else
                  class="wp_vue_editor wp_vue_editor_plain"
                  v-model="plain_content"
                  @click="updateCursorPos">
        </textarea>

        <button-designer v-if="showButtonDesigner" @close="() => {showButtonDesigner = false}" @insert="insertHtml"
                         :visibility="showButtonDesigner"></button-designer>

    </div>
</template>

<script type="text/babel">
import popover from './MCE/input-popover-dropdown.vue'
import ButtonDesigner from './MCE/button';
import {emailFontFamilies} from '@/Bits/data_config.js';
import each from 'lodash/each';

export default {
    name: 'wp_editor',
    components: {
        popover,
        ButtonDesigner
    },
    props: {
        editor_id: {
            type: String,
            default() {
                return 'wp_editor_' + Date.now() + parseInt(Math.random() * 1000);
            }
        },
        modelValue: {
            type: String,
            default() {
                return '';
            }
        },
        editorShortcodes: {
            default() {
                return []
            }
        },
        height: {
            type: Number,
            default() {
                return 400;
            }
        },
        extra_style: {
            default() {
                return ''
            }
        }
    },
    data() {
        return {
            showButtonDesigner: false,
            hasWpEditor: (!!window.wp.editor && !!wp.editor.autop) || !!window.wp.oldEditor,
            editor: window.wp.oldEditor || window.wp.editor,
            plain_content: this.modelValue,
            cursorPos: (this.modelValue) ? this.modelValue.length : 0,
            app_ready: false,
            buttonInitiated: false,
            currentEditor: false
        }
    },
    watch: {
        plain_content() {
            this.$emit('update:modelValue', this.plain_content);
        }
    },
    methods: {
        each,
        initEditor() {
            if (!this.hasWpEditor) {
                return;
            }

            const formFormats = [];

            this.each(emailFontFamilies, (name, key) => {
                 formFormats.push(key + '=' + name);
            });

            let defaultStyles = 'blockquote {padding: 10px 30px;margin: 0;background: #f2f2f2;}';
            this.editor.remove(this.editor_id);
            const that = this;
            this.editor.initialize(this.editor_id, {
                mediaButtons: true,
                tinymce: {
                    height: that.height,
                    fontsize_formats: '8px 10px 12px 14px 16px 18px 24px 30px 36px 45px',
                    toolbar1: 'formatselect,fontselect,fontsizeselect,customInsertButton,table,bold,italic,bullist,numlist,link,blockquote,alignleft,aligncenter,alignright,underline,strikethrough,forecolor,removeformat,codeformat,outdent,indent,undo,redo',
                    font_formats: formFormats.join('; '),
                    setup(editor) {
                        editor.on('change', function (ed, l) {
                            that.changeContentEvent();
                        });
                        if (!that.buttonInitiated) {
                            that.buttonInitiated = true;
                            editor.addButton('customInsertButton', {
                                text: that.$t('Button'),
                                classes: 'fluentcrm_editor_btn',
                                onclick() {
                                    that.showInsertButtonModal(editor);
                                }
                            });
                        }
                    },
                    formats: {
                        // Changes the alignment buttons to add a class to each of the matching selector elements
                        alignleft: { selector: 'p,h1,h2,h3,h4,h5,h6,td,th,div,ul,ol,li,table,img', classes: 'align-left', styles: { 'text-align': 'left' } },
                        aligncenter: { selector: 'p,h1,h2,h3,h4,h5,h6,td,th,div,ul,ol,li,table,img', classes: 'align-center', styles: { 'text-align': 'center' }, attributes: { align: 'center' } },
                        alignright: { selector: 'p,h1,h2,h3,h4,h5,h6,td,th,div,ul,ol,li,table,img', classes: 'align-right', styles: { 'text-align': 'right' }, attributes: { align: 'right' } }
                    },
                    content_style: that.extra_style + defaultStyles
                },
                quicktags: true
            });

            jQuery('#' + this.editor_id).on('change', function (e) {
                that.changeContentEvent();
            });
        },
        showInsertButtonModal(editor) {
            this.currentEditor = editor;
            this.showButtonDesigner = true;
        },
        insertHtml(content) {
            this.currentEditor.insertContent(content);
        },
        changeContentEvent() {
            const content = this.editor.getContent(this.editor_id);
            this.$emit('update:modelValue', content);
        },
        handleCommand(command) {
            if (this.hasWpEditor) {
                window.tinymce.activeEditor.insertContent(command);
            } else {
                var part1 = this.plain_content.slice(0, this.cursorPos);
                var part2 = this.plain_content.slice(this.cursorPos, this.plain_content.length);
                this.plain_content = part1 + command + part2;
                this.cursorPos += command.length;
            }
        },
        updateCursorPos() {
            var cursorPos = jQuery('.wp_vue_editor_plain').prop('selectionStart');
            this.cursorPos = cursorPos;
        }
    },
    mounted() {
        this.initEditor();
        this.app_ready = true;
    }
}
</script>
