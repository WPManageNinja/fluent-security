<script type="text/babel">
/**
 * One translated sentence with form fields inside it. `text` keeps its placeholders
 * ($t() without arguments leaves them), and `%1$s`, `%2$s`... render slots `field1`,
 * `field2`... so translators can move the fields anywhere in the sentence. A field
 * that a translation drops is added at the end, so the setting can still be changed.
 */
const PLACEHOLDER = /(%\d*\$?[sd])/;

export default {
    name: 'InlineSentence',
    props: {text: {type: String, required: true}},
    computed: {
        parts() {
            let next = 0;
            const parts = String(this.text).split(PLACEHOLDER).filter(part => part !== '').map(part => {
                const match = part.match(/^%(\d*)\$?[sd]$/);
                if (!match) {
                    return {text: part};
                }
                return {slot: 'field' + (match[1] ? parseInt(match[1], 10) : ++next)};
            });

            Object.keys(this.$slots).sort().forEach(name => {
                if (/^field\d+$/.test(name) && !parts.some(part => part.slot === name)) {
                    parts.push({text: ' '}, {slot: name});
                }
            });

            return parts;
        }
    }
};
</script>

<template>
    <span class="fls_sentence">
        <template v-for="(part, index) in parts" :key="index">
            <slot v-if="part.slot" :name="part.slot"/>
            <template v-else>{{ part.text }}</template>
        </template>
    </span>
</template>
