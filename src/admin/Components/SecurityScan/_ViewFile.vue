<template>
    <h3>{{ filePath }}</h3>

    <div v-loading="loading" :element-loading-text="$t('Loading file…')">
        <div v-if="error">
            <pre>{{error}}</pre>
        </div>
        <div v-else-if="!hasDiff">
            <el-input type="textarea" :rows="30" v-model="fileContent" :readonly="true"></el-input>
        </div>
        <div v-else class="diff_viewer">
            <el-scrollbar :style="{height: '500px'}" class="diff_viewer">
                <pre class="fls_diff_view" id="fls_diff_viewer" ref="fls_diff_viewer"></pre>
            </el-scrollbar>
        </div>
    </div>
</template>

<script type="text/babel">
export default {
    name: 'ViewFile',
    props: ['viewing_file'],
    data() {
        return {
            filePath: '',
            fileContent: '',
            originalFileContent: '',
            hasDiff: false,
            loading: true,
            error: ''
        }
    },
    methods: {
        getFileContent() {
            this.error = '';
            this.loading = true;
            this.$get('security-scan-settings/scan/view-file', {viewing_file: this.viewing_file})
                .then(response => {
                    this.filePath = response.filePath;
                    this.hasDiff = response.hasDiff;
                    this.fileContent = response.fileContent;
                    this.originalFileContent = response.originalFileContent;

                    if (response.hasDiff) {
                        this.$nextTick(() => {
                            this.initDiff();
                        });
                    }
                })
                .catch((errors) => {
                    this.$handleError(errors);
                    this.error = errors?.message;
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        initDiff() {
            var color = '',
                span = null;

            var diff = Diff.diffLines(this.originalFileContent, this.fileContent),
                display = this.$refs.fls_diff_viewer,
                fragment = document.createDocumentFragment();

            diff.forEach(function (part) {
                // green for additions, red for deletions
                // grey for common parts
                color = part.added ? 'green' :
                    part.removed ? 'red' : 'grey';
                span = document.createElement('span');
                span.style.color = color;
                span.appendChild(document
                    .createTextNode(part.value));
                fragment.appendChild(span);
            });

            display.appendChild(fragment);
        }
    },
    mounted() {
        this.getFileContent();
    },
}
</script>
