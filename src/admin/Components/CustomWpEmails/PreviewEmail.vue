<template>
    <el-skeleton v-if="previewLoading" :animated="true" :rows="10" />
    <template v-else-if="rendered_email">
        <div>
            <strong>{{$t('Subject:')}} </strong> {{ rendered_email.subject }}
        </div>
        <emailbody-container
            :content="rendered_email.body"></emailbody-container>
    </template>
    <div v-else>
        <el-empty :description="$t('The preview could not be loaded.')" />
    </div>
</template>

<script type="text/javascript">
import EmailbodyContainer from "./EmailbodyContainer.vue";
export default {
    name: 'PreviewEmail',
    props: ['email_data', 'email_id'],
    components: {
        EmailbodyContainer
    },
    data() {
        return {
            rendered_email: null,
            previewLoading: true,
        }
    },
    methods: {
        fetchEmail() {
            this.previewLoading = true;
            this.$post('wp-default-emails/preview', {
                email_id: this.email_id,
                email_data: this.email_data,
            })
                .then(response => {
                    this.rendered_email = response.rendered_email;
                })
                .catch((errors) => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.previewLoading = false;
                });
        },
    },
    mounted() {
        this.fetchEmail();
    },
}
</script>
