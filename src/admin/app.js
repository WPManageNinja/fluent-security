import {createApp} from 'vue'
import {createRouter, createWebHashHistory} from 'vue-router';
import {routes} from './routes';
import Rest from './Bits/Rest.js';
import {ElNotification, ElLoading, ElMessageBox} from 'element-plus'
import Storage from '@/Bits/Storage';
import App from './App.vue';

import {FolderOpened, CloseBold, Document, ArrowLeftBold, MoreFilled, View, DocumentAdd, DocumentDelete, Warning, MuteNotification} from '@element-plus/icons-vue';

require('./app.scss');

function convertToText(obj) {
    const string = [];
    if (typeof (obj) === 'object' && (obj.join === undefined)) {
        for (const prop in obj) {
            string.push(convertToText(obj[prop]));
        }
    } else if (typeof (obj) === 'object' && !(obj.join === undefined)) {
        for (const prop in obj) {
            string.push(convertToText(obj[prop]));
        }
    } else if (typeof (obj) === 'function') {

    } else if (typeof (obj) === 'string') {
        string.push(obj)
    }

    return string.join('<br />')
}

const app = createApp(App);
app.use(ElLoading);

app.component(FolderOpened.name, FolderOpened);
app.component(Document.name, Document);
app.component(DocumentAdd.name, DocumentAdd);
app.component(DocumentDelete.name, DocumentDelete);
app.component(Warning.name, Warning);
app.component(MuteNotification.name, MuteNotification);
app.component(MoreFilled.name, MoreFilled);
app.component(View.name, View);
app.component(CloseBold.name, CloseBold);
app.component(ArrowLeftBold.name, ArrowLeftBold);

app.config.globalProperties.appVars = window.fluentAuthAdmin;

app.mixin({
    data() {
        return {
            Storage
        }
    },
    methods: {
        $get: Rest.get,
        $post: Rest.post,
        $put: Rest.put,
        $del: Rest.delete,
        changeTitle(title) {
            jQuery('head title').text(title + ' - Fluent Auth');
        },
        $handleError(response) {
            let errorMessage = '';
            if (typeof response === 'string') {
                errorMessage = response;
            } else if (response && response.message) {
                errorMessage = response.message;
            } else {
                errorMessage = convertToText(response);
            }
            if (!errorMessage) {
                errorMessage = 'Something is wrong!';
            }
            this.$notify({
                type: 'error',
                title: 'Error',
                message: errorMessage,
                dangerouslyUseHTMLString: true
            });
        },
        convertToText,
        $t(string) {
            string = window.fluentAuthAdmin.i18n[string] || string;

            // Prepare the arguments, excluding the first one (the string itself)
            const args = Array.prototype.slice.call(arguments, 1);

            if (args.length === 0) {
                return string;
            }

            // Regular expression to match %s, %d, or %1s, %2s, etc.
            const regex = /%(\d*)s|%d/g;

            // Replace function to handle each match found by the regex
            let argIndex = 0; // Keep track of the argument index for non-numbered placeholders
            string = string.replace(regex, (match, number) => {
                // If it's a numbered placeholder, use the number to find the corresponding argument
                if (number) {
                    const index = parseInt(number, 10) - 1; // Convert to zero-based index
                    return index < args.length ? args[index] : match; // Replace or keep the placeholder
                } else {
                    // For non-numbered placeholders, use the next argument in the array
                    return argIndex < args.length ? args[argIndex++] : match; // Replace or keep the placeholder
                }
            });

            return string;
        },
        $_n(singular, plural, count) {
            let number = parseInt(count.toString().replace(/,/g, ''), 10);
            if (number > 1) {
                return this.$t(plural, count);
            }

            return this.$t(singular, count);
        }
    }
});

app.config.globalProperties.$notify = ElNotification;
app.config.globalProperties.$confirm = ElMessageBox.confirm;

const router = createRouter({
    routes,
    history: createWebHashHistory()
});

window.fluentFrameworkApp = app.use(router).mount(
    '#fluent_auth_app'
);

jQuery('.toplevel_page_fluent-security a').on('click', function () {
    jQuery('.toplevel_page_fluent-security li').removeClass('current');
    jQuery(this).parent().addClass('current');
    window.scrollTo({top: 0, behavior: 'smooth'});
});
