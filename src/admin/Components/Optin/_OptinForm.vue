<script type="text/babel">
/*
 * The mailing list signup, drawn the same way in both places that ask.
 *
 * Two hosts, one form: the wizard's last screen, where it is the only thing left to read,
 * and the dashboard aside, where it is a 380px card among others. What differs between
 * them is the frame around it, which is the host's business - the question, the fields and
 * what pressing the button sends are the same either way, and keeping them in one file is
 * the only way that stays true.
 *
 * Prefilled from the administrator's own account, because the person reading this is the
 * person being asked. Both fields stay editable all the same: the address WordPress has
 * for somebody is often a role account nobody reads.
 */
export default {
    name: 'OptinForm',
    props: {
        /* `wide` on the wizard, where there is room for the two fields side by side. */
        layout: {
            type: String,
            default: 'narrow'
        }
    },
    emits: ['answered'],
    data() {
        return {
            form: {
                full_name: '',
                email: '',
                /*
                 * Off until somebody ticks it.
                 *
                 * This box is consent to send something we are not owed - the environment
                 * details - and a consent box that arrives already ticked is not consent to
                 * anything. GDPR names pre-ticked boxes specifically, and the service this
                 * form belongs to says on its face that the optional half is optional, which
                 * it was not while the default answered for the reader.
                 *
                 * It also costs nothing worth having: a tick collected from somebody who did
                 * not read the label is a PHP version we cannot honestly say anybody agreed
                 * to send.
                 */
                share_essentials: 'no'
            },
            saving: false,
            subscribed: false,
            /* The server's sentence, which is the one that knows what actually happened. */
            done: ''
        };
    },
    methods: {
        subscribe() {
            if (!this.form.email) {
                this.$notify.error(this.$t('Please enter an email address.'));
                return;
            }

            this.saving = true;

            this.$post('optin/subscribe', this.form)
                .then(response => {
                    this.subscribed = true;
                    this.done = response.message;
                    this.$notify.success(response.message);
                    /*
                     * Closes the question everywhere at once. The server has already
                     * recorded it, but the dashboard reads this flag from the page it was
                     * loaded with - without this, finishing the wizard and clicking through
                     * to the dashboard would ask a second time in the same breath.
                     */
                    this.appVars.optin_required = false;
                    this.$emit('answered', 'subscribed');
                })
                .catch(error => this.$handleError(error))
                .finally(() => {
                    this.saving = false;
                });
        },
        /* Not now, for a week. See Optin::DISMISS_DAYS. */
        dismiss() {
            if (this.saving) {
                return;
            }

            this.saving = true;

            this.$post('optin/dismiss')
                .then(() => {
                    this.appVars.optin_required = false;
                    this.$emit('answered', 'dismissed');
                })
                .catch(error => this.$handleError(error))
                .finally(() => {
                    this.saving = false;
                });
        }
    },
    created() {
        this.form.full_name = this.appVars.me.full_name || '';
        this.form.email = this.appVars.me.email || '';
    }
};
</script>

<template>
    <div class="fls_optin" :class="'is_' + layout">
        <!--
            The server's own sentence rather than one of this component's, because only the
            server knows which of the two happened: an address already confirmed is told it is
            subscribed, a fresh one is told to check its inbox. A second copy of that decision
            here would be a second place for the two to disagree.
        -->
        <p v-if="subscribed" class="fls_optin_done">
            <span class="dashicons dashicons-yes" aria-hidden="true"></span>
            {{ done }}
        </p>

        <form v-else @submit.prevent="subscribe">
            <p class="fls_optin_intro">{{ $t('__optin_intro__') }}</p>

            <div class="fls_optin_fields">
                <label class="fls_optin_field">
                    <span class="fls_optin_label">{{ $t('Your Name') }}</span>
                    <el-input v-model="form.full_name" :placeholder="$t('Your Full Name')"/>
                </label>

                <label class="fls_optin_field">
                    <span class="fls_optin_label">{{ $t('Your Email Address') }}</span>
                    <el-input v-model="form.email" type="email" :placeholder="$t('Your Email')"/>
                </label>
            </div>

            <!--
                What is sent is listed, not summarised - see Optin::essentials(), which is
                the whole of it. The tooltip's click is stopped because reading what goes
                should not be the same gesture as agreeing to send it.
            -->
            <el-checkbox class="fls_optin_share" true-value="yes" false-value="no"
                         v-model="form.share_essentials">
                <span class="fls_optin_share_text">
                    {{ $t('__optin_share__') }}
                    <el-tooltip effect="dark" placement="top" :content="$t('__optin_share_details__')">
                        <span class="fls_optin_info dashicons dashicons-info-outline"
                              @click.stop.prevent></span>
                    </el-tooltip>
                </span>
            </el-checkbox>

            <div class="fls_optin_actions">
                <el-button type="primary" native-type="submit" :loading="saving" :disabled="saving">
                    {{ $t('Subscribe to updates') }}
                </el-button>
                <el-button text class="fls_optin_no" :disabled="saving" @click="dismiss">
                    {{ $t('No thanks') }}
                </el-button>
            </div>
        </form>
    </div>
</template>
