<script type="text/babel">
import icons from './icons';
import ViewFile from './_ViewFile.vue';

/*
 * The must-use plugins directory, listed rather than judged.
 *
 * These files run on every request and cannot be switched off from the plugins screen, which
 * is exactly why they are worth showing and exactly why an alarm about them would be wrong on
 * most sites: managed hosts put their own here, and a plugin that opened by accusing somebody
 * of their host's arrangement teaches them to stop reading it.
 *
 * So this section makes no claim at all beyond what it can see. The check that watches these
 * records what is here on its first run and speaks up only when something changes or arrives
 * afterwards; this is the other half of that bargain - what the plugin will not accuse anybody
 * of, it will at least let them read, because nobody can tell a legitimate mu-plugin from a
 * planted one without opening it.
 *
 * Which leaves one thing the automatic record cannot do, and the button here is it. Recording
 * on first sight takes the day this plugin was installed on trust, so a site already broken
 * into records the backdoor as normal. Nobody can fix that for a reader - but somebody who has
 * now opened these files and is satisfied can say so, and have the record start from a state
 * they have actually looked at rather than one nobody ever saw.
 */
export default {
    name: 'MuPluginsSection',
    components: {
        ViewFile
    },
    data() {
        return {
            icons,
            open: false,
            loading: true,
            files: [],
            directory: '',
            baselinedHuman: '',
            saving: false,
            viewing: false,
            viewingFile: null
        }
    },
    computed: {
        /*
         * Only what has arrived or moved since watching began. A file that was here on the
         * first run is not something this section has an opinion about.
         */
        unrecorded() {
            return this.files.filter(file => file.status !== 'recorded');
        },
        statusTag() {
            if (!this.files.length) {
                return 'is_success';
            }

            return this.unrecorded.length ? 'is_warning' : 'is_neutral';
        },
        statusLabel() {
            if (!this.files.length) {
                return this.$t('None');
            }

            if (this.unrecorded.length) {
                return this.$_n('%s to check', '%s to check', this.unrecorded.length);
            }

            return this.$_n('%s file', '%s files', this.files.length);
        }
    },
    methods: {
        load() {
            this.$get('security-scan-settings/mu-plugins')
                .then(response => {
                    this.files = response.files || [];
                    this.directory = response.directory || '';
                    this.baselinedHuman = response.baselined_human || '';
                })
                .catch(() => {
                    /*
                     * Silent. This is a listing beside a scan, not the scan - an error banner
                     * here would read as a finding about the site rather than about us.
                     */
                    this.files = [];
                })
                .finally(() => {
                    this.loading = false;
                });
        },
        /*
         * Vouch for the whole folder as it stands.
         *
         * Whole-folder rather than per file, the way accepting a finding is: the reader is
         * answering one question - "yes, I have looked at these" - and asking it once per file
         * would be asking them to do the sorting this section exists to save them.
         */
        record() {
            this.saving = true;

            this.$post('security-scan-settings/mu-plugins/baseline')
                .then(response => {
                    this.files = response.files || [];
                    this.baselinedHuman = response.baselined_human || '';
                    this.$notify.success(response.message);
                })
                .catch(errors => {
                    this.$handleError(errors);
                })
                .finally(() => {
                    this.saving = false;
                });
        },
        fileLabel(file) {
            const labels = {
                changed: this.$t('Changed since recorded'),
                new: this.$t('New since recorded')
            };

            return labels[file.status] || '';
        },
        fileTag(file) {
            return file.status === 'changed' ? 'is_blocked' : 'is_warning';
        },
        readableSize(bytes) {
            if (bytes < 1024) {
                return bytes + ' B';
            }

            if (bytes < 1024 * 1024) {
                return Math.round(bytes / 1024) + ' KB';
            }

            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        },
        readableDate(stamp) {
            if (!stamp) {
                return '';
            }

            return new Date(stamp * 1000).toLocaleDateString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric'
            });
        },
        /* No official copy exists for any of these, so the viewer only ever shows the source. */
        viewFile(file) {
            this.viewing = true;
            this.viewingFile = {scope: 'mu-plugin', file: file.name, status: 'new'};
        },
        closeViewer() {
            this.viewing = false;
            this.viewingFile = null;
        }
    },
    mounted() {
        this.load();
    }
}
</script>

<template>
    <div class="fls_dcard">
        <component :is="files.length ? 'button' : 'div'"
                   :type="files.length ? 'button' : null"
                   class="fls_scan_summary"
                   :class="{is_open: open, is_static: !files.length}"
                   @click="files.length && (open = !open)">
            <span class="fls_scan_summary_icon" v-html="icons.plugin"></span>

            <span class="fls_scan_summary_name">{{ $t('Must-Use Plugins') }}</span>

            <span class="fls_scan_summary_tags">
                <span class="fls_tag" :class="statusTag">{{ statusLabel }}</span>
            </span>

            <span v-if="files.length" class="fls_scan_chevron" v-html="icons.chevron"></span>
        </component>

        <div v-if="open && files.length" class="fls_scan_detail" v-loading="saving">
            <!--
                Said before the list rather than after it. Somebody reading these names needs
                to know what the plugin is and is not claiming about them first, or the list
                reads as a list of suspects.
            -->
            <p class="fls_scan_section_note">
                <span v-if="baselinedHuman"
                      v-html="$t('__mu_plugins_watched_note__', baselinedHuman)"></span>
                <span v-else>{{ $t('__mu_plugins_note__') }}</span>
            </p>

            <!--
                The same bar the premium extensions carry, because it is the same offer - the
                site's own record of files nothing else can vouch for. Kept below the note so
                the claim is read before the button.
            -->
            <div class="fls_scan_snapshot" :class="unrecorded.length ? 'is_changed' : 'is_watching'">
                <span class="fls_scan_snapshot_icon"
                      v-html="unrecorded.length ? icons.alert : icons.radar"></span>

                <div class="fls_scan_snapshot_text">
                    <strong v-if="unrecorded.length">
                        {{ $_n('%s file is new or changed since it was recorded', '%s files are new or changed since they were recorded', unrecorded.length) }}
                    </strong>
                    <strong v-else>
                        {{ $_n('Watching %s file', 'Watching %s files', files.length) }}
                    </strong>

                    <span v-if="unrecorded.length">{{ $t('__mu_plugins_unrecorded_note__') }}</span>
                    <span v-else>{{ $t('__mu_plugins_record_note__') }}</span>
                </div>

                <div class="fls_scan_snapshot_actions">
                    <el-button size="small" :disabled="saving" @click="record()">
                        {{ unrecorded.length ? $t('Accept and record') : $t('Update record') }}
                    </el-button>
                </div>
            </div>

            <ul class="fls_mu_list">
                <li v-for="file in files" :key="file.path">
                    <span class="fls_mu_icon" v-html="icons.file"></span>

                    <span class="fls_mu_name">{{ file.name }}</span>

                    <span v-if="file.status !== 'recorded'" class="fls_tag" :class="fileTag(file)">
                        {{ fileLabel(file) }}
                    </span>

                    <span class="fls_mu_meta">
                        {{ readableSize(file.size) }} · {{ readableDate(file.modified) }}
                    </span>

                    <button type="button" class="fls_mu_view" @click="viewFile(file)">
                        <span v-html="icons.eye"></span>
                        {{ $t('View') }}
                    </button>
                </li>
            </ul>
        </div>

        <el-dialog :title="$t('View File')" v-model="viewing" width="70%" :append-to-body="true"
                   @closed="closeViewer">
            <view-file v-if="viewingFile" :viewing_file="viewingFile"/>
        </el-dialog>
    </div>
</template>
