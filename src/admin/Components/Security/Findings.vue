<script type="text/babel">
import icons from '../SecurityScan/icons';
import FindingRow from './_FindingRow.vue';
import FindingsAside from './_FindingsAside.vue';
import {counts as subNavCounts} from '@/Bits/subNav';

export default {
    name: 'SecurityFindings',
    components: {FindingRow, FindingsAside},
    data() {
        return {
            icons,
            loading: true,
            refreshing: false,
            loaded: false,
            error: '',
            updatedAt: '',
            findings: [],
            accepted: [],
            passed: [],
            counts: {open: 0, to_fix: 0, look: 0, advice: 0, attention: 0, passed: 0, accepted: 0},
            score: {done: 0, total: 0, percent: 0},
            scan: null,
            scanLoading: true,
            scanError: false,
            view: 'attention',
            group: 'all',
            query: '',
            acting: '',
            announcement: ''
        };
    },
    computed: {
        /* What the section bar counts: everything open that is more than advice. */
        attentionCount() {
            return this.findings.filter(item => item.severity !== 'advice').length;
        },
        views() {
            return [
                {id: 'attention', label: this.$t('Needs attention'), count: this.attentionCount},
                {id: 'advice', label: this.$t('Recommendations'), count: this.findings.filter(item => item.severity === 'advice').length},
                {id: 'passed', label: this.$t('Passed'), count: this.passed.length},
                {id: 'accepted', label: this.$t('Dismissed'), count: this.accepted.length}
            ];
        },
        currentView() {
            return this.views.find(view => view.id === this.view);
        },
        viewFindings() {
            if (this.view === 'accepted') return this.accepted;
            if (this.view === 'passed') return this.passed;
            return this.findings.filter(item => this.view === 'advice' ? item.severity === 'advice' : item.severity !== 'advice');
        },
        groupLabels() {
            return {
                files: this.$t('Files'), config: this.$t('Configuration'), login: this.$t('Login'),
                users: this.$t('Users'), plugins: this.$t('Plugins & Themes')
            };
        },
        groups() {
            return [...new Set(this.viewFindings.map(item => item.group))].map(key => ({
                key, label: this.groupLabels[key] || key
            }));
        },
        visibleFindings() {
            const query = this.query.trim().toLocaleLowerCase();
            return this.viewFindings.filter(item => {
                if (this.group !== 'all' && item.group !== this.group) return false;
                const content = [item.title, item.why, this.groupLabels[item.group], ...(item.details || [])].join(' ').toLocaleLowerCase();
                return !query || content.includes(query);
            });
        },
        isFiltered() {
            return this.group !== 'all' || !!this.query.trim();
        },
        viewDescription() {
            const descriptions = {
                attention: this.$t('Review these findings, starting with the highest priority.'),
                advice: this.$t('Optional extras that make your site harder to break into. Nothing here is wrong with your site.'),
                passed: this.$t('These checks found nothing wrong.'),
                accepted: this.$t('Findings you have set aside. Restore one to see it in the list again.')
            };
            return descriptions[this.view];
        },
        verdict() {
            if (this.counts.to_fix) {
                return {tone: 'is_fix', icon: icons.alert,
                    title: this.$_n('%s finding needs action', '%s findings need action', this.counts.to_fix),
                    body: this.$t('Start with the items marked Action needed.')};
            }
            if (this.views[0].count) {
                return {tone: 'is_look', icon: icons.shield,
                    title: this.$_n('%s finding to review', '%s findings to review', this.views[0].count),
                    body: this.$t('Review the findings below to decide what applies to your site.')};
            }
            return {tone: 'is_passed', icon: icons.shieldTick,
                title: this.$t('Nothing needs attention'),
                body: this.$t('The Recommendations tab has optional extras you can look at.')};
        },
        emptyTitle() {
            if (this.isFiltered) return this.$t('No matching checks');
            const titles = {
                attention: this.$t('No findings need attention'), advice: this.$t('No recommendations right now'),
                passed: this.$t('No passed checks to show'), accepted: this.$t('No dismissed findings')
            };
            return titles[this.view];
        }
    },
    methods: {
        async load() {
            if (this.refreshing || this.acting) return;
            this.refreshing = true;
            this.error = '';
            try {
                const response = await this.$get('security-findings');
                this.apply(response);
                this.loaded = true;
                this.updatedAt = new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
                this.announcement = this.$t('Security checks updated.');
            } catch (error) {
                this.error = error && error.message || this.$t('Unable to load security checks. Please try again.');
            } finally {
                this.loading = false;
                this.refreshing = false;
            }
        },
        apply(response) {
            this.findings = response.findings || [];
            this.accepted = response.accepted || [];
            this.passed = response.passed || [];
            this.counts = response.counts || this.counts;
            this.score = response.score || this.score;
            if (this.group !== 'all' && !this.groups.some(item => item.key === this.group)) this.group = 'all';
            /*
             * The section bar is drawn by the shell, above this screen, so the number on its
             * Findings tab is published rather than passed down. Here rather than after a load
             * because acting on a finding lands here too, which is what keeps the badge in step
             * with a list somebody is working through.
             */
            subNavCounts.findings = this.attentionCount;
        },
        async getScanState() {
            this.scanLoading = true;
            this.scanError = false;
            try {
                const response = await this.$get('security-scan-settings');
                this.scan = response.settings || null;
                this.scanError = !this.scan;
            } catch (error) {
                this.scanError = true;
            } finally {
                this.scanLoading = false;
            }
        },
        refresh() {
            if (this.refreshing || this.acting) return;
            this.load();
            this.getScanState();
        },
        selectView(view) {
            this.view = view;
            this.clearFilters();
        },
        clearFilters() {
            this.group = 'all';
            this.query = '';
        },
        async act(action, finding) {
            // Every response contains a full snapshot. Serialize writes so an older one
            // cannot overwrite the result of a later action on a different finding.
            if (this.acting || this.refreshing) return;
            this.acting = finding.id;
            try {
                const response = await this.$post('security-findings/' + action, {check: finding.check, finding: finding.id});
                if (response.settings) this.appVars.auth_settings = response.settings;
                this.apply(response);
                this.announcement = response.message || this.$t('Security checks updated.');
                this.$notify.success(this.announcement);
                this.updatedAt = new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
            } catch (error) {
                this.$handleError(error);
            } finally {
                this.acting = '';
            }
        },
        navigate(finding) {
            if (!finding.route) return;
            const target = {name: finding.route};
            if (finding.section) target.query = {section: finding.section};
            this.$router.push(target);
        }
    },
    mounted() {
        this.load();
        this.getScanState();
    }
};
</script>

<template>
    <div class="fls_page fls_security">
        <div class="fls_security_inner">
            <div class="fls_page_head">
                <div>
                    <h1 class="fls_page_title">{{ $t('Findings') }}</h1>
                    <p class="fls_page_desc">{{ $t('What the checks found on your site, and what to do about it.') }}</p>
                </div>
                <div class="fls_security_refresh">
                    <span v-if="updatedAt">{{ $t('Updated at %s', updatedAt) }}</span>
                    <el-button :loading="refreshing" :disabled="!!acting" @click="refresh">
                        {{ $t('Recheck') }}
                    </el-button>
                </div>
            </div>
            <p class="screen-reader-text" role="status">{{ announcement }}</p>

            <el-skeleton v-if="loading" :animated="true" :rows="8"/>
            <div v-if="error" class="fls_security_error" role="alert">
                <strong>{{ loaded ? $t('Could not refresh checks') : $t('Could not load security checks') }}</strong>
                <p>{{ error }}</p>
                <p v-if="loaded">{{ $t('Showing the last loaded results. Use Recheck to try again.') }}</p>
                <el-button v-else :loading="refreshing" @click="refresh">{{ $t('Try again') }}</el-button>
            </div>

            <template v-if="loaded">
                <section class="fls_security_summary" :class="verdict.tone" :aria-label="$t('Check summary')">
                    <span class="fls_security_summary_icon" aria-hidden="true" v-html="verdict.icon"></span>
                    <div>
                        <h2>{{ verdict.title }}</h2>
                        <p>{{ verdict.body }}</p>
                    </div>
                    <button type="button" class="fls_security_passed_link" @click="selectView('passed')">
                        <span aria-hidden="true" v-html="icons.tick"></span>
                        {{ $_n('%s check passed', '%s checks passed', passed.length) }} <span aria-hidden="true">→</span>
                    </button>
                </section>

                <div class="fls_security_workspace">
                    <section class="fls_security_results" :aria-label="$t('Security checks')" :aria-busy="refreshing || !!acting">
                        <div class="fls_security_views" role="group" :aria-label="$t('Finding status')">
                            <button v-for="item in views" :key="item.id" type="button"
                                    :class="{is_active: view === item.id}" :aria-pressed="view === item.id"
                                    @click="selectView(item.id)">
                                {{ item.label }} <span>{{ item.count }}</span>
                            </button>
                        </div>
                        <div class="fls_security_toolbar">
                            <el-input v-model="query" clearable :placeholder="$t('Search checks')" :aria-label="$t('Search checks')"/>
                            <select v-model="group" :aria-label="$t('Filter by category')">
                                <option value="all">{{ $t('All categories') }}</option>
                                <option v-for="item in groups" :key="item.key" :value="item.key">{{ item.label }}</option>
                            </select>
                        </div>
                        <div v-if="visibleFindings.length && (view !== 'attention' || isFiltered)" class="fls_security_list_intro">
                            <p>{{ viewDescription }}</p>
                            <button v-if="isFiltered && visibleFindings.length" type="button" @click="clearFilters">{{ $t('Clear filters') }}</button>
                        </div>
                        <p v-if="isFiltered" class="fls_security_match_count" role="status">{{ $t('%s of %s checks', visibleFindings.length, viewFindings.length) }}</p>
                        <div v-if="visibleFindings.length" class="fls_find_list">
                            <finding-row v-for="finding in visibleFindings" :key="view + finding.id"
                                         :finding="finding" :busy="acting === finding.id" :disabled="!!acting || refreshing"
                                         @fix="item => act('fix', item)" @accept="item => act('accept', item)"
                                         @unaccept="item => act('unaccept', item)" @navigate="navigate"/>
                        </div>
                        <div v-else class="fls_security_empty">
                            <span aria-hidden="true" v-html="isFiltered ? icons.unknown : icons.shieldTick"></span>
                            <h2>{{ emptyTitle }}</h2>
                            <p>{{ isFiltered ? $t('Try another search or clear your filters.') : viewDescription }}</p>
                            <el-button v-if="isFiltered" @click="clearFilters">{{ $t('Clear filters') }}</el-button>
                            <el-button v-else-if="view === 'attention' && counts.advice" @click="selectView('advice')">{{ $t('View recommendations') }}</el-button>
                        </div>
                    </section>
                    <findings-aside :score="score" :scan="scan" :loading="scanLoading" :error="scanError" @retry="getScanState"/>
                </div>
            </template>
        </div>
    </div>
</template>
