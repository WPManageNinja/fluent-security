<script type="text/babel">
import icons from './icons';

/*
 * Sign-in activity over the selected range: one stacked bar per bucket.
 *
 * Drawn with elements and percentages rather than SVG or a charting library. A stacked
 * bar chart is a flex row of columns and a column is a stack of divs, so the whole thing
 * is about twenty lines of CSS - where SVG would need the plot measured in pixels before
 * anything could be positioned, and a library would be a dependency and a bundle for one
 * chart on one screen.
 *
 * Stacked rather than grouped: the question this answers first is how much traffic the
 * login form saw on a given day, and only then how it split.
 */
export default {
    name: 'ActivityChart',
    props: {
        chart: {
            type: Object,
            required: true
        }
    },
    data() {
        return {
            icons,
            active: -1,
            /* Bottom of the stack first, so the fill order matches the legend. */
            colors: {
                success: '#23A682',
                failed: '#F6B51E',
                blocked: '#F04438'
            }
        }
    },
    computed: {
        hasData() {
            return this.chart.max > 0;
        },
        /*
         * The top gridline, rounded up to something a person would choose - 1, 2 or 5
         * times a power of ten. Scaling the bars to the exact maximum instead would put
         * the busiest bar flush against the top of the plot and label the axis 37.
         */
        niceMax() {
            const max = this.chart.max;

            if (max <= 4) {
                return 4;
            }

            const magnitude = Math.pow(10, Math.floor(Math.log10(max)));
            const steps = [1, 2, 2.5, 5, 10];

            for (const step of steps) {
                const candidate = step * magnitude;

                if (candidate >= max) {
                    return candidate;
                }
            }

            return max;
        },
        gridLines() {
            const steps = this.niceMax % 5 === 0 ? 5 : 4;
            return Array.from({length: steps + 1}, (_, index) => 1 - index / steps).map(fraction => ({
                fraction: fraction,
                offset: (1 - fraction) * 100,
                label: this.formatCount(Math.round(this.niceMax * fraction))
            }));
        },
        /*
         * How many buckets to skip between x labels. Thirty dates across a 900px column
         * overlap into a grey smear, so only every nth is printed - the tooltip carries
         * the exact date for the one being looked at.
         */
        labelStep() {
            return Math.max(1, Math.ceil(this.chart.points.length / 9));
        },
        columns() {
            return this.chart.points.map((point, index) => {
                const counts = point.counts;
                const total = counts.success + counts.failed + counts.blocked;

                /* Top of the stack first: this is the DOM order inside the column. */
                const segments = ['blocked', 'failed', 'success']
                    .filter(key => counts[key] > 0)
                    .map(key => ({
                        key: key,
                        height: (counts[key] / total) * 100,
                        color: this.colors[key]
                    }));

                return {
                    label: point.label,
                    tooltip: point.tooltip,
                    counts: counts,
                    total: total,
                    segments: segments,
                    height: (total / this.niceMax) * 100,
                    showLabel: index % this.labelStep === 0
                };
            });
        },
        activeColumn() {
            return this.active > -1 ? this.columns[this.active] : null;
        },
        /*
         * The tooltip sits over the top of its own bar. Near either end of the plot it is
         * pinned to that end instead of centred, so it cannot hang off the card.
         */
        tipStyle() {
            const count = this.columns.length;
            const centre = ((this.active + 0.5) / count) * 100;
            const nearStart = centre < 12;
            const nearEnd = centre > 88;

            let shift = '-50%';

            if (nearStart) {
                shift = '0';
            } else if (nearEnd) {
                shift = '-100%';
            }

            return {
                left: centre + '%',
                bottom: 'calc(' + Math.min(this.activeColumn.height, 88) + '% + 10px)',
                transform: 'translateX(' + shift + ')'
            };
        }
    },
    methods: {
        columnLabel(column) {
            return column.tooltip + '. ' + this.chart.series.map(series => series.label + ': ' + column.counts[series.key]).join(', ');
        },
        moveFocus(event, index) {
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? this.columns.length - 1
                : Math.max(0, Math.min(this.columns.length - 1, index + (event.key === 'ArrowRight' ? 1 : -1)));
            this.$refs.columns[next].focus();
        },
        formatCount(value) {
            if (value >= 1000) {
                return (value / 1000).toFixed(value % 1000 === 0 ? 0 : 1) + 'k';
            }

            return String(value);
        },
        /* Only the top segment is rounded, so a stack still reads as one bar. */
        segmentStyle(column, index) {
            const style = {
                height: column.segments[index].height + '%',
                background: column.segments[index].color
            };

            if (index === 0) {
                style.borderRadius = '3px 3px 0 0';
            }

            return style;
        }
    }
}
</script>

<template>
    <div class="fls_chart">
        <div class="fls_chart_legend">
            <div v-for="series in chart.series" :key="series.key" class="fls_chart_legend_item">
                <span class="fls_chart_swatch" :style="{background: colors[series.key]}"></span>
                {{ series.label }}
            </div>
        </div>

        <div v-if="hasData" class="fls_chart_plot">
            <div class="fls_chart_area">
                <div class="fls_chart_grid">
                    <div v-for="line in gridLines" :key="line.fraction" class="fls_chart_grid_row"
                         :style="{top: line.offset + '%'}">
                        <span class="fls_chart_grid_label">{{ line.label }}</span>
                    </div>
                </div>

                <div class="fls_chart_cols" @mouseleave="active = -1">
                    <div v-for="(column, index) in columns" :key="index" class="fls_chart_col" ref="columns" role="img"
                         :tabindex="index === Math.max(active, 0) ? 0 : -1" :aria-label="columnLabel(column)"
                         @focus="active = index" @blur="active = -1"
                         @keydown.left.prevent="moveFocus($event, index)" @keydown.right.prevent="moveFocus($event, index)"
                         @keydown.home.prevent="moveFocus($event, index)" @keydown.end.prevent="moveFocus($event, index)"
                         :class="{is_active: active === index}" @mouseenter="active = index">
                        <div class="fls_chart_stack" :style="{height: column.height + '%'}">
                            <span v-for="(segment, segmentIndex) in column.segments" :key="segment.key"
                                  class="fls_chart_seg" :style="segmentStyle(column, segmentIndex)"></span>
                        </div>
                        <span v-if="column.showLabel" class="fls_chart_x_label">{{ column.label }}</span>
                    </div>
                </div>

                <div v-if="activeColumn" class="fls_chart_tip" :style="tipStyle">
                    <div class="fls_chart_tip_title">{{ activeColumn.tooltip }}</div>
                    <div v-for="series in chart.series" :key="series.key" class="fls_chart_tip_row">
                        <span>
                            <span class="fls_chart_swatch" :style="{background: colors[series.key]}"></span>
                            {{ series.label }}
                        </span>
                        <b>{{ activeColumn.counts[series.key] }}</b>
                    </div>
                </div>
            </div>
        </div>

        <div v-else class="fls_empty">
            <span v-html="icons.empty"></span>
            {{ $t('No login activity in this period yet') }}
        </div>
    </div>
</template>
