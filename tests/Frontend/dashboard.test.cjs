const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {parse} = require('@vue/compiler-sfc');

/*
 * Every identifier the SFC imports, stubbed.
 *
 * The imports are stripped before the script is evaluated, so anything the component names -
 * a child component in `components`, a shared helper - is an undefined reference in here.
 * Listing them by hand meant the harness broke every time a screen gained an import, and the
 * failure looked like the screen was broken rather than the test: adding RivalNotice to the
 * dashboard took four unrelated tests down with a ReferenceError.
 */
function importedNames(source) {
    const names = {};

    for (const line of source.match(/^import .*;$/gm) || []) {
        const named = line.match(/^import\s+\{([^}]+)\}/);
        const plain = line.match(/^import\s+([A-Za-z_$][\w$]*)/);

        if (named) {
            named[1].split(',').forEach((part) => {
                const name = part.split(/\s+as\s+/).pop().trim();
                if (name) names[name] = {};
            });
        } else if (plain) {
            names[plain[1]] = {};
        }
    }

    return names;
}


function screen(file, overrides = {}) {
    const {descriptor} = parse(fs.readFileSync(path.join(__dirname, '../../src/admin/Components/Dashboard', file), 'utf8'));
    const source = descriptor.script.content;
    const script = source.replace(/^import .*;\n/gm, '').replace('export default', 'module.exports =');
    const context = Object.assign({module: {exports: {}}}, importedNames(source));
    vm.runInNewContext(script, context);
    const component = context.module.exports;
    /*
     * appVars is a global mixin property in the real app, so a component may read it in
     * data() before any override lands. Empty by default and overridable like anything else.
     */
    const instance = {$t: text => text, $_n: (one, many, count) => count === 1 ? one : many, $notify: {success() {}}, $handleError() {}, appVars: overrides.appVars || {}};
    Object.assign(instance, component.data.call(instance), overrides);
    for (const [name, method] of Object.entries(component.methods || {})) instance[name] = method.bind(instance);
    for (const [name, getter] of Object.entries(component.computed || {})) Object.defineProperty(instance, name, {get: getter.bind(instance)});
    return instance;
}

test('failed initial load exits loading and exposes a retryable error', async () => {
    const page = screen('index.vue', {$get: async () => { throw Error('offline'); }});
    await page.fetchDashboard();
    assert.equal(page.loading, false);
    assert.equal(page.loadError, true);
    assert.equal(page.dashboard, false);
});

test('failed refresh preserves results and restores their date label', async () => {
    const data = {stats: []};
    const page = screen('index.vue', {dashboard: data, range: '-7 days', $get: async () => { throw Error('offline'); }});
    await page.fetchDashboard();
    assert.equal(page.dashboard, data);
    assert.equal(page.range, '-30 days');
    assert.equal(page.loadedRange, '-30 days');
    page.$get = async () => ({stats: [1]});
    page.range = '-7 days';
    await page.fetchDashboard();
    assert.equal(page.loadedRange, '-7 days');
    assert.equal(page.loadError, false);
});

test('serializes activity refreshes and IP mutations', async () => {
    let finish;
    let calls = 0;
    const page = screen('index.vue', {$get: () => { calls++; return new Promise(resolve => finish = resolve); }});
    const request = page.fetchDashboard();
    await page.fetchDashboard();
    assert.equal(calls, 1);
    finish({stats: []});
    await request;
    page.blocking = '192.0.2.1';
    await page.fetchDashboard();
    assert.equal(calls, 1);
});

test('IP blocking needs the selected confirmation and prevents duplicate requests', async () => {
    const row = {ip: '192.0.2.1', is_blocked: false};
    let calls = 0;
    let finish;
    const page = screen('index.vue', {$post: () => { calls++; return new Promise(resolve => finish = resolve); }});
    await page.blockIp(row);
    assert.equal(calls, 0);
    page.pendingBlock = row;
    const request = page.blockIp(row);
    await page.blockIp(row);
    assert.equal(calls, 1);
    finish({message: 'saved'});
    await request;
    assert.equal(row.is_blocked, true);
    assert.equal(page.pendingBlock, null);
    assert.equal(page.blocking, '');
});

test('failed security checks cannot be presented as a clean result', async () => {
    const page = screen('_SecurityAside.vue', {$get: async () => { throw Error('offline'); }});
    await page.getFindings();
    assert.equal(page.loadError, true);
    assert.equal(page.loading, false);
    page.$get = async () => ({findings: [{id: 1, severity: 'advice'}, {id: 2, severity: 'custom'}, {id: 3, severity: 'fix'}]});
    await page.getFindings();
    assert.equal(page.loadError, false);
    assert.deepEqual(Array.from(page.preview, item => item.id), [3, 2]);
    assert.equal(page.recommendations, 1);
});

test('chart segments fill their stack and preserve counts at different totals', () => {
    const page = screen('_ActivityChart.vue', {chart: {max: 8, series: [{key: 'success', label: 'Successful'}], points: [
        {tooltip: 'Today', counts: {success: 2, failed: 1, blocked: 1}},
        {tooltip: 'Yesterday', counts: {success: 8, failed: 0, blocked: 0}},
        {tooltip: 'Quiet', counts: {success: 0, failed: 0, blocked: 0}}
    ]}});
    for (const column of page.columns.filter(column => column.total)) {
        assert.equal(column.segments.reduce((total, segment) => total + segment.height, 0), 100);
        const success = column.segments.find(segment => segment.key === 'success');
        assert.equal(column.height * success.height / 100, column.counts.success / page.niceMax * 100);
    }
    assert.equal(page.columns[2].segments.length, 0);
    assert.match(page.columnLabel(page.columns[0]), /Successful: 2/);
});
