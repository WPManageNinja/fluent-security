// Run with: node --test tests/Frontend/security-findings.test.cjs
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


const root = path.resolve(__dirname, '../..');
const {descriptor} = parse(fs.readFileSync(path.join(root, 'src/admin/Components/Security/Findings.vue'), 'utf8'));
const source = descriptor.script.content;
const script = source.replace(/^import .*;\n/gm, '').replace('export default', 'module.exports =');
const context = Object.assign({module: {exports: {}}}, importedNames(source));
vm.runInNewContext(script, context);
const component = context.module.exports;

function screen(overrides = {}) {
    const instance = {
        ...component.data(),
        $t: text => text,
        $_n: (one, many, count) => count === 1 ? one : many,
        $notify: {success() {}},
        $handleError() {},
        appVars: {},
        ...overrides
    };
    for (const [name, method] of Object.entries(component.methods)) instance[name] = method.bind(instance);
    for (const [name, getter] of Object.entries(component.computed)) Object.defineProperty(instance, name, {get: getter.bind(instance)});
    return instance;
}

const data = {
    findings: [
        {id: 'a', check: 'users', group: 'users', severity: 'fix', title: 'Review administrators'},
        {id: 'b', check: 'files', group: 'files', severity: 'look', title: 'Review a file', details: ['wp-content/example.php']},
        {id: 'c', check: 'config', group: 'config', severity: 'advice', title: 'Disable file editing'},
        {id: 'd', check: 'addon', group: 'plugins', severity: 'custom', title: 'Extension check'}
    ],
    passed: [{id: 'p', group: 'login', state: 'passed', title: 'Login limit enabled'}],
    accepted: [{id: 'x', group: 'files', state: 'accepted', title: 'Expected file'}],
    counts: {attention: 3, to_fix: 1, look: 1, advice: 1, passed: 1, accepted: 1}
};

function ids(items) { return Array.from(items, item => item.id); }

test('keeps recommendations separate and unknown severities visible for review', () => {
    const instance = screen();
    instance.apply(data);
    assert.deepEqual(ids(instance.visibleFindings), ['a', 'b', 'd']);
    instance.selectView('advice');
    assert.deepEqual(ids(instance.visibleFindings), ['c']);
    instance.selectView('passed');
    assert.deepEqual(ids(instance.visibleFindings), ['p']);
    instance.selectView('accepted');
    assert.deepEqual(ids(instance.visibleFindings), ['x']);
});

test('combines category and detail search, then clears filters on view change', () => {
    const instance = screen();
    instance.apply(data);
    instance.group = 'files';
    instance.query = 'EXAMPLE.PHP';
    assert.deepEqual(ids(instance.visibleFindings), ['b']);
    instance.query = 'missing';
    assert.equal(instance.visibleFindings.length, 0);
    instance.selectView('passed');
    assert.equal(instance.group, 'all');
    assert.equal(instance.query, '');
    assert.deepEqual(ids(instance.visibleFindings), ['p']);
});

test('resets a category when the server removes its final finding', () => {
    const instance = screen();
    instance.apply(data);
    instance.group = 'files';
    instance.apply({...data, findings: data.findings.filter(item => item.id !== 'b')});
    assert.equal(instance.group, 'all');
    assert.deepEqual(ids(instance.visibleFindings), ['a', 'd']);
});

test('failed initial load cannot present a successful check result', async () => {
    const instance = screen({$get: async () => { throw new Error('Offline'); }});
    await instance.load();
    assert.equal(instance.loaded, false);
    assert.equal(instance.loading, false);
    assert.equal(instance.error, 'Offline');
});

test('failed refresh preserves existing results and releases the loading state', async () => {
    const instance = screen({$get: async () => data});
    await instance.load();
    instance.$get = async () => { throw new Error('Offline'); };
    await instance.load();
    assert.equal(instance.loaded, true);
    assert.equal(instance.refreshing, false);
    assert.equal(instance.error, 'Offline');
    assert.deepEqual(ids(instance.visibleFindings), ['a', 'b', 'd']);
});

test('serializes mutations and blocks refresh until the full response is applied', async () => {
    let resolve, writes = 0, reads = 0;
    const instance = screen({
        $post: () => { writes++; return new Promise(done => { resolve = done; }); },
        $get: async () => { reads++; return data; }
    });
    instance.apply(data);
    const pending = instance.act('fix', data.findings[0]);
    await instance.act('accept', data.findings[1]);
    await instance.load();
    assert.equal(writes, 1);
    assert.equal(reads, 0);
    resolve({...data, findings: data.findings.slice(1), settings: {updated: true}});
    await pending;
    assert.equal(instance.acting, '');
    assert.equal(instance.appVars.auth_settings.updated, true);
    assert.deepEqual(ids(instance.visibleFindings), ['b', 'd']);
});

test('mutation errors retain findings and let the user retry', async () => {
    let error;
    const instance = screen({
        $post: async () => { throw new Error('Not saved'); },
        $handleError: value => { error = value; }
    });
    instance.apply(data);
    await instance.act('accept', data.findings[0]);
    assert.equal(instance.acting, '');
    assert.equal(error.message, 'Not saved');
    assert.deepEqual(ids(instance.visibleFindings), ['a', 'b', 'd']);
});

test('failed monitoring status is distinguished from never having run', async () => {
    const instance = screen({$get: async () => { throw new Error('Unavailable'); }});
    await instance.getScanState();
    assert.equal(instance.scanError, true);
    assert.equal(instance.scanLoading, false);
});


test('unknown severities cannot produce a clean verdict', () => {
    const instance = screen();
    instance.apply({...data, findings: [data.findings[3]], counts: {attention: 0, to_fix: 0}});
    assert.equal(instance.verdict.tone, 'is_look');
});
