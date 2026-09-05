// Run with: node --test tests/Frontend/recovery.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {parse} = require('@vue/compiler-sfc');

const root = path.resolve(__dirname, '../..');
const {descriptor} = parse(fs.readFileSync(path.join(root, 'src/admin/Components/Security/Recovery.vue'), 'utf8'));
const script = descriptor.script.content.replace(/^import .*;\n/gm, '').replace('export default', 'module.exports =');
const context = {module: {exports: {}}, icons: {}, SecurityTabs: {}};
vm.runInNewContext(script, context);
const component = context.module.exports;

function screen(overrides = {}) {
    const instance = {
        ...component.data(),
        $t: (text, ...args) => {
            let index = 0;
            return text.replace(/%(\d*)s/g, (match, number) => number ? args[number - 1] : args[index++]);
        },
        $_n: (one, many, count) => (count === 1 ? one : many).replace('%s', count),
        $notify: {success() {}, warning(message) { instance.warnings.push(message); }},
        $handleError() {},
        warnings: [],
        ...overrides
    };
    for (const [name, method] of Object.entries(component.methods)) instance[name] = method.bind(instance);
    for (const [name, getter] of Object.entries(component.computed)) Object.defineProperty(instance, name, {get: getter.bind(instance)});
    return instance;
}

const files = {
    scanned: true,
    checked_human: '2 hours',
    core: {version: '6.9.4', checked: true, files: 4, modified: 1, new: 2, deleted: 1, removable: 1, fixable: 3, truncated: 0, reinstallable: true, blocked: ''},
    extensions: [
        {type: 'plugin', key: 'beta/beta.php', name: 'Beta', version: '2.0-rc', files: 0, modified: 0, new: 0, deleted: 0, suspicious: true, reason_label: 'Version not on WordPress.org', reinstallable: true, blocked: ''},
        {type: 'plugin', key: 'demo/demo.php', name: 'Demo', version: '1.0.0', files: 3, modified: 2, new: 1, deleted: 0, suspicious: false, reinstallable: true, blocked: ''},
        {type: 'plugin', key: 'hello.php', name: 'Hello', version: '1.7', files: 1, modified: 1, new: 0, deleted: 0, suspicious: false, reinstallable: false, blocked: 'A single-file plugin.'}
    ],
    unverifiable: [{key: 'wp-config', label: 'wp-config.php', detail: '', modified: '3 days ago'}],
    quarantine: {files: 2, path: '/wp-content/uploads/fluent-auth-quarantine'}
};

test('puts the files first, because a backdoor undoes everything after it', () => {
    const instance = screen();
    assert.deepEqual(Array.from(instance.steps, step => step.key), ['files', 'admins', 'passwords']);
});

test('the file step says what is known: nothing yet, all clean, or what differs', () => {
    const instance = screen();
    assert.match(instance.filesStepBody, /Nothing has been compared/);
    assert.equal(instance.hasFileFindings, false);

    instance.files = {...files, core: {...files.core, files: 0}, extensions: []};
    assert.match(instance.filesStepBody, /Checked 2 hours ago: every core file/);
    assert.equal(instance.hasFileFindings, false);

    instance.files = files;
    assert.match(instance.filesStepBody, /Checked 2 hours ago\. Each reinstall/);
    assert.equal(instance.hasFileFindings, true);
    assert.equal(instance.steps[0].warning, true);
});

test('summarises counts by status and leaves out the zeros', () => {
    const instance = screen();
    instance.files = files;
    assert.equal(instance.coreStatusLine, '1 file changed · 2 files not in the release · 1 file missing');
    assert.equal(instance.rowStatusLine(files.extensions[1]), '2 files changed · 1 file not in the release');
    assert.equal(instance.rowStatusLine(files.extensions[0]), 'Version not on WordPress.org');
    assert.equal(instance.rowActionLabel(files.extensions[0]), 'Replace with the WordPress.org release');
    assert.equal(instance.rowActionLabel(files.extensions[1]), 'Reinstall');
});

test('only offers "reinstall all" for the rows that can be', () => {
    const instance = screen();
    instance.files = files;
    assert.deepEqual(instance.reinstallableRows.map(row => row.name), ['Beta', 'Demo']);
});

test('says where quarantined files went, and that they are harmless there', () => {
    const instance = screen();
    assert.equal(instance.quarantineNote, '');
    instance.files = files;
    assert.equal(instance.quarantineNote, '2 files are in quarantine at /wp-content/uploads/fluent-auth-quarantine. They cannot run from there. Delete the folder once you are sure you do not need them.');
    instance.files = {...files, quarantine: {files: 1, path: '/q'}};
    assert.match(instance.quarantineNote, /^1 file is in quarantine at \/q\./);
});

test('takes the server\'s picture after a reinstall and warns about what could not be moved', () => {
    const instance = screen();
    instance.files = files;
    instance.applyReinstall({files: {...files, extensions: []}, failed: ['wp-includes/x.php']});
    assert.deepEqual(instance.extensionRows, []);
    assert.equal(instance.warnings.length, 1);
    assert.match(instance.warnings[0], /wp-includes\/x\.php could not be moved/);
});

test('nothing on the page can be pressed while a reinstall is in flight', () => {
    const instance = screen();
    instance.files = files;
    assert.equal(instance.busy, false);
    instance.reinstalling = 'core';
    assert.equal(instance.busy, true);
    instance.reinstalling = '';
    instance.reinstallingAll = true;
    assert.equal(instance.busy, true);
});
