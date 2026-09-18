// Run with: node --test tests/Frontend/recovery.test.cjs
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
const {descriptor} = parse(fs.readFileSync(path.join(root, 'src/admin/Components/Security/Recovery.vue'), 'utf8'));
const source = descriptor.script.content;
const script = source.replace(/^import .*;\n/gm, '').replace('export default', 'module.exports =');
const context = Object.assign({module: {exports: {}}}, importedNames(source));
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

/*
 * Signing out is step one because it is instant and the rest of the page refers to it - the
 * password step's own body says "do step 1 first". Files come before the two account steps
 * for the original reason: a backdoor left in a file undoes everything done after it.
 */
test('orders the steps so nothing later is undone by something earlier', () => {
    const instance = screen();
    assert.deepEqual(Array.from(instance.steps, step => step.key), ['sessions', 'files', 'admins', 'passwords']);
});

test('the file step says what is known: nothing yet, all clean, or what differs', () => {
    const instance = screen();
    assert.match(instance.filesStepBody, /No scan has run yet/);
    assert.equal(instance.hasFileFindings, false);

    instance.files = {...files, core: {...files.core, files: 0}, extensions: []};
    assert.match(instance.filesStepBody, /Checked 2 hours ago\. Every WordPress file/);
    assert.equal(instance.hasFileFindings, false);

    instance.files = files;
    assert.match(instance.filesStepBody, /Checked 2 hours ago\. Each reinstall/);
    assert.equal(instance.hasFileFindings, true);
    // steps[1] is the file step - steps[0] signs everyone out.
    assert.equal(instance.steps[1].warning, true);
});

test('summarises counts by status and leaves out the zeros', () => {
    const instance = screen();
    instance.files = files;
    assert.equal(instance.coreStatusLine, '1 file changed · 2 unexpected files · 1 file missing');
    assert.equal(instance.rowStatusLine(files.extensions[1]), '2 files changed · 1 unexpected file');
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
    assert.equal(instance.quarantineNote, '2 files were moved to /wp-content/uploads/fluent-auth-quarantine, where they cannot run. Delete the folder once you are sure you do not need them.');
    instance.files = {...files, quarantine: {files: 1, path: '/q'}};
    assert.match(instance.quarantineNote, /^1 file was moved to \/q,/);
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
