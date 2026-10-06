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


function stage(overrides = {}) {
    const file = path.join(__dirname, '../../src/admin/Components/Onboarding/_Stage.vue');
    const {descriptor} = parse(fs.readFileSync(file, 'utf8'));
    const source = descriptor.script.content;
    const script = source.replace(/^import .*;\n/gm, '').replace('export default', 'module.exports =');
    const context = Object.assign({module: {exports: {}}}, importedNames(source));
    vm.runInNewContext(script, context);
    const component = context.module.exports;
    const instance = {
        $t: text => text,
        appVars: {site_url: 'https://example.test/'},
        step: {preview: 'two_factor'},
        answer: {},
        connection: {},
        authSettings: null,
        siteName: '',
        adminEmail: '',
        userRoles: []
    };
    Object.assign(instance, component.data.call(instance), overrides);
    for (const [name, getter] of Object.entries(component.computed || {})) Object.defineProperty(instance, name, {get: getter.bind(instance)});
    return instance;
}

test('draws the stock WordPress page until the customizer is switched on', () => {
    assert.equal(stage().previewComponent, 'WpLoginPreview');
    assert.equal(stage({authSettings: {status: 'no', login: {form: {title: 'Custom'}}}}).previewComponent, 'WpLoginPreview');
    assert.equal(stage({authSettings: {status: 'yes', login: {form: {title: 'Custom'}}}}).previewComponent, 'AuthFormPreview');
});

test('the frame shows the registration address for signup previews', () => {
    assert.equal(stage().previewUrl, 'https://example.test/wp-login.php');
    assert.equal(stage({step: {preview: 'signup'}}).previewUrl, 'https://example.test/wp-login.php?action=register');
});
