const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {parse} = require('@vue/compiler-sfc');

function stage(overrides = {}) {
    const file = path.join(__dirname, '../../src/admin/Components/Onboarding/_Stage.vue');
    const {descriptor} = parse(fs.readFileSync(file, 'utf8'));
    const script = descriptor.script.content.replace(/^import .*;\n/gm, '').replace('export default', 'module.exports =');
    const context = {module: {exports: {}}, AuthFormPreview: {}, WpLoginPreview: {}, ConnectionPreview: {}, EmailPreview: {}};
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
