// Run with: node --test tests/Frontend/self-lockout.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');

/*
 * Plain module, no imports - so it loads by rewriting its exports rather than by
 * standing up a bundler. Same trick the other tests in here use on a .vue file.
 */
const source = fs.readFileSync(path.join(root, 'src/admin/Bits/selfLockout.js'), 'utf8')
    .replace(/^export function (\w+)/gm, 'module.exports.$1 = function $1');

const context = {module: {exports: {}}};
context.module.exports = {};
vm.runInNewContext(source, context);
const {selfWillOweFactor} = context.module.exports;

const appVars = (me = {}, extra = {}) => ({
    passkey_supported: true,
    me: {roles: ['administrator'], has_device_factor: false, two_fa_bypassed: false, ...me},
    ...extra
});

const settings = (overrides = {}) => ({
    totp_2fa: 'no',
    totp_2fa_roles: [],
    passkey_2fa: 'no',
    passkey_2fa_roles: [],
    email2fa: 'no',
    email2fa_roles: [],
    totp_required_roles: [],
    two_fa_required_level: 'device',
    ...overrides
});

test('nothing required means nothing to warn about', () => {
    assert.equal(selfWillOweFactor(settings({totp_2fa: 'yes'}), appVars()), false);
});

test('requiring your own role with a method on is the case this exists for', () => {
    const result = selfWillOweFactor(
        settings({totp_2fa: 'yes', totp_required_roles: ['administrator']}),
        appVars()
    );

    assert.equal(result, true);
});

test('requiring somebody else\'s role is not your problem', () => {
    const result = selfWillOweFactor(
        settings({totp_2fa: 'yes', totp_required_roles: ['editor']}),
        appVars()
    );

    assert.equal(result, false);
});

/* A requirement over no switched-on method does not stand - see DeviceRequirement. */
test('a requirement over no method at all warns about nothing', () => {
    const result = selfWillOweFactor(
        settings({totp_required_roles: ['administrator']}),
        appVars()
    );

    assert.equal(result, false);
});

test('an administrator who already holds a factor is not warned', () => {
    const result = selfWillOweFactor(
        settings({totp_2fa: 'yes', totp_required_roles: ['administrator']}),
        appVars({has_device_factor: true})
    );

    assert.equal(result, false);
});

/*
 * The wp-config.php escape hatch. Without this the dialog fires on every save a bypassed
 * administrator makes, on screens that have nothing to do with 2FA.
 */
test('a wp-config bypass means nothing happens to them', () => {
    const result = selfWillOweFactor(
        settings({totp_2fa: 'yes', totp_required_roles: ['administrator']}),
        appVars({two_fa_bypassed: true})
    );

    assert.equal(result, false);
});

/* Passkeys cannot be created over plain http, so the switch alone is not the answer. */
test('a passkey switch on an http site is not a method being on', () => {
    const base = settings({passkey_2fa: 'yes', totp_required_roles: ['administrator']});

    assert.equal(selfWillOweFactor(base, appVars({}, {passkey_supported: false})), false);
    assert.equal(selfWillOweFactor(base, appVars()), true);
});

test('an emailed code cannot meet a device floor', () => {
    const result = selfWillOweFactor(
        settings({
            email2fa: 'yes',
            email2fa_roles: ['administrator'],
            totp_required_roles: ['administrator']
        }),
        appVars()
    );

    assert.equal(result, false, 'Nothing that meets the floor is switched on, so it does not stand.');
});

test('at the relaxed floor an emailed code they already get changes nothing', () => {
    const result = selfWillOweFactor(
        settings({
            email2fa: 'yes',
            email2fa_roles: ['administrator'],
            totp_required_roles: ['administrator'],
            two_fa_required_level: 'any'
        }),
        appVars()
    );

    assert.equal(result, false);
});

test('at the relaxed floor an emailed code for somebody else does not help them', () => {
    const result = selfWillOweFactor(
        settings({
            email2fa: 'yes',
            email2fa_roles: ['editor'],
            totp_required_roles: ['administrator'],
            two_fa_required_level: 'any'
        }),
        appVars()
    );

    assert.equal(result, true);
});

test('it survives being asked before anything has loaded', () => {
    assert.equal(selfWillOweFactor(null, appVars()), false);
    assert.equal(selfWillOweFactor(settings(), null), false);
    assert.equal(selfWillOweFactor(settings(), {}), false);
});
