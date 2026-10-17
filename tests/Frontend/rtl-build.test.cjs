const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {generateRtlStylesheets, stylesheets} = require('../../scripts/build-rtl');

test('declares an RTL output for every shipped stylesheet', () => {
    assert.deepEqual(stylesheets, [
        ['dist/admin/element-plus.css', 'dist/admin/element-plus-rtl.css'],
        ['dist/admin/app.css', 'dist/admin/app-rtl.css'],
        ['dist/public/login_helper.css', 'dist/public/login_helper-rtl.css'],
        ['dist/public/login_customizer.css', 'dist/public/login_customizer-rtl.css']
    ]);
});

test('generates a mirrored stylesheet from compiled CSS', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fluent-auth-rtl-'));
    const source = 'build/example.css';
    const output = 'build/example-rtl.css';

    context.after(() => fs.rmSync(root, {recursive: true, force: true}));
    fs.mkdirSync(path.join(root, 'build'));
    fs.writeFileSync(path.join(root, source), '.notice{left:10px;margin-right:4px;text-align:left}');

    generateRtlStylesheets(root, [[source, output]]);

    assert.equal(
        fs.readFileSync(path.join(root, output), 'utf8'),
        '.notice{right:10px;margin-left:4px;text-align:right}\n'
    );
});

test('mirrors native select background positioning', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fluent-auth-rtl-'));
    const source = 'build/example.css';
    const output = 'build/example-rtl.css';

    context.after(() => fs.rmSync(root, {recursive: true, force: true}));
    fs.mkdirSync(path.join(root, 'build'));
    fs.writeFileSync(path.join(root, source), '.range select{background-position:right 8px top 55%}');

    generateRtlStylesheets(root, [[source, output]]);

    assert.equal(
        fs.readFileSync(path.join(root, output), 'utf8'),
        '.range select{background-position:left 8px top 55%}\n'
    );
});

test('preserves existing manual RTL overrides', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fluent-auth-rtl-'));
    const source = 'build/example.css';
    const output = 'build/example-rtl.css';
    const css = '/*!rtl:begin:ignore*/.rtl .notice{right:auto;left:15px}/*!rtl:end:ignore*/';

    context.after(() => fs.rmSync(root, {recursive: true, force: true}));
    fs.mkdirSync(path.join(root, 'build'));
    fs.writeFileSync(path.join(root, source), css);

    generateRtlStylesheets(root, [[source, output]]);

    assert.equal(fs.readFileSync(path.join(root, output), 'utf8'), '.rtl .notice{right:auto;left:15px}\n');
});

test('preserves runtime-measured physical shell insets', (context) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fluent-auth-rtl-'));
    const source = 'build/example.css';
    const output = 'build/example-rtl.css';
    const css = '/*!rtl:begin:ignore*/.shell{left:var(--shell-left);right:var(--shell-right);padding-left:var(--content-left);padding-right:var(--content-right)}/*!rtl:end:ignore*/';

    context.after(() => fs.rmSync(root, {recursive: true, force: true}));
    fs.mkdirSync(path.join(root, 'build'));
    fs.writeFileSync(path.join(root, source), css);

    generateRtlStylesheets(root, [[source, output]]);

    assert.equal(
        fs.readFileSync(path.join(root, output), 'utf8'),
        '.shell{left:var(--shell-left);right:var(--shell-right);padding-left:var(--content-left);padding-right:var(--content-right)}\n'
    );
});
