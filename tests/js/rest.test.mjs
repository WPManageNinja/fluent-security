import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

// Exercise the ES module with the jQuery transport boundary replaced, without a build.
let options;
let failure;
const response = { findings: [{ id: 'existing', status: 'open' }], count: 1 };
globalThis.jQuery = () => ({ ajaxSuccess() {} });
globalThis.document = {};
globalThis.window = {
    fluentAuthAdmin: { rest: { url: 'https://example.test/wp-json/fluent-auth', nonce: 'test-nonce' } },
    jQuery: {
        ajax(config) {
            options = config;
            return {
                then(resolve) {
                    if (!failure) resolve(response);
                    return { fail(reject) { if (failure) reject(failure); } };
                }
            };
        }
    }
};
const source = readFileSync(new URL('../../src/admin/Bits/Rest.js', import.meta.url), 'utf8');
const { default: Rest } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
    for (const route of ['security-findings', 'security-findings?view=all']) {
        test(`${method}: user locale and JSON Accept with ${route}`, async () => {
            failure = undefined;
            const data = { settings: { roles: ['editor', 'subscriber'] }, search: '語言 & locale' };
            const result = await Rest[method](route, data);
            const url = new URL(options.url);
            assert.equal(url.searchParams.get('_locale'), 'user');
            assert.equal(url.pathname, '/wp-json/fluent-auth/security-findings');
            assert.equal(url.searchParams.get('view'), route.includes('?') ? 'all' : null);
            assert.equal(options.headers.Accept, 'application/json');
            assert.equal(options.headers['X-WP-Nonce'], 'test-nonce');
            assert.deepEqual(options.data.settings.roles, ['editor', 'subscriber']);
            assert.equal(options.data.search, '語言 & locale');
            assert.equal(typeof options.data.query_timestamp, 'number');
            assert.equal(options.contentType, undefined, 'jQuery must keep form encoding');
            assert.strictEqual(result, response, 'response identity and JSON body are unchanged');
            const override = ['put', 'patch', 'delete'].includes(method);
            assert.equal(options.type, override ? 'POST' : method.toUpperCase());
            assert.equal(options.headers['X-HTTP-Method-Override'], override ? method.toUpperCase() : undefined);
        });
    }
}

test('plain-permalink REST base retains rest_route and negotiates user locale', async () => {
    const base = window.fluentAuthAdmin.rest.url;
    try {
        window.fluentAuthAdmin.rest.url = 'https://example.test/?rest_route=/fluent-auth';
        await Rest.get('security-findings');
        const url = new URL(options.url);
        assert.equal(url.searchParams.get('rest_route'), '/fluent-auth/security-findings');
        assert.equal(url.searchParams.get('_locale'), 'user');
    } finally {
        window.fluentAuthAdmin.rest.url = base;
    }
});

test('REST errors still reject with the parsed responseJSON', async () => {
    failure = { responseJSON: { code: 'invalid_finding', message: 'Translated error', data: { status: 400 } } };
    try {
        await assert.rejects(Rest.post('security-findings/fix', { check: 'invalid' }), error => {
            assert.strictEqual(error, failure.responseJSON);
            return true;
        });
    } finally {
        failure = undefined;
    }
});
