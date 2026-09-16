---
title: Running Your Plugin's Login on FluentAuth
slug: adopting-fluentauth
tagline: Hand your own auth screen to FluentAuth and get magic login, passkeys and 2FA for free
prev: true
next: true
editLink: true
pageClass: docs-other
menu_order: 7
---

If your plugin already renders a login screen of its own — a membership portal, a
community, a checkout — you can hand that screen to FluentAuth instead of reimplementing
what it already does. Adopting gives the screen magic login, the passkey button, social
login, the second factor challenge inline, the attempt limit and the audit log, with no
JavaScript of your own.

## Two calls

```php
use FluentAuth\App\Services\LoginBridge;

// 1. Wherever your plugin boots. Must run on every request, ajax included.
if (class_exists('\FluentAuth\App\Services\LoginBridge')) {
    LoginBridge::register('my-plugin', 'is_my_auth_screen');
}

// 2. On the screen itself, before you render the form.
LoginBridge::adopt([
    'host'          => 'my-plugin',
    'redirect_to'   => $currentUrl,
    'hidden_fields' => ['is_my_auth_screen' => 'yes'],
]);

echo do_shortcode('[fluent_auth_login]');
```

That is the whole integration. FluentCommunity's portal is about this long.

## Why registration is separate from adoption

`adopt()` only lasts for the request that calls it, and the form it renders posts back to
`admin-ajax.php` — a different PHP process, where nothing survives but what the browser
sent. `register()` is how FluentAuth recognises that second request as yours.

It is also the thing that confers trust. FluentAuth's front end forms sit behind a site
setting, and adoption is allowed to override it — so the override has to be something
only server-side code can ask for. A visitor cannot switch the forms back on at a site
whose owner turned them off, because they cannot call `register()`.

## register()

```php
LoginBridge::register($slug, $claim = null, $ajaxActions = []);
```

- **`$slug`** — your own identifier. Your text domain is a good choice.
- **`$claim`** — how FluentAuth tells whether a given request is yours:
  - a **string** names a request field that must be present (the usual case — put it in
    `hidden_fields` and it rides along on every post the form makes);
  - a **callable** is asked and returns a bool;
  - **`null`** claims every request, which only suits a plugin that owns login for the
    whole site.
- **`$ajaxActions`** — see *Keeping your own login endpoint* below.

FluentAuth also prints a signed marker inside every form it renders while adopted, and
that marker claims the request on its own. This is what makes forms you never touch —
the password reset form, for one — work without you adding a field to them.

## adopt()

```php
LoginBridge::adopt([
    'host'          => 'my-plugin',   // claims this request outright
    'redirect_to'   => $url,          // where a completed login lands
    'hidden_fields' => [],            // name => value, printed inside the form
]);
```

It enqueues the login assets, sets the redirect the forms carry, prints your hidden
fields and marks the request as yours. Call it before rendering; calling it twice is
harmless.

## What your handlers still see

Your hidden fields come back on every post, so the hooks you already have keep working:

```php
add_filter('fluent_auth/login_redirect_url', function ($url, $user) {
    if (empty($_REQUEST['is_my_auth_screen'])) {
        return $url;
    }

    return my_plugin_portal_url();
}, 10, 2);
```

## Keeping your own login endpoint

If you would rather keep your own `admin-ajax` login handler, you can adopt the second
factor alone. Name your action at registration and FluentAuth stops treating your
post as headless: instead of a `WP_Error` your handler would print as an error message,
the reply carries the challenge.

```php
LoginBridge::register('my-plugin', 'is_my_auth_screen', ['my_plugin_login']);
```

It goes on `register()` rather than `adopt()` because the action arrives on the post,
long after the screen that adopted was rendered — and that is a different request.

Your login reply then comes back as:

```json
{
  "load_2fa": "yes",
  "two_fa_form": "<form id=\"fls_2fa_form\">…</form>",
  "challenge_url": "https://example.com/wp-login.php?fls_2fa=verify&login_hash=…"
}
```

Mount it with the helper rather than assigning the html yourself — `innerHTML` never runs
a `<script>`, and the ceremonies live in FluentAuth's bundle for exactly that reason:

```js
if (response.load_2fa) {
    const helper = window.fluentAuthLogin;

    if (helper && helper.mountChallenge(response.two_fa_form, myContainer)) {
        return;
    }

    // FluentAuth's script is not on this page; its own challenge page is.
    window.location.href = response.challenge_url;
}
```

## Filters

| Filter | Use |
| --- | --- |
| `fluent_auth/auth_forms_enabled` | Final say over whether the front end forms render and their endpoints answer. |
| `fluent_auth/can_render_2fa_inline` | Whether an ajax login may be answered with a challenge form rather than a `WP_Error`. |
| `fluent_auth/login_form_args` | The args the login form is built from. |
| `fluent_auth/login_redirect_url` | Where a completed login lands. |
