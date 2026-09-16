# Recorded authenticator fixtures

Each `.json` file here is a registration and an assertion captured from a real
authenticator, replayed by `WebAuthnRecordedFixtureTest` through the same verification
code a login uses.

They exist because the synthetic fixtures cannot catch a misreading of the
specification: those responses are built by this codebase, so an encoder and a decoder
that are wrong in the same way agree with each other. A recording from a device does
not.

## Capturing one

1. Copy `bin/passkey-fixture-capture.php` into `wp-content/mu-plugins/` on an **https**
   development site.
2. Visit **Tools → Passkey capture**.
3. Name the authenticator and browser, press **Register**, then **Authenticate** with
   the same device.
4. Save the JSON here as, for example, `macos-touchid-safari.json`.
5. Delete the mu-plugin.

## What is worth recording

| Authenticator | Why |
| --- | --- |
| macOS Touch ID | Platform authenticator, ES256, device bound |
| Bitwarden | Password manager, synced credential - reports a zero counter forever |
| Windows Hello | The one that may hand back RS256 rather than ES256 |
| A hardware key | Roaming authenticator, real advancing signature counter |

The first two cover the paths most users take. The last two cover the paths most likely
to be got wrong, since neither is exercised by anything else in the suite.
