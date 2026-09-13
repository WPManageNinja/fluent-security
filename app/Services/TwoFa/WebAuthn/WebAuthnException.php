<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * A ceremony that could not be completed.
 *
 * Thrown rather than returned so that no step of a verification checklist can be
 * skipped by a caller who forgot to check a return value. The message names the step
 * that failed and is meant for the site's own log, not for the browser: telling an
 * attacker which of the checks their forged assertion tripped tells them what to fix.
 * The two callers - PasskeyTwoFaMethod and the enrollment handler - both translate
 * these into one flat message.
 */
class WebAuthnException extends \Exception
{
}
