<?php
defined('ABSPATH') || exit;

$router = new \FluentAuth\App\Services\Router('fluent-auth');

function fluent_auth_public_route_permission($request)
{
    return true;
}

$appPermission = \FluentAuth\App\Helpers\Helper::getAppPermission();

if(!$appPermission) {
    $appPermission = 'manage_options';
}

$permissions = [$appPermission];

$router->get('settings', ['\FluentAuth\App\Http\Controllers\SettingsController', 'getSettings'], $permissions)
    ->post('settings', ['\FluentAuth\App\Http\Controllers\SettingsController', 'updateSettings'], $permissions)
    /*
     * The setup wizard. Answers name steps rather than settings and are applied in a
     * single write at the end - see the Onboarding service, which is where every rule
     * about what an answer may mean actually lives.
     */
    ->get('onboarding', ['\FluentAuth\App\Http\Controllers\OnboardingController', 'getOnboarding'], $permissions)
    ->post('onboarding/complete', ['\FluentAuth\App\Http\Controllers\OnboardingController', 'complete'], $permissions)
    ->post('onboarding/skip', ['\FluentAuth\App\Http\Controllers\OnboardingController', 'skip'], $permissions)
    /*
     * The mailing list signup, asked on the wizard's last screen and again from the
     * dashboard aside. Two endpoints because there are two answers worth recording - see
     * the Optin service, where a "not now" is a dated thing rather than a permanent one.
     */
    ->post('optin/subscribe', ['\FluentAuth\App\Http\Controllers\OptinController', 'subscribe'], $permissions)
    ->post('optin/dismiss', ['\FluentAuth\App\Http\Controllers\OptinController', 'dismiss'], $permissions)
    ->get('two-fa/users', ['\FluentAuth\App\Http\Controllers\TwoFaController', 'getUsers'], $permissions)
    ->post('two-fa/users/{id}/reset', ['\FluentAuth\App\Http\Controllers\TwoFaController', 'resetUser'], $permissions)
    /*
     * Encryption of the authenticator secrets. Two calls to switch on rather than one,
     * because the key lives in wp-config.php and this request cannot see a line added to
     * it - see TwoFaEncryptionController.
     */
    ->get('two-fa/encryption', ['\FluentAuth\App\Http\Controllers\TwoFaEncryptionController', 'getStatus'], $permissions)
    ->post('two-fa/encryption/write-config', ['\FluentAuth\App\Http\Controllers\TwoFaEncryptionController', 'writeConfig'], $permissions)
    ->post('two-fa/encryption/enable', ['\FluentAuth\App\Http\Controllers\TwoFaEncryptionController', 'enable'], $permissions)
    ->post('two-fa/encryption/disable', ['\FluentAuth\App\Http\Controllers\TwoFaEncryptionController', 'disable'], $permissions)
    ->post('two-fa/encryption/rekey', ['\FluentAuth\App\Http\Controllers\TwoFaEncryptionController', 'rekey'], $permissions)
    ->get('auth-logs', ['\FluentAuth\App\Http\Controllers\LogsController', 'getLogs'], $permissions)
    ->get('dashboard', ['\FluentAuth\App\Http\Controllers\DashboardController', 'getDashboard'], $permissions)
    /*
     * Superseded, and unreachable from this plugin's own screens: nothing calls it. The
     * checklist moved to `security-findings/fix` below, which names a check *and* a finding -
     * one check can raise several, and a file finding identifies itself by a path, which does
     * not survive a route pattern. The service underneath is still very much alive; it is
     * reached through SettingsCheck::fix() on the newer route.
     *
     * Kept because it is a public endpoint on a distributed plugin and something outside this
     * repository may post to it. It is not dead logic, only a second door to the same room.
     */
    ->post('security-checks/{key}/apply', ['\FluentAuth\App\Http\Controllers\DashboardController', 'applySecurityCheck'], $permissions)
    /*
     * The security screen. Three endpoints for every check the plugin has or will have -
     * see SecurityFindingsController. The check and finding are named in the body rather
     * than the path: a finding identifies itself with whatever its check finds meaningful,
     * which for a file check is a path, and a path does not survive a route pattern.
     */
    ->get('security-findings', ['\FluentAuth\App\Http\Controllers\SecurityFindingsController', 'getFindings'], $permissions)
    ->post('security-findings/fix', ['\FluentAuth\App\Http\Controllers\SecurityFindingsController', 'fix'], $permissions)
    ->post('security-findings/accept', ['\FluentAuth\App\Http\Controllers\SecurityFindingsController', 'accept'], $permissions)
    ->post('security-findings/unaccept', ['\FluentAuth\App\Http\Controllers\SecurityFindingsController', 'unaccept'], $permissions)
    ->get('baseline', ['\FluentAuth\App\Http\Controllers\BaselineController', 'getBaseline'], $permissions)
    ->post('baseline/snapshot', ['\FluentAuth\App\Http\Controllers\BaselineController', 'takeSnapshot'], $permissions)
    ->post('baseline/compare', ['\FluentAuth\App\Http\Controllers\BaselineController', 'compare'], $permissions)
    ->post('baseline/clear', ['\FluentAuth\App\Http\Controllers\BaselineController', 'clear'], $permissions)
    ->get('recovery', ['\FluentAuth\App\Http\Controllers\RecoveryController', 'getRecovery'], $permissions)
    ->post('recovery/secure-now', ['\FluentAuth\App\Http\Controllers\RecoveryController', 'secureNow'], $permissions)
    ->post('recovery/password-resets', ['\FluentAuth\App\Http\Controllers\RecoveryController', 'passwordResets'], $permissions)
    ->post('recovery/reinstall-core', ['\FluentAuth\App\Http\Controllers\RecoveryController', 'reinstallCore'], $permissions)
    ->post('recovery/reinstall-extension', ['\FluentAuth\App\Http\Controllers\RecoveryController', 'reinstallExtension'], $permissions)
    ->get('ip-rules', ['\FluentAuth\App\Http\Controllers\IpRulesController', 'getRules'], $permissions)
    ->post('ip-rules', ['\FluentAuth\App\Http\Controllers\IpRulesController', 'saveRules'], $permissions)
    ->post('ip-rules/add', ['\FluentAuth\App\Http\Controllers\IpRulesController', 'addIp'], $permissions)
    ->post('delete-log/{id}', ['\FluentAuth\App\Http\Controllers\LogsController', 'deleteLog'], $permissions)
    ->post('truncate-auth-logs', ['\FluentAuth\App\Http\Controllers\LogsController', 'deleteAllLog'], $permissions)
    ->get('social-auth-settings', ['\FluentAuth\App\Http\Controllers\SocialAuthApiController', 'getSettings'], $permissions)
    ->post('social-auth-settings', ['\FluentAuth\App\Http\Controllers\SocialAuthApiController', 'saveSettings'], $permissions)
    ->get('auth-forms-settings', ['\FluentAuth\App\Http\Controllers\SettingsController', 'getAuthFormSettings'], $permissions)
    ->post('auth-forms-settings', ['\FluentAuth\App\Http\Controllers\SettingsController', 'saveAuthFormSettings'], $permissions)
    ->get('wp-default-emails', ['\FluentAuth\App\Http\Controllers\SystemEmailsController', 'getEmails'], $permissions)
    ->get('wp-default-emails/find-email', ['\FluentAuth\App\Http\Controllers\SystemEmailsController', 'findEmail'], $permissions)
    ->post('wp-default-emails/preview', ['\FluentAuth\App\Http\Controllers\SystemEmailsController', 'previewEmail'], $permissions)
    ->get('wp-default-emails/template-settings', ['\FluentAuth\App\Http\Controllers\SystemEmailsController', 'getTemplateSettings'], $permissions)
    ->post('wp-default-emails/save-template-settings', ['\FluentAuth\App\Http\Controllers\SystemEmailsController', 'saveTemplateSettings'], $permissions)
    ->post('wp-default-emails/save-email-settings', ['\FluentAuth\App\Http\Controllers\SystemEmailsController', 'saveEmailSettings'], $permissions)
    ->get('security-scan-settings', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'getSettings'], $permissions)
    ->post('security-scan-settings/register', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'registerSite'], $permissions)
    ->get('security-scan-settings/scan', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'scanSite'], $permissions)
    ->get('security-scan-settings/scan/targets', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'getScanTargets'], $permissions)
    ->post('security-scan-settings/scan/extension', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'scanExtension'], $permissions)
    ->post('security-scan-settings/scan/toggle-ignore', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'toggleIgnore'], $permissions)
    ->get('security-scan-settings/mu-plugins', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'getMuPlugins'], $permissions)
    ->post('security-scan-settings/mu-plugins/baseline', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'baselineMuPlugins'], $permissions)
    ->get('security-scan-settings/scan/view-file', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'viewFileDiff'], $permissions)
    ->post('security-scan-settings/scan/restore-file', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'restoreFile'], $permissions)
    ->post('security-scan-settings/scan/delete-file', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'deleteFile'], $permissions)
    ->post('security-scan-settings/scan/update-schedule-scan', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'updateScheduleScan'], $permissions)
    ->post('security-scan-settings/scan/reset-api', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'resetApi'], $permissions)
    ->post('security-scan-settings/scan/resume-reporting', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'resumeReporting'], $permissions)
    ->post('security-scan-settings/scan/reset-ignores', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'resetIgnores'], $permissions)
    ->get('auth-customizer', ['\FluentAuth\App\Http\Controllers\SettingsController', 'getAuthCustomizerSetting'], $permissions)
    ->post('auth-customizer', ['\FluentAuth\App\Http\Controllers\SettingsController', 'saveAuthCustomizerSetting'], $permissions)
    ->post('upload-image', ['\FluentAuth\App\Http\Controllers\SettingsController', 'uploadImage'], $permissions)
    ->post('child-sites',['\FluentAuth\App\Http\Controllers\SettingsController', 'saveChildSite'], $permissions)
    ->get('child-sites',['\FluentAuth\App\Http\Controllers\SettingsController', 'getChildSites'], $permissions)
    ->post('child-sites/validate-token', ['\FluentAuth\App\Http\Controllers\SettingsController', 'validateChildSiteToken'], 'fluent_auth_public_route_permission')
    ->post('install-plugin', ['\FluentAuth\App\Http\Controllers\SettingsController', 'installPlugin'], $permissions);

