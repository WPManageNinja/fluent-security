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
    ->get('auth-logs', ['\FluentAuth\App\Http\Controllers\LogsController', 'getLogs'], $permissions)
    ->get('quick-stats', ['\FluentAuth\App\Http\Controllers\LogsController', 'quickStats'], $permissions)
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
    ->post('security-scan-settings/scan/toggle-ignore', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'toggleIgnore'], $permissions)
    ->get('security-scan-settings/scan/view-file', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'viewFileDiff'], $permissions)
    ->post('security-scan-settings/scan/update-schedule-scan', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'updateScheduleScan'], $permissions)
    ->post('security-scan-settings/scan/reset-api', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'resetApi'], $permissions)
    ->post('security-scan-settings/scan/reset-ignores', ['\FluentAuth\App\Http\Controllers\SecurityScanController', 'resetIgnores'], $permissions)
    ->get('auth-customizer', ['\FluentAuth\App\Http\Controllers\SettingsController', 'getAuthCustomizerSetting'], $permissions)
    ->post('auth-customizer', ['\FluentAuth\App\Http\Controllers\SettingsController', 'saveAuthCustomizerSetting'], $permissions)
    ->post('upload-image', ['\FluentAuth\App\Http\Controllers\SettingsController', 'uploadImage'], $permissions)
    ->post('child-sites',['\FluentAuth\App\Http\Controllers\SettingsController', 'saveChildSite'], $permissions)
    ->get('child-sites',['\FluentAuth\App\Http\Controllers\SettingsController', 'getChildSites'], $permissions)
    ->post('child-sites/validate-token', ['\FluentAuth\App\Http\Controllers\SettingsController', 'validateChildSiteToken'], 'fluent_auth_public_route_permission');

