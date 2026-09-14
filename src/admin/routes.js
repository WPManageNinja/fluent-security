import Dashboard from './Components/Dashboard/index.vue';
import Logs from './Components/Logs.vue';

import SettingsLayout from './Components/Settings/SettingsLayout.vue';
import GeneralSettings from './Components/Settings/Pages/General.vue';
import EnrolledUsers from './Components/TwoFa/EnrolledUsers.vue';
import IpRulesSettings from './Components/Settings/Pages/IpRules.vue';

import AuthShortcodes from './Components/AuthShortcodes.vue';
import LoginRedirects from './Components/Redirects/LoginRedirects.vue';
import SocialAuthSettings from './Components/SocialAuthSettings.vue';
import CustomWpEmails from './Components/CustomWpEmails/AllEmails.vue';
import EditWpEmail from './Components/CustomWpEmails/EditWpEmail.vue';
import TemplateSettings from './Components/CustomWpEmails/TemplateSettings.vue';
import SecurityFindings from './Components/Security/Findings.vue';
import SecurityRecovery from './Components/Security/Recovery.vue';
import SecurityScans from './Components/SecurityScan/index.vue';
import RegisterPromt from './Components/SecurityScan/RegisterPromt.vue';
import AuthCustomizer from './Components/AuthCustomizer/AuthCustomizer.vue';
import ServerMode from './Components/ServerMode/ServerMode.vue';
import OnboardingWizard from './Components/Onboarding/Wizard.vue';

/*
 * Everything configurable is a child of /settings, so the sidebar is the one place to
 * look for a setting. The top bar keeps only the places you go to look at something.
 */
const settingsChildren = [
    {
        path: '',
        name: 'settings_general',
        component: GeneralSettings,
        meta: {title: 'Settings'}
    },
    {
        path: 'two-factor-enrollment',
        name: 'settings_two_fa_enrollment',
        component: EnrolledUsers,
        meta: {title: 'Two-Factor Enrollment'}
    },
    {
        path: 'ip-rules',
        name: 'settings_ip_rules',
        component: IpRulesSettings,
        meta: {title: 'IP Access Rules'}
    },
    {
        path: 'social-login',
        name: 'settings_social_login',
        component: SocialAuthSettings,
        meta: {title: 'Social Login'}
    },
    {
        path: 'auth-forms',
        name: 'settings_auth_forms',
        component: AuthShortcodes,
        meta: {title: 'Login/Signup Forms'}
    },
    // The designer used to live here. Kept so an existing bookmark still lands on it.
    {
        path: 'login-page-design',
        redirect: {name: 'settings_auth_customizer'}
    },
    {
        path: 'redirects',
        name: 'settings_redirects',
        component: LoginRedirects,
        meta: {title: 'Login Redirects'}
    },
    {
        path: 'emails',
        name: 'settings_emails',
        component: CustomWpEmails,
        meta: {title: 'System Emails'}
    },
    {
        path: 'emails/template',
        name: 'settings_email_template',
        component: TemplateSettings,
        meta: {title: 'Email Template Design'}
    },
    {
        path: 'emails/:email_id/edit',
        name: 'settings_edit_email',
        component: EditWpEmail,
        props: true,
        meta: {title: 'Edit Email'}
    },
    {
        path: 'remote-auth',
        name: 'settings_server_mode',
        component: ServerMode,
        meta: {title: 'Remote Auth'}
    }
];

export var routes = [
    /*
     * The first run. Outside the app shell rather than inside it - like the login page
     * designer, it covers the whole screen and draws its own header, and for the same
     * reason: a wizard shown under the app's own navigation is a wizard offering to be
     * abandoned by every link in the bar before the first question is answered.
     */
    {
        path: '/onboarding',
        name: 'onboarding',
        component: OnboardingWizard,
        meta: {
            active: 'onboarding',
            title: 'Setup',
            bare: true
        }
    },
    {
        path: '/',
        name: 'dashboard',
        component: Dashboard,
        meta: {
            active: 'dashboard',
            title: 'Dashboard'
        }
    },
    {
        path: '/logs',
        name: 'logs',
        component: Logs,
        meta: {
            active: 'logs',
            title: 'Activity Log'
        }
    },
    /*
     * Security is one destination with three views of the same subject: what needs doing,
     * what is being watched, and what to do if the worst has happened. They share `active`,
     * which is what puts them in one section bar under a single Security tab - see
     * Bits/subNav.js, which is also where the labels live.
     *
     * The names and paths are all older than the labels and none of them match: Monitoring
     * is still `security_scans` at `/security-scans`, and Been Hacked? is still
     * `security_recovery` at `/security/recovery`. The names are what findings point at (see
     * IntegrityCheck and the rest of app/Services/Checks) and the paths are what a year of
     * bookmarks point at; neither is worth breaking to make a route agree with a menu.
     */
    {
        path: '/security',
        name: 'security_findings',
        component: SecurityFindings,
        meta: {
            active: 'security',
            title: 'Findings'
        }
    },
    {
        path: '/security/recovery',
        name: 'security_recovery',
        component: SecurityRecovery,
        meta: {
            active: 'security',
            title: 'Been Hacked?'
        }
    },
    {
        path: '/security-scans',
        name: 'security_scans',
        component: SecurityScans,
        meta: {
            active: 'security',
            title: 'Monitoring'
        }
    },
    {
        path: '/security-scans/register',
        name: 'security_scan_register',
        component: RegisterPromt,
        meta: {
            active: 'security',
            title: 'Monitoring'
        }
    },
    /*
     * The login page designer covers the whole screen and draws its own header, so it
     * sits outside the settings shell rather than inside it. That is not only tidier:
     * the settings pane is pinned, which makes it a stacking context, and an editor
     * nested inside one cannot lift itself above wp-admin's menu however high its
     * z-index goes. Its own Back button returns to the forms screen.
     */
    {
        path: '/login-page-design',
        name: 'settings_auth_customizer',
        component: AuthCustomizer,
        meta: {
            active: 'settings',
            title: 'Login Page Design'
        }
    },
    {
        path: '/settings',
        component: SettingsLayout,
        children: settingsChildren.map(route => ({
            ...route,
            meta: {...route.meta, active: 'settings'}
        }))
    }
];
