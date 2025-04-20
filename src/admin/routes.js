import Dashboard from './Components/Dashboard.vue';
import Logs from './Components/Logs.vue';
import Settings from './Components/Setttings.vue';
import SocialAuthSettings from './Components/SocialAuthSettings.vue';
import AuthShortcodes from './Components/AuthShortcodes.vue';
import LoginRedirects from './Components/LoginRedirects.vue';

import CustomWpEmails from './Components/CustomWpEmails/AllEmails.vue';
import EditWpEmail from './Components/CustomWpEmails/EditWpEmail.vue';
import TemplateSettings from "./Components/CustomWpEmails/TemplateSettings.vue";
import SecurityScans from "./Components/SecurityScan/index.vue";
import RegisterPromt from "./Components/SecurityScan/RegisterPromt.vue";
import AuthCustomizer from "./Components/AuthCustomizer/AuthCustomizer.vue";

export var routes = [
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
            title: 'Auth Logs'
        }
    },
    {
        path: '/settings',
        name: 'settings',
        component: Settings,
        meta: {
            active: 'settings',
            title: 'Settings'
        }
    },
    {
        path: '/social-login-settings',
        name: 'social_auth_settings',
        component: SocialAuthSettings,
        meta: {
            active: 'social_auth_settings',
            title: 'Social Login Settings'
        }
    },
    {
        path: '/auth-shortcodes',
        name: 'auth_shortcodes',
        component: AuthShortcodes,
        meta: {
            active: 'auth_shortcodes',
            title: 'Auth Shortcodes'
        }
    },
    {
        path: '/login-redirects',
        name: 'login_redirects',
        component: LoginRedirects,
        meta: {
            active: 'login_redirects',
            title: 'Login Redirects'
        }
    },
    {
        path: '/custom-wp-emails',
        name: 'custom_wp_emails',
        component: CustomWpEmails,
        meta: {
            active: 'custom_wp_emails',
            title: 'System Emails Customizations'
        }
    },
    {
        path: '/template-settings',
        name: 'template_settings',
        component: TemplateSettings,
        meta: {
            active: 'custom_wp_emails',
            title: 'Template Settings'
        }
    },
    {
        path: '/custom-wp-emails/:email_id/edit',
        name: 'edit_wp_email',
        component: EditWpEmail,
        props: true,
        meta: {
            active: 'custom_wp_emails',
            title: 'Edit Email'
        }
    },
    {
        path: '/security-scans',
        name: 'security_scans',
        component: SecurityScans,
        meta: {
            active: 'security_scans',
            title: 'Security Scans'
        }
    },
    {
        path: '/security-scans/register',
        name: 'security_scan_register',
        component: RegisterPromt,
        meta: {
            active: 'security_scans',
            title: 'Security Scans'
        }
    },
    {
        path: '/auth-customizer',
        name:'auth_customizer',
        component: AuthCustomizer,
        meta: {
            active: 'auth_customizer',
            title: 'Auth Customizer'
        }
    }
];
