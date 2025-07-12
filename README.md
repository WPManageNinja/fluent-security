## Fluent Auth
Super Simple Auth Security Plugin for WordPress

**What It Does**

- Log Login Attempts
- Limit Login Attempts (like max 5 times in 30 minutes)
- Enable/Disable xml-rpc requests
- Enable/Disable REST-API Remote Authentications
- View Detailed Audit Logs for Logins
- Magic Login via email
- **Conditional Login/Logout redirect** by user role or user permissions
- Extra Security Code verification for login
- Get email when high-level user role login
- Social Login/Signup with **Google** and **Github**
- Two-Factor verification Via Email for specific User roles

**Development**
- `npm install` 
- Then `npx mix`
- For development `npx mix watch`
- For Build `npx mix --production`

**Build for WP Org**
- `sh build.sh --loco --node-build`

**Running PHPStan**
- `composer install`
- `composer phpstan`

**Libraries Used**
- Vue3
- Element Plus
- Vue Router
