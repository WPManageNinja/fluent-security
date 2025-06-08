---
title: Configure Login with Facebook
slug: facebook-auth-connection
tagline: Add Login or Register with Facebook in minutes
sidebar: false
prev: true
next: true
editLink: true
pageClass: docs-facebook
menu_order: 11
---

Configuring Facebook Login Integration

Setting up Facebook Login for your application requires creating and configuring a Facebook app through the Facebook Developer Console. This guide walks you through the complete process.

# Prerequisites
- Before starting, ensure you have:
  - A Facebook account
  - Access to the Facebook Developer Console
  - Your application's domain and callback URLs are ready


## Create a Facebook Application

- Access Facebook Developers Dashboard
  - Navigate to the [Facebook Developers](https://developers.facebook.com/) Dashboard and log in with your Facebook account.
- Create New App
  - Click the "Create App" button
  - Enter your application name and contact email
  - Select "Other" as your use case 
  - Choose "Consumer" as the app type
  - Click "Create App" to proceed

## Configure Basic App Settings 

- Navigate to Basic Settings
  - In the left sidebar, go to Settings → Basic
  - Complete the following required fields:
- Required Configuration
  - App Domains: Add your website domain (without protocol)
  - Privacy Policy URL: Provide a valid privacy policy URL (required for app approval)
  - User Data Deletion URL: Provide a URL for data deletion requests (required)
  - App Icon: Upload a 1024×1024px icon (recommended)
- Save Changes
  - Click "Save Changes" to apply your basic settings.

## Configure Facebook Login Product

- Access Facebook Login Settings
  - In the left sidebar, navigate to Facebook Login → Settings
- Configure OAuth Settings
  - Add the following configurations:
    - Valid OAuth Redirect URIs: Add your application's callback URLs
    - Client OAuth Login: Enable this option
    - Web OAuth Login: Enable this option
- Save Configuration
  - Click "Save Changes" to apply the Facebook Login settings.

## Add Website URL (Optional)

- For web applications, you can specify your website URL:
  - Go to Facebook Login → Quickstart
  - Select "Web" platform
  - Enter your website URL
  - No additional steps are required in the quickstart flow

## Configure App Permissions 

- Request Advanced Access
  - Navigate to App Review → Permissions and Features
  - Find "email" and "public_profile" (optional) permissions
  - Switch both from "Standard Access" to "Advanced Access."
This step is crucial for accessing user email addresses and basic profile information.

## Published App 

- Publish the app to Development mode to Live Mode

## Integrate with FluentAuth 

- Obtain App Credentials (From your Facebook app's Settings → Basic page, copy: )
  - App ID (Client ID)
  - App Secret (Client Secret)
- Configure Your Application 
  - Go to wp-config.php (Recommended)
  - Add the following constants to your wp-config.php file:
```php
define(''FLUENT_AUTH_FACEBOOK_CLIENT_ID'', '******');
define(''FLUENT_AUTH_FACEBOOK_CLIENT_SECRET'', '******');
```

It is recommended to use the wp-config instruction to save the credentials in wp-config.php file.

Once you set the credential to FluentAuth, Click save button in FluentAuth. 

Now, your users can Signup or Login with Facebook profile.
