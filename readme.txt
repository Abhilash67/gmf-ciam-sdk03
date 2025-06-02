# GMF-CIAM-SDK Documentation

A comprehensive authentication SDK for GMF applications supporting Auth0 and Okta identity providers with enhanced error handling and TypeScript support.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Authentication Methods](#authentication-methods)
- [Profile Management](#profile-management)
- [Password Management](#password-management)
- [Error Handling](#error-handling)
- [TypeScript Support](#typescript-support)
- [Examples](#examples)
- [API Reference](#api-reference)
- [Migration Guide](#migration-guide)
- [Troubleshooting](#troubleshooting)

## Installation

### NPM
```bash
npm install GMF-CIAM-sdk
```

### Yarn
```bash
yarn add GMF-CIAM-sdk
```

### CDN
```html
<script src="https://unpkg.com/GMF-CIAM-sdk@latest/dist/index.js"></script>
```

## Quick Start

### Basic Setup

```javascript
import GMFCIAMAuth from 'GMF-CIAM-sdk';

// Initialize Auth0 provider
const authProvider = await GMFCIAMAuth.createAuthProvider('auth0', {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-identifier',
  redirectUri: window.location.origin
});

// Set up error handling
authProvider.onError((error) => {
  console.error('Auth Error:', error.message);
  // Handle error in your UI
});

// Check authentication status
const isAuthenticated = await authProvider.isAuthenticated();

if (isAuthenticated) {
  const profile = await authProvider.getUserProfile();
  console.log('User:', profile);
} else {
  // Redirect to login
  await authProvider.login();
}
```

### Angular Integration

```typescript
import { Injectable } from '@angular/core';
import GMFCIAMAuth, { AuthProvider, AuthError } from 'GMF-CIAM-sdk';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private authProvider: AuthProvider | null = null;

  async initialize() {
    this.authProvider = await GMFCIAMAuth.createAuthProvider('auth0', {
      domain: 'your-domain.auth0.com',
      clientId: 'your-client-id',
      audience: 'your-api-identifier'
    });

    // Set up centralized error handling
    this.authProvider.onError((error: AuthError) => {
      this.handleAuthError(error);
    });
  }

  private handleAuthError(error: AuthError) {
    switch (error.code) {
      case 'INVALID_REFRESH_TOKEN':
        // Redirect to login
        break;
      case 'PASSWORD_TOO_SHORT':
        // Show validation message
        break;
      default:
        // Show generic error
    }
  }
}
```

## Configuration

### Auth0 Configuration

```javascript
const auth0Config = {
  domain: 'your-domain.auth0.com',           // Required
  clientId: 'your-client-id',                // Required
  audience: 'your-api-identifier',           // Required
  redirectUri: window.location.origin,      // Optional
  scope: 'openid profile email offline_access', // Optional
  responseType: 'code',                      // Optional
  cacheLocation: 'localstorage',            // Optional: 'localstorage' | 'sessionstorage'
  clientSecret: 'your-client-secret',       // Optional: For server-side operations
  managementApiAudience: 'https://your-domain.auth0.com/api/v2/' // Optional
};
```

### Okta Configuration

```javascript
const oktaConfig = {
  orgUrl: 'https://your-org.okta.com',      // Required
  clientId: 'your-client-id',               // Required
  redirectUri: window.location.origin,     // Optional
  scopes: ['openid', 'profile', 'email']   // Optional
};
```

### Environment-Specific Configuration

```javascript
// Development
const devConfig = {
  domain: 'dev-company.auth0.com',
  clientId: 'dev-client-id',
  audience: 'https://dev-api.company.com'
};

// Production
const prodConfig = {
  domain: 'company.auth0.com',
  clientId: 'prod-client-id',
  audience: 'https://api.company.com'
};

const config = process.env.NODE_ENV === 'production' ? prodConfig : devConfig;
```

## Authentication Methods

### Login

```javascript
// Basic login
await authProvider.login();

// Login with specific parameters (will redirect to Auth0)
try {
  await authProvider.login();
  // Redirect happens automatically
} catch (error) {
  console.error('Login failed:', error.message);
}
```

### Logout

```javascript
// Logout and redirect
authProvider.logout();

// Logout with error handling
try {
  authProvider.logout();
} catch (error) {
  console.error('Logout failed:', error.message);
  // Clear local state anyway
  localStorage.clear();
}
```

### Check Authentication Status

```javascript
// Simple check
const isAuth = await authProvider.isAuthenticated();

// Comprehensive check with validation
const authStatus = await authProvider.validateAuthState();
if (authStatus.valid) {
  console.log('User is authenticated');
} else {
  console.log('Authentication issue:', authStatus.reason);
}
```

### Token Management

```javascript
// Get access token
const token = await authProvider.getAccessToken();

// Refresh token
const success = await authProvider.refreshToken();
if (success) {
  console.log('Token refreshed successfully');
}

// Get detailed auth status
const status = authProvider.getAuthStatus();
console.log('Auth Status:', status);
```

## Profile Management

### Get User Profile

```javascript
// Get basic profile
const profile = await authProvider.getUserProfile();

// Force refresh profile
const freshProfile = await authProvider.getUserProfile(true);

// Get detailed profile (requires Management API)
const detailedProfile = await authProvider.getDetailedUserProfile();
```

### Update User Profile

```javascript
// Update profile fields
const updatedProfile = await authProvider.updateUserProfile({
  name: 'John Doe',
  nickname: 'johndoe',
  picture: 'https://example.com/avatar.jpg'
});

// Update with validation
try {
  await authProvider.updateUserProfile({
    name: '',  // This will trigger validation error
  });
} catch (error) {
  if (error.code === 'EMPTY_UPDATES') {
    console.log('Please provide at least one field to update');
  }
}
```

### Allowed Profile Fields

```javascript
const allowedFields = [
  'name', 'given_name', 'family_name', 'middle_name', 'nickname',
  'preferred_username', 'profile', 'picture', 'website', 'gender',
  'birthdate', 'zoneinfo', 'locale', 'phone_number', 'address',
  'user_metadata', 'app_metadata'
];
```

## Password Management

### Reset Password

```javascript
// Send password reset email
try {
  const message = await authProvider.resetPassword('user@example.com');
  console.log(message); // "Password reset email sent successfully"
} catch (error) {
  if (error.code === 'USER_NOT_FOUND') {
    console.log('No account found with this email');
  } else if (error.code === 'INVALID_EMAIL_FORMAT') {
    console.log('Please enter a valid email address');
  }
}
```

### Change Password

```javascript
// Change password for authenticated user
try {
  const result = await authProvider.changePassword('oldPassword', 'newPassword123');
  console.log(result); // "Password changed successfully"
} catch (error) {
  switch (error.code) {
    case 'INCORRECT_PASSWORD':
      console.log('Current password is incorrect');
      break;
    case 'PASSWORD_TOO_SHORT':
      console.log('New password must be at least 8 characters');
      break;
    case 'PASSWORD_UNCHANGED':
      console.log('New password must be different from current password');
      break;
  }
}
```

## Error Handling

### Centralized Error Handling

```javascript
// Set up global error handler
authProvider.onError((error) => {
  console.error(`${error.name}: ${error.message}`);
  
  // Handle different error types
  switch (error.name) {
    case 'AuthenticationError':
      handleAuthError(error);
      break;
    case 'ValidationError':
      handleValidationError(error);
      break;
    case 'NetworkError':
      handleNetworkError(error);
      break;
    case 'TokenError':
      handleTokenError(error);
      break;
  }
});

function handleAuthError(error) {
  switch (error.code) {
    case 'NOT_AUTHENTICATED':
      redirectToLogin();
      break;
    case 'INVALID_STATE':
      showError('Security check failed. Please try again.');
      break;
  }
}
```

### Error Types and Codes

#### Authentication Errors
- `NOT_AUTHENTICATED` - User not logged in
- `INVALID_STATE` - CSRF protection failed
- `INCORRECT_PASSWORD` - Wrong password provided
- `USER_NOT_FOUND` - Email not found in system

#### Validation Errors
- `MISSING_EMAIL` - Email required but not provided
- `INVALID_EMAIL_FORMAT` - Invalid email format
- `PASSWORD_TOO_SHORT` - Password less than 8 characters
- `EMPTY_UPDATES` - No fields provided for update

#### Token Errors
- `TOKEN_EXPIRED` - Access token has expired
- `INVALID_REFRESH_TOKEN` - Refresh token is invalid
- `NO_MANAGEMENT_TOKEN` - Management API access required

#### Network Errors
- `NETWORK_ERROR` - Connection issues
- `TOKEN_EXCHANGE_ERROR` - Failed to exchange authorization code
- `PASSWORD_RESET_ERROR` - Failed to send reset email

### Manual Error Handling

```javascript
// Check for errors manually
const lastError = authProvider.getLastError();
if (lastError) {
  console.log('Last error:', lastError);
  authProvider.clearError();
}

// Create custom errors
const customError = authProvider.createValidationError(
  'Custom validation failed',
  'CUSTOM_VALIDATION',
  { field: 'email', value: 'invalid' }
);
```

## TypeScript Support

### Type Definitions

```typescript
import { AuthProvider, UserProfile, AuthError, AuthConfig } from 'GMF-CIAM-sdk';

// Configuration typing
const config: AuthConfig = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-identifier'
};

// Error handling with types
authProvider.onError((error: AuthError) => {
  console.log(`Error ${error.code}: ${error.message}`);
  console.log('Details:', error.details);
  console.log('Timestamp:', error.timestamp);
});

// Profile typing
const profile: UserProfile = await authProvider.getUserProfile();
console.log('User ID:', profile.sub);
console.log('Email:', profile.email);
```

### Generic Error Handling

```typescript
// Type-safe error code checking
import { AuthErrorCode } from 'GMF-CIAM-sdk';

function handleError(error: AuthError) {
  const code: AuthErrorCode = error.code;
  
  switch (code) {
    case 'INVALID_REFRESH_TOKEN':
      // TypeScript knows this is a valid error code
      redirectToLogin();
      break;
    case 'PASSWORD_TOO_SHORT':
      showValidationMessage('Password must be at least 8 characters');
      break;
  }
}
```

## Examples

### React Hook

```jsx
import { useState, useEffect } from 'react';
import GMFCIAMAuth from 'GMF-CIAM-sdk';

export function useAuth() {
  const [authProvider, setAuthProvider] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    initAuth();
  }, []);

  async function initAuth() {
    try {
      const provider = await GMFCIAMAuth.createAuthProvider('auth0', {
        domain: process.env.REACT_APP_AUTH0_DOMAIN,
        clientId: process.env.REACT_APP_AUTH0_CLIENT_ID,
        audience: process.env.REACT_APP_AUTH0_AUDIENCE
      });

      provider.onError((authError) => {
        setError(authError.message);
      });

      setAuthProvider(provider);
      
      const authenticated = await provider.isAuthenticated();
      setIsAuthenticated(authenticated);
      
      if (authenticated) {
        const profile = await provider.getUserProfile();
        setUser(profile);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  return {
    authProvider,
    isAuthenticated,
    user,
    error,
    login: () => authProvider?.login(),
    logout: () => authProvider?.logout()
  };
}
```

### Vue.js Composition API

```javascript
import { ref, onMounted } from 'vue';
import GMFCIAMAuth from 'GMF-CIAM-sdk';

export function useAuth() {
  const authProvider = ref(null);
  const isAuthenticated = ref(false);
  const user = ref(null);
  const error = ref(null);

  onMounted(async () => {
    try {
      authProvider.value = await GMFCIAMAuth.createAuthProvider('auth0', {
        domain: import.meta.env.VITE_AUTH0_DOMAIN,
        clientId: import.meta.env.VITE_AUTH0_CLIENT_ID,
        audience: import.meta.env.VITE_AUTH0_AUDIENCE
      });

      authProvider.value.onError((authError) => {
        error.value = authError.message;
      });

      isAuthenticated.value = await authProvider.value.isAuthenticated();
      
      if (isAuthenticated.value) {
        user.value = await authProvider.value.getUserProfile();
      }
    } catch (err) {
      error.value = err.message;
    }
  });

  return {
    authProvider,
    isAuthenticated,
    user,
    error
  };
}
```

### Server-Side Usage (Node.js)

```javascript
// For server-side token validation
import GMFCIAMAuth from 'GMF-CIAM-sdk';

const authProvider = await GMFCIAMAuth.createAuthProvider('auth0', {
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  audience: process.env.AUTH0_AUDIENCE
});

// Validate token from request
async function validateRequest(req, res, next) {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    // Use the token to get user info
    const isValid = await authProvider.validateToken(token);
    if (isValid) {
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
}
```

## API Reference

### GMFCIAMAuth

#### `createAuthProvider(type, config)`
Creates and returns an authentication provider instance.

- **Parameters:**
  - `type`: `'auth0' | 'okta'` - The identity provider type
  - `config`: `AuthConfig | OktaConfig` - Provider-specific configuration
- **Returns:** `Promise<AuthProvider>`

### AuthProvider Interface

#### Core Methods

##### `login(): Promise<void>`
Initiates the authentication flow by redirecting to the identity provider.

##### `logout(): void`
Logs out the user and redirects to the logout URL.

##### `isAuthenticated(): Promise<boolean>`
Checks if the user is currently authenticated.

##### `getAccessToken(): Promise<string>`
Returns the current access token, refreshing if necessary.

##### `refreshToken(): Promise<boolean>`
Manually refreshes the access token using the refresh token.

#### Profile Methods

##### `getUserProfile(forceRefresh?: boolean): Promise<UserProfile>`
Gets the user's profile information.
- `forceRefresh`: If true, bypasses cache and fetches fresh data

##### `getDetailedUserProfile(): Promise<UserProfile>`
Gets detailed profile information using the Management API.

##### `updateUserProfile(updates: Partial<UserProfile>): Promise<UserProfile>`
Updates the user's profile with the provided fields.

#### Password Methods

##### `resetPassword(email: string): Promise<string>`
Sends a password reset email to the specified address.

##### `changePassword(oldPassword: string, newPassword: string): Promise<string>`
Changes the user's password (requires authentication).

#### Error Handling Methods

##### `onError(callback: (error: AuthError) => void): void`
Registers a callback function to handle authentication errors.

##### `removeErrorCallback(callback: (error: AuthError) => void): void`
Removes a previously registered error callback.

##### `getLastError(): AuthError | null`
Returns the last error that occurred, or null if no errors.

##### `clearError(): void`
Clears the stored error state.

##### `createError(type: string, message: string, code: string, details?: object): AuthError`
Creates a custom error object with the specified parameters.

#### Utility Methods

##### `validateAuthState(): Promise<AuthValidationResult>`
Performs a comprehensive validation of the current authentication state.

##### `getAuthStatus(): AuthStatus`
Returns detailed information about the current authentication status.

## Migration Guide

### From Version 1.x to 2.x

#### Breaking Changes

1. **Error Handling**: Manual error checking replaced with callback system
```javascript
// v1.x
if (authProvider.hasError()) {
  const error = authProvider.getLastError();
  // handle error
}

// v2.x
authProvider.onError((error) => {
  // handle error automatically
});
```

2. **Configuration**: New required fields for enhanced security
```javascript
// v1.x
const config = {
  domain: 'domain.auth0.com',
  clientId: 'client-id'
};

// v2.x
const config = {
  domain: 'domain.auth0.com',
  clientId: 'client-id',
  audience: 'api-identifier' // Now required
};
```

3. **TypeScript**: Improved type definitions
```typescript
// v1.x
import GMFAuth, { AuthProvider } from 'GMF-CIAM-sdk';

// v2.x
import GMFCIAMAuth, { AuthProvider, AuthError, AuthConfig } from 'GMF-CIAM-sdk';
```

#### Migration Steps

1. **Update configuration** to include required `audience` field
2. **Replace manual error checking** with `onError()` callbacks
3. **Update TypeScript imports** to use new interface names
4. **Test error handling** with the new centralized system

### From Auth0 SDK Direct Usage

```javascript
// Direct Auth0 SDK
import { createAuth0Client } from '@auth0/auth0-spa-js';

const auth0 = await createAuth0Client({
  domain: 'domain.auth0.com',
  clientId: 'client-id'
});

// GMF-CIAM-SDK
import GMFCIAMAuth from 'GMF-CIAM-sdk';

const authProvider = await GMFCIAMAuth.createAuthProvider('auth0', {
  domain: 'domain.auth0.com',
  clientId: 'client-id',
  audience: 'api-identifier'
});
```

## Troubleshooting

### Common Issues

#### 1. "Configuration Error: Missing required Auth0 configuration"

**Cause:** Required configuration fields are missing.

**Solution:**
```javascript
// Ensure all required fields are provided
const config = {
  domain: 'your-domain.auth0.com',    // Required
  clientId: 'your-client-id',         // Required
  audience: 'your-api-identifier'     // Required
};
```

#### 2. "Invalid state parameter - possible CSRF attack"

**Cause:** State parameter validation failed during authentication callback.

**Solution:**
- Check that your domain configuration is correct
- Ensure cookies are enabled in the browser
- Verify that the redirect URI matches exactly

#### 3. "Management token required for this operation"

**Cause:** Attempting to use Management API features without proper configuration.

**Solution:**
```javascript
const config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-identifier',
  clientSecret: 'your-client-secret' // Required for Management API
};
```

#### 4. TypeScript compilation errors

**Cause:** Type definition conflicts or outdated types.

**Solution:**
- Update to the latest version of the SDK
- Clear `node_modules` and reinstall dependencies
- Check TypeScript version compatibility

### Debug Mode

Enable debug logging to troubleshoot issues:

```javascript
// Enable debug mode
localStorage.setItem('gmf-ciam-debug', 'true');

// Or set in configuration
const config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-identifier',
  debug: true
};
```

### Error Logging

Set up comprehensive error logging:

```javascript
authProvider.onError((error) => {
  // Log to console
  console.error('Auth Error:', {
    name: error.name,
    code: error.code,
    message: error.message,
    details: error.details,
    timestamp: error.timestamp
  });
  
  // Log to external service
  if (window.analytics) {
    window.analytics.track('auth_error', {
      error_type: error.name,
      error_code: error.code,
      error_message: error.message
    });
  }
});
```

### Performance Optimization

#### Token Caching
```javascript
// Configure token caching
const config = {
  domain: 'your-domain.auth0.com',
  clientId: 'your-client-id',
  audience: 'your-api-identifier',
  cacheLocation: 'localstorage' // or 'sessionstorage'
};
```

#### Lazy Loading
```javascript
// Lazy load the auth provider
async function getAuthProvider() {
  if (!window.authProvider) {
    const GMFCIAMAuth = await import('GMF-CIAM-sdk');
    window.authProvider = await GMFCIAMAuth.default.createAuthProvider('auth0', config);
  }
  return window.authProvider;
}
```

## Support

### Getting Help

- **Documentation**: This documentation
- **GitHub Issues**: [GitHub Repository Issues](https://github.com/gmf/ciam-sdk/issues)
- **Email Support**: support@gmf.com

### Reporting Bugs

When reporting bugs, please include:

1. **SDK Version**: Check `package.json` or use `npm list GMF-CIAM-sdk`
2. **Environment**: Browser version, Node.js version, framework
3. **Configuration**: Sanitized configuration (remove secrets)
4. **Error Details**: Full error message and stack trace
5. **Reproduction Steps**: Minimal code example to reproduce the issue

### Feature Requests

Feature requests should include:

1. **Use Case**: Describe the problem you're trying to solve
2. **Proposed Solution**: How you think it should work
3. **Alternatives**: Other solutions you've considered
4. **Impact**: How many users would benefit from this feature

---

**Version**: 2.0.0  
**Last Updated**: June 2025  
**License**: MIT
