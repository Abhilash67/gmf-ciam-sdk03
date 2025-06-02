// Auth0 specific implementation with simplified error handling
import { AuthProvider } from "../auth-provider.js";

export default class Auth0Provider extends AuthProvider {
  constructor(config) {
    console.log("[Auth0Provider] constructor called");
    
    try {
      super(config);
      
      // Validate required configuration
      if (!config) {
        throw this.createConfigError(
          "Auth0 configuration object is required",
          'MISSING_CONFIG'
        );
      }

      const requiredFields = ['domain', 'clientId', 'audience'];
      const missingFields = requiredFields.filter(field => !config[field]);
      
      if (missingFields.length > 0) {
        throw this.createConfigError(
          `Missing required Auth0 configuration: ${missingFields.join(', ')}`,
          'INCOMPLETE_CONFIG'
        );
      }

      // Validate domain format
      if (!this._isValidDomain(config.domain)) {
        throw this.createConfigError(
          "Invalid Auth0 domain format. Expected format: your-domain.auth0.com",
          'INVALID_DOMAIN'
        );
      }

      this.config = {
        domain: config.domain,
        clientId: config.clientId,
        audience: config.audience,
        redirectUri: config.redirectUri || window.location.origin,
        scope: config.scope || "openid profile email offline_access",
        responseType: "code",
        cacheLocation: "localstorage",
        managementApiAudience: config.managementApiAudience || `https://${config.domain}/api/v2/`,
        clientSecret: config.clientSecret,
      };

      this._initializeProperties();
      this._initializeAuth();
      
    } catch (error) {
      console.error("[Auth0Provider] Constructor failed:", error);
      throw error;
    }
  }

  _initializeProperties() {
    this.accessToken = null;
    this.refreshToken = null;
    this.managementToken = null;
    this.userProfile = null;
    this.expiresAt = null;
    this.authenticated = false;
  }

  _isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9-]+\.(?:auth0\.com|eu\.auth0\.com|au\.auth0\.com)$/;
    return domainRegex.test(domain) || domain.includes('.') && domain.length > 3;
  }

  _initializeAuth() {
    console.log("[Auth0Provider] _initializeAuth called");
    
    try {
      const storedAuth = this._getStoredAuthData();
      
      if (storedAuth) {
        if (this._isValidStoredAuth(storedAuth)) {
          this._restoreAuthState(storedAuth);
        } else if (storedAuth.refreshToken) {
          this._attemptTokenRefresh(storedAuth.refreshToken);
        } else {
          this._clearStorage();
        }
      }

      if (!this.authenticated && this._hasAuthCallback()) {
        this._handleAuthCallback().catch(error => {
          console.error("[Auth0Provider] Callback handling failed:", error);
          this._clearStorage();
        });
      }
      
    } catch (error) {
      console.error("[Auth0Provider] Auth initialization failed:", error);
      this._clearStorage();
    }
  }

  _getStoredAuthData() {
    try {
      const storedAuth = localStorage.getItem("authClient");
      return storedAuth ? JSON.parse(storedAuth) : null;
    } catch (error) {
      console.warn("[Auth0Provider] Failed to parse stored auth data:", error);
      return null;
    }
  }

  _isValidStoredAuth(authData) {
    return authData.expiresAt && 
           new Date().getTime() < authData.expiresAt && 
           authData.accessToken;
  }

  _restoreAuthState(authData) {
    this.accessToken = authData.accessToken;
    this.refreshToken = authData.refreshToken;
    this.managementToken = authData.managementToken;
    this.userProfile = authData.userProfile;
    this.expiresAt = authData.expiresAt;
    this.authenticated = true;
  }

  _hasAuthCallback() {
    return window.location.search.includes("code=") || window.location.search.includes("error=");
  }

  _attemptTokenRefresh(refreshToken) {
    this._refreshToken(refreshToken).catch(error => {
      console.error("[Auth0Provider] Auto token refresh failed:", error);
      this._clearStorage();
    });
  }

  _clearStorage() {
    console.log("[Auth0Provider] _clearStorage called");
    
    try {
      localStorage.removeItem("authClient");
      this._initializeProperties();
    } catch (error) {
      console.error("[Auth0Provider] Failed to clear storage:", error);
      this._initializeProperties();
    }
  }

  async login() {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] login called");
      
      if (!this.config.domain || !this.config.clientId) {
        throw this.createConfigError(
          "Invalid configuration: domain and clientId are required for login",
          'LOGIN_CONFIG_ERROR'
        );
      }

      const state = this._generateRandomString(32);
      sessionStorage.setItem('auth0_state', state);

      const authUrl = this._buildAuthUrl(state);
      
      if (!this._isValidUrl(authUrl)) {
        throw this.createAuthError(
          "Failed to generate valid authentication URL",
          'INVALID_AUTH_URL'
        );
      }

      window.location.assign(authUrl);
    }, 'Login');
  }

  _buildAuthUrl(state) {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: this.config.responseType,
      scope: this.config.scope,
      audience: this.config.audience,
      state: state
    });

    return `https://${this.config.domain}/authorize?${params.toString()}`;
  }

  _generateRandomString(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  _isValidUrl(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  async _handleAuthCallback() {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] _handleAuthCallback called");
      
      const urlParams = new URLSearchParams(window.location.search);
      
      const error = urlParams.get("error");
      if (error) {
        const errorDescription = urlParams.get("error_description") || "Unknown authentication error";
        throw this.createAuthError(
          `Authentication failed: ${errorDescription}`,
          error.toUpperCase()
        );
      }

      const state = urlParams.get("state");
      const storedState = sessionStorage.getItem('auth0_state');
      
      if (!state || !storedState || state !== storedState) {
        throw this.createAuthError(
          "Invalid state parameter - possible CSRF attack",
          'INVALID_STATE'
        );
      }

      const code = urlParams.get("code");
      if (!code) {
        throw this.createAuthError(
          "No authorization code received from Auth0",
          'MISSING_AUTH_CODE'
        );
      }

      await this._exchangeCodeForTokens(code);
      await this._getManagementToken();
      await this.getUserProfile();
      
      this._saveAuthData();
      this._cleanupUrl();
      sessionStorage.removeItem('auth0_state');

      return true;
    }, 'Authentication callback');
  }

  async _exchangeCodeForTokens(code) {
    return this.handleAsync(async () => {
      const tokenResponse = await fetch(
        `https://${this.config.domain}/oauth/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "authorization_code",
            client_id: this.config.clientId,
            code,
            redirect_uri: this.config.redirectUri,
          }),
        }
      );

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json().catch(() => ({}));
        throw this.createNetworkError(
          `Token exchange failed: ${errorData.error_description || errorData.error || 'Unknown error'}`,
          'TOKEN_EXCHANGE_ERROR',
          { status: tokenResponse.status }
        );
      }

      const tokenData = await tokenResponse.json();
      
      if (!tokenData.access_token) {
        throw this.createTokenError(
          "No access token received from Auth0",
          'MISSING_ACCESS_TOKEN'
        );
      }

      this.accessToken = tokenData.access_token;
      this.refreshToken = tokenData.refresh_token;
      this.expiresAt = new Date().getTime() + (tokenData.expires_in * 1000);
      this.authenticated = true;
    }, 'Token exchange');
  }

  _cleanupUrl() {
    try {
      const url = new URL(window.location.href);
      url.search = "";
      window.history.replaceState({}, document.title, url.toString());
    } catch (error) {
      console.warn("[Auth0Provider] Failed to cleanup URL:", error);
    }
  }

  async _getManagementToken() {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] _getManagementToken called");
      
      if (!this.config.clientSecret) {
        console.warn("[Auth0Provider] Client secret not provided - Management API features limited");
        return;
      }

      const response = await fetch(`https://${this.config.domain}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
          audience: this.config.managementApiAudience,
          grant_type: "client_credentials",
        }),
      });

      if (response.ok) {
        const tokenData = await response.json();
        if (tokenData.access_token) {
          this.managementToken = tokenData.access_token;
        } else {
          throw this.createTokenError(
            "Management API token response missing access token",
            'INVALID_MGMT_TOKEN_RESPONSE'
          );
        }
      } else {
        const errorData = await response.json().catch(() => ({}));
        throw this.createNetworkError(
          `Management token request failed: ${errorData.error_description || 'Unknown error'}`,
          'MGMT_TOKEN_ERROR',
          { status: response.status }
        );
      }
    }, 'Management token acquisition').catch(error => {
      console.warn("[Auth0Provider] Management token acquisition failed:", error);
      // Don't throw - management token is optional
    });
  }

  async _refreshToken(refreshToken) {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] _refreshToken called");
      
      if (!refreshToken) {
        throw this.createTokenError(
          "Refresh token is required for token refresh",
          'MISSING_REFRESH_TOKEN'
        );
      }

      const tokenResponse = await fetch(
        `https://${this.config.domain}/oauth/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "refresh_token",
            client_id: this.config.clientId,
            refresh_token: refreshToken,
          }),
        }
      );

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json().catch(() => ({}));
        
        if (tokenResponse.status === 403 || errorData.error === 'invalid_grant') {
          this._clearStorage();
          throw this.createTokenError(
            "Refresh token is invalid or expired - please log in again",
            'INVALID_REFRESH_TOKEN'
          );
        }
        
        throw this.createNetworkError(
          `Token refresh failed: ${errorData.error_description || errorData.error || 'Unknown error'}`,
          'TOKEN_REFRESH_ERROR',
          { status: tokenResponse.status }
        );
      }

      const tokenData = await tokenResponse.json();
      
      if (!tokenData.access_token) {
        throw this.createTokenError(
          "Token refresh response missing access token",
          'INVALID_REFRESH_RESPONSE'
        );
      }
      
      this.accessToken = tokenData.access_token;
      this.refreshToken = tokenData.refresh_token || refreshToken;
      this.expiresAt = new Date().getTime() + (tokenData.expires_in * 1000);
      this.authenticated = true;
      
      this._saveAuthData();
      return true;
    }, 'Token refresh');
  }

  async refreshToken() {
    console.log("[Auth0Provider] refreshToken called");
    
    if (!this.refreshToken) {
      throw this.createTokenError(
        "No refresh token available - user needs to log in again",
        'NO_REFRESH_TOKEN'
      );
    }
    
    return this._refreshToken(this.refreshToken);
  }

  async resetPassword(email) {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] resetPassword called");
      
      if (!email) {
        throw this.createValidationError(
          "Email address is required for password reset",
          'MISSING_EMAIL'
        );
      }

      if (!this._isValidEmail(email)) {
        throw this.createValidationError(
          "Invalid email address format",
          'INVALID_EMAIL_FORMAT'
        );
      }
      
      const response = await fetch(
        `https://${this.config.domain}/dbconnections/change_password`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client_id: this.config.clientId,
            email: email,
            connection: "Username-Password-Authentication"
          }),
        }
      );
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 400 && errorData.error === 'user_not_found') {
          throw this.createAuthError(
            "No account found with this email address",
            'USER_NOT_FOUND'
          );
        }
        
        throw this.createNetworkError(
          `Password reset failed: ${errorData.error_description || errorData.error || 'Unknown error'}`,
          'PASSWORD_RESET_ERROR',
          { status: response.status }
        );
      }
      
      return "Password reset email sent successfully";
    }, 'Password reset');
  }

  _isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  async changePassword(oldPassword, newPassword) {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] changePassword called");
      
      if (!this.authenticated || !this.userProfile) {
        throw this.createAuthError(
          "User must be authenticated to change password",
          'NOT_AUTHENTICATED'
        );
      }

      if (!oldPassword || !newPassword) {
        throw this.createValidationError(
          "Both current and new passwords are required",
          'MISSING_PASSWORDS'
        );
      }

      if (typeof oldPassword !== 'string' || typeof newPassword !== 'string') {
        throw this.createValidationError(
          "Passwords must be strings",
          'INVALID_PASSWORD_TYPE'
        );
      }

      if (newPassword.length < 8) {
        throw this.createValidationError(
          "New password must be at least 8 characters long",
          'PASSWORD_TOO_SHORT'
        );
      }

      if (oldPassword === newPassword) {
        throw this.createValidationError(
          "New password must be different from current password",
          'PASSWORD_UNCHANGED'
        );
      }

      await this._verifyCurrentPassword(oldPassword);
      await this._updatePasswordViaManagementApi(newPassword);
      
      return "Password changed successfully";
    }, 'Password change');
  }

  async _verifyCurrentPassword(oldPassword) {
    return this.handleAsync(async () => {
      const verifyResponse = await fetch(
        `https://${this.config.domain}/oauth/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "password",
            username: this.userProfile.email,
            password: oldPassword,
            audience: this.config.audience,
            client_id: this.config.clientId,
            scope: "openid profile email"
          }),
        }
      );

      if (!verifyResponse.ok) {
        const errorData = await verifyResponse.json().catch(() => ({}));
        
        if (verifyResponse.status === 403 || errorData.error === 'invalid_grant') {
          throw this.createAuthError(
            "Current password is incorrect",
            'INCORRECT_PASSWORD'
          );
        }
        
        throw this.createNetworkError(
          `Password verification failed: ${errorData.error_description || 'Unknown error'}`,
          'PASSWORD_VERIFY_ERROR',
          { status: verifyResponse.status }
        );
      }
    }, 'Password verification');
  }

  async _updatePasswordViaManagementApi(newPassword) {
    return this.handleAsync(async () => {
      if (!this.managementToken) {
        await this._getManagementToken();
      }

      if (!this.managementToken) {
        throw this.createTokenError(
          "Unable to obtain management token for password change - this operation requires server-side implementation",
          'NO_MANAGEMENT_TOKEN'
        );
      }

      const updateResponse = await fetch(
        `https://${this.config.domain}/api/v2/users/${this.userProfile.sub}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${this.managementToken}`,
          },
          body: JSON.stringify({ password: newPassword }),
        }
      );

      if (!updateResponse.ok) {
        const errorData = await updateResponse.json().catch(() => ({}));
        
        if (updateResponse.status === 401) {
          throw this.createTokenError(
            "Management token is invalid or expired",
            'INVALID_MANAGEMENT_TOKEN'
          );
        }
        
        if (updateResponse.status === 403) {
          throw this.createAuthError(
            "Insufficient permissions to change password",
            'INSUFFICIENT_PERMISSIONS'
          );
        }
        
        throw this.createNetworkError(
          `Password update failed: ${errorData.message || errorData.error || 'Unknown error'}`,
          'PASSWORD_UPDATE_ERROR',
          { status: updateResponse.status }
        );
      }
    }, 'Password update via Management API');
  }

  async getUserProfile(forceRefresh = false) {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] getUserProfile called");
      
      if (!this.authenticated || !this.accessToken) {
        throw this.createAuthError(
          "User must be authenticated to get profile",
          'NOT_AUTHENTICATED'
        );
      }

      if (this.userProfile && !forceRefresh) {
        return this.userProfile;
      }

      if (this.expiresAt && new Date().getTime() >= this.expiresAt) {
        if (this.refreshToken) {
          await this.refreshToken();
        } else {
          throw this.createTokenError(
            "Access token expired and no refresh token available",
            'TOKEN_EXPIRED'
          );
        }
      }

      const userInfoResponse = await fetch(
        `https://${this.config.domain}/userinfo`,
        {
          headers: { Authorization: `Bearer ${this.accessToken}` },
        }
      );

      if (!userInfoResponse.ok) {
        const errorData = await userInfoResponse.json().catch(() => ({}));
        
        if (userInfoResponse.status === 401) {
          throw this.createTokenError(
            "Access token is invalid or expired",
            'INVALID_ACCESS_TOKEN'
          );
        }
        
        throw this.createNetworkError(
          `Failed to fetch user profile: ${errorData.error_description || errorData.error || 'Unknown error'}`,
          'PROFILE_FETCH_ERROR',
          { status: userInfoResponse.status }
        );
      }

      const profileData = await userInfoResponse.json();
      
      if (!profileData.sub) {
        throw this.createAuthError(
          "Invalid user profile data received",
          'INVALID_PROFILE_DATA'
        );
      }

      this.userProfile = profileData;
      this._saveAuthData();

      return this.userProfile;
    }, 'Get user profile');
  }

  async getDetailedUserProfile() {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] getDetailedUserProfile called");
      
      if (!this.authenticated || !this.userProfile) {
        throw this.createAuthError(
          "User must be authenticated to get detailed profile",
          'NOT_AUTHENTICATED'
        );
      }

      if (!this.managementToken) {
        await this._getManagementToken();
      }

      if (!this.managementToken) {
        throw this.createTokenError(
          "Unable to obtain management token for detailed profile - this operation requires server-side implementation",
          'NO_MANAGEMENT_TOKEN'
        );
      }

      const response = await fetch(
        `https://${this.config.domain}/api/v2/users/${this.userProfile.sub}`,
        {
          headers: { "Authorization": `Bearer ${this.managementToken}` },
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 401) {
          throw this.createTokenError(
            "Management token is invalid or expired",
            'INVALID_MANAGEMENT_TOKEN'
          );
        }
        
        if (response.status === 404) {
          throw this.createAuthError(
            "User not found in Auth0 database",
            'USER_NOT_FOUND'
          );
        }
        
        throw this.createNetworkError(
          `Failed to get detailed profile: ${errorData.message || errorData.error || 'Unknown error'}`,
          'DETAILED_PROFILE_ERROR',
          { status: response.status }
        );
      }

      return await response.json();
    }, 'Get detailed user profile');
  }

  async updateUserProfile(updates) {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] updateUserProfile called");
      
      if (!this.authenticated || !this.userProfile) {
        throw this.createAuthError(
          "User must be authenticated to update profile",
          'NOT_AUTHENTICATED'
        );
      }

      if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
        throw this.createValidationError(
          "Updates must be a valid object",
          'INVALID_UPDATES_FORMAT'
        );
      }

      if (Object.keys(updates).length === 0) {
        throw this.createValidationError(
          "Updates object cannot be empty",
          'EMPTY_UPDATES'
        );
      }

      this._validateProfileUpdates(updates);

      if (!this.managementToken) {
        await this._getManagementToken();
      }

      if (!this.managementToken) {
        throw this.createTokenError(
          "Unable to obtain management token for profile update - this operation requires server-side implementation",
          'NO_MANAGEMENT_TOKEN'
        );
      }

      const response = await fetch(
        `https://${this.config.domain}/api/v2/users/${this.userProfile.sub}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${this.managementToken}`,
          },
          body: JSON.stringify(updates),
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        if (response.status === 401) {
          throw this.createTokenError(
            "Management token is invalid or expired",
            'INVALID_MANAGEMENT_TOKEN'
          );
        }
        
        if (response.status === 400) {
          throw this.createValidationError(
            `Invalid profile update data: ${errorData.message || 'Bad request'}`,
            'INVALID_UPDATE_DATA'
          );
        }
        
        if (response.status === 403) {
          throw this.createAuthError(
            "Insufficient permissions to update profile",
            'INSUFFICIENT_PERMISSIONS'
          );
        }
        
        throw this.createNetworkError(
          `Profile update failed: ${errorData.message || errorData.error || 'Unknown error'}`,
          'PROFILE_UPDATE_ERROR',
          { status: response.status }
        );
      }

      const updatedProfile = await response.json();
      
      try {
        await this.getUserProfile(true);
      } catch (refreshError) {
        console.warn("[Auth0Provider] Failed to refresh profile after update:", refreshError);
      }
      
      return updatedProfile;
    }, 'Update user profile');
  }

  _validateProfileUpdates(updates) {
    const allowedFields = [
      'name', 'given_name', 'family_name', 'middle_name', 'nickname',
      'preferred_username', 'profile', 'picture', 'website', 'gender',
      'birthdate', 'zoneinfo', 'locale', 'phone_number', 'address',
      'user_metadata', 'app_metadata'
    ];

    const restrictedFields = ['sub', 'user_id', 'email', 'email_verified', 'identities'];
    
    for (const field of Object.keys(updates)) {
      if (restrictedFields.includes(field)) {
        throw this.createValidationError(
          `Field '${field}' cannot be updated through this method`,
          'RESTRICTED_FIELD'
        );
      }
      
      if (!allowedFields.includes(field)) {
        console.warn(`[Auth0Provider] Warning: Field '${field}' may not be supported`);
      }
    }

    if (updates.email && !this._isValidEmail(updates.email)) {
      throw this.createValidationError(
        "Invalid email format in updates",
        'INVALID_EMAIL_FORMAT'
      );
    }

    if (updates.phone_number && typeof updates.phone_number !== 'string') {
      throw this.createValidationError(
        "Phone number must be a string",
        'INVALID_PHONE_FORMAT'
      );
    }
  }

  logout() {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] logout called");
      
      this._clearStorage();

      const logoutUrl = this._buildLogoutUrl();
      
      if (!this._isValidUrl(logoutUrl)) {
        throw this.createAuthError(
          "Failed to generate valid logout URL",
          'INVALID_LOGOUT_URL'
        );
      }

      window.location.assign(logoutUrl);
    }, 'Logout').catch(error => {
      // Even if logout URL generation fails, clear local state
      this._clearStorage();
      throw error;
    });
  }

  _buildLogoutUrl() {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      returnTo: this.config.redirectUri
    });

    return `https://${this.config.domain}/v2/logout?${params.toString()}`;
  }

  async isAuthenticated() {
    try {
      console.log("[Auth0Provider] isAuthenticated called");
      
      if (!this.authenticated || !this.accessToken || !this.expiresAt) {
        return false;
      }

      const now = new Date().getTime();
      if (now >= this.expiresAt) {
        if (this.refreshToken) {
          try {
            await this.refreshToken();
            return this.authenticated && this.expiresAt && now < this.expiresAt;
          } catch (refreshError) {
            console.warn("[Auth0Provider] Token refresh failed during auth check:", refreshError);
            return false;
          }
        } else {
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error("[Auth0Provider] Authentication check failed:", error);
      return false;
    }
  }

  async getAccessToken() {
    return this.handleAsync(async () => {
      console.log("[Auth0Provider] getAccessToken called");
      
      const isAuth = await this.isAuthenticated();
      if (!isAuth) {
        throw this.createTokenError(
          "User is not authenticated - cannot provide access token",
          'NOT_AUTHENTICATED'
        );
      }

      if (!this.accessToken) {
        throw this.createTokenError(
          "No access token available",
          'NO_ACCESS_TOKEN'
        );
      }

      const now = new Date().getTime();
      const bufferTime = 5 * 60 * 1000; // 5 minutes buffer
      
      if (this.expiresAt && (now + bufferTime) >= this.expiresAt && this.refreshToken) {
        await this.refreshToken();
      }
      
      return this.accessToken;
    }, 'Get access token');
  }

  _saveAuthData() {
    console.log("[Auth0Provider] _saveAuthData called");
    
    try {
      const authData = {
        accessToken: this.accessToken,
        refreshToken: this.refreshToken,
        managementToken: this.managementToken,
        userProfile: this.userProfile,
        expiresAt: this.expiresAt,
      };

      localStorage.setItem("authClient", JSON.stringify(authData));
      
    } catch (error) {
      console.error("[Auth0Provider] Failed to save auth data:", error);
      
      if (error.name === 'QuotaExceededError') {
        console.warn("[Auth0Provider] Storage quota exceeded - attempting to clear old data");
        try {
          localStorage.removeItem("authClient");
          localStorage.setItem("authClient", JSON.stringify({
            accessToken: this.accessToken,
            refreshToken: this.refreshToken,
            userProfile: this.userProfile,
            expiresAt: this.expiresAt,
          }));
        } catch (retryError) {
          console.error("[Auth0Provider] Failed to save auth data after cleanup:", retryError);
        }
      }
    }
  }

  // Enhanced utility methods
  async validateAuthState() {
    try {
      const isAuth = await this.isAuthenticated();
      if (!isAuth) {
        return { valid: false, reason: 'Not authenticated' };
      }

      try {
        await this.getUserProfile();
        return { valid: true };
      } catch (profileError) {
        return { 
          valid: false, 
          reason: 'Token validation failed',
          error: profileError.message 
        };
      }
    } catch (error) {
      return { 
        valid: false, 
        reason: 'Validation check failed',
        error: error.message 
      };
    }
  }

  getAuthStatus() {
    return {
      authenticated: this.authenticated,
      hasAccessToken: !!this.accessToken,
      hasRefreshToken: !!this.refreshToken,
      hasUserProfile: !!this.userProfile,
      tokenExpired: this.expiresAt ? new Date().getTime() >= this.expiresAt : null,
      expiresAt: this.expiresAt ? new Date(this.expiresAt).toISOString() : null,
      lastError: this.getLastError(),
    };
  }
}
