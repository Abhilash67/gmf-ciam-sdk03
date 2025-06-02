// Base AuthProvider with error handling utilities
export class AuthProvider {
  constructor(config) {
    if (this.constructor === AuthProvider) {
      throw new Error(
        "AuthProvider is an abstract class and cannot be instantiated directly"
      );
    }
    
    // Initialize error tracking
    this._lastError = null;
    this._errorCallbacks = [];
  }

  // Error handling utilities
  createError(type, message, code, details = {}) {
    const error = new Error(message);
    error.name = type;
    error.code = code;
    error.details = details;
    error.timestamp = new Date().toISOString();
    
    this._lastError = error;
    this._notifyErrorCallbacks(error);
    
    return error;
  }

  getLastError() {
    return this._lastError;
  }

  clearError() {
    this._lastError = null;
  }

  onError(callback) {
    if (typeof callback === 'function') {
      this._errorCallbacks.push(callback);
    }
  }

  removeErrorCallback(callback) {
    this._errorCallbacks = this._errorCallbacks.filter(cb => cb !== callback);
  }

  _notifyErrorCallbacks(error) {
    this._errorCallbacks.forEach(callback => {
      try {
        callback(error);
      } catch (callbackError) {
        console.error('Error in error callback:', callbackError);
      }
    });
  }

  // Error type creators for consistency
  createAuthError(message, code = 'AUTH_ERROR', details = {}) {
    return this.createError('AuthenticationError', message, code, details);
  }

  createConfigError(message, code = 'CONFIG_ERROR', details = {}) {
    return this.createError('ConfigurationError', message, code, details);
  }

  createNetworkError(message, code = 'NETWORK_ERROR', details = {}) {
    return this.createError('NetworkError', message, code, details);
  }

  createTokenError(message, code = 'TOKEN_ERROR', details = {}) {
    return this.createError('TokenError', message, code, details);
  }

  createValidationError(message, code = 'VALIDATION_ERROR', details = {}) {
    return this.createError('ValidationError', message, code, details);
  }

  // Utility method to handle async operations with error tracking
  async handleAsync(operation, errorContext = 'Unknown operation') {
    try {
      return await operation();
    } catch (error) {
      console.error(`[${this.constructor.name}] ${errorContext} failed:`, error);
      
      // If it's already our custom error, just re-throw
      if (error.code && error.details !== undefined) {
        throw error;
      }
      
      // Otherwise, wrap it
      throw this.createError(
        'OperationError',
        `${errorContext} failed: ${error.message}`,
        'OPERATION_ERROR',
        { originalError: error.message, context: errorContext }
      );
    }
  }

  // Abstract methods that must be implemented
  login() {
    throw new Error("Method 'login()' must be implemented");
  }

  logout() {
    throw new Error("Method 'logout()' must be implemented");
  }

  getUserProfile(forceRefresh = false) {
    throw new Error("Method 'getUserProfile()' must be implemented");
  }

  isAuthenticated() {
    throw new Error("Method 'isAuthenticated()' must be implemented");
  }

  getAccessToken() {
    throw new Error("Method 'getAccessToken()' must be implemented");
  }

  refreshToken() {
    throw new Error("Method 'refreshToken()' must be implemented");
  }
  
  resetPassword(email) {
    throw new Error("Method 'resetPassword()' must be implemented");
  }

  changePassword(oldPassword, newPassword) {
    throw new Error("Method 'changePassword()' must be implemented");
  }

  getDetailedUserProfile() {
    throw new Error("Method 'getDetailedUserProfile()' must be implemented");
  }

  updateUserProfile(updates) {
    throw new Error("Method 'updateUserProfile()' must be implemented");
  }
}

export function createAuthProvider(type, config) {
  console.log("type", type);
  
  try {
    return import("../src/provider/auth0-provider").then((module) => {
      return new module.default(config);
    }).catch(error => {
      console.error('Failed to create auth provider:', error);
      throw new Error(`Failed to load ${type} provider: ${error.message}`);
    });
  } catch (error) {
    console.error('Auth provider creation failed:', error);
    throw error;
  }
}
