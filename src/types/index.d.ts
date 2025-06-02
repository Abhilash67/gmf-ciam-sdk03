// src/types/index.d.ts
export interface AuthConfig {
  domain: string;
  clientId: string;
  audience?: string;
  redirectUri?: string;
  scope?: string;
  responseType?: string;
  cacheLocation?: string;
  clientSecret?: string; // For server-side operations
  managementApiAudience?: string;
}

export interface OktaConfig {
  orgUrl: string;
  clientId: string;
  redirectUri?: string;
  scopes?: string[];
}

export interface UserProfile {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  address?: any;
  user_metadata?: Record<string, any>;
  app_metadata?: Record<string, any>;
  [key: string]: any;
}

// Error types
export interface AuthError extends Error {
  name: string;
  code: string;
  details: Record<string, any>;
  timestamp: string;
}

export type ErrorType = 
  | 'AuthenticationError'
  | 'ConfigurationError'
  | 'NetworkError'
  | 'TokenError'
  | 'ValidationError'
  | 'OperationError';

export type ErrorCallback = (error: AuthError) => void;

// Auth status and validation types
export interface AuthStatus {
  authenticated: boolean;
  hasAccessToken: boolean;
  hasRefreshToken: boolean;
  hasUserProfile: boolean;
  tokenExpired: boolean | null;
  expiresAt: string | null;
  lastError?: AuthError | null;
}

export interface AuthValidationResult {
  valid: boolean;
  reason?: string;
  error?: string;
}

// Profile update types
export type ProfileUpdates = Partial<Pick<UserProfile, 
  | 'name' 
  | 'given_name' 
  | 'family_name' 
  | 'middle_name' 
  | 'nickname'
  | 'preferred_username' 
  | 'profile' 
  | 'picture' 
  | 'website' 
  | 'gender'
  | 'birthdate' 
  | 'zoneinfo' 
  | 'locale' 
  | 'phone_number' 
  | 'address'
  | 'user_metadata' 
  | 'app_metadata'
>>;

export interface AuthProvider {
  // Core authentication methods
  login(): Promise<void>;
  logout(): void;
  getUserProfile(forceRefresh?: boolean): Promise<UserProfile>;
  isAuthenticated(): boolean | Promise<boolean>;
  getAccessToken(): string | Promise<string>;
  refreshToken(): Promise<boolean>;
  
  // Password management
  resetPassword(email: string): Promise<string>;
  changePassword(oldPassword: string, newPassword: string): Promise<string>;
  
  // Profile management
  getDetailedUserProfile(): Promise<UserProfile>;
  updateUserProfile(updates: ProfileUpdates): Promise<UserProfile>;
  
  // Error handling methods
  createError(type: ErrorType, message: string, code: string, details?: Record<string, any>): AuthError;
  createAuthError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createConfigError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createNetworkError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createTokenError(message: string, code?: string, details?: Record<string, any>): AuthError;
  createValidationError(message: string, code?: string, details?: Record<string, any>): AuthError;
  
  getLastError(): AuthError | null;
  clearError(): void;
  onError(callback: ErrorCallback): void;
  removeErrorCallback(callback: ErrorCallback): void;
  
  // Utility methods
  handleAsync<T>(operation: () => Promise<T>, errorContext?: string): Promise<T>;
  validateAuthState(): Promise<AuthValidationResult>;
  getAuthStatus(): AuthStatus;
}

export interface GMFCIAMAuth {
  createAuthProvider(type: 'auth0' | 'okta', config: AuthConfig | OktaConfig): Promise<AuthProvider>;
}

// Error code type - using string literal union instead of const object
export type AuthErrorCode = 
  // Configuration errors
  | 'MISSING_CONFIG'
  | 'INCOMPLETE_CONFIG'
  | 'INVALID_DOMAIN'
  | 'LOGIN_CONFIG_ERROR'
  
  // Authentication errors
  | 'NOT_AUTHENTICATED'
  | 'INVALID_STATE'
  | 'MISSING_AUTH_CODE'
  | 'INCORRECT_PASSWORD'
  | 'USER_NOT_FOUND'
  | 'INSUFFICIENT_PERMISSIONS'
  | 'INVALID_PROFILE_DATA'
  
  // Token errors
  | 'TOKEN_EXPIRED'
  | 'INVALID_REFRESH_TOKEN'
  | 'NO_REFRESH_TOKEN'
  | 'MISSING_REFRESH_TOKEN'
  | 'INVALID_ACCESS_TOKEN'
  | 'NO_ACCESS_TOKEN'
  | 'MISSING_ACCESS_TOKEN'
  | 'NO_MANAGEMENT_TOKEN'
  | 'INVALID_MANAGEMENT_TOKEN'
  | 'INVALID_REFRESH_RESPONSE'
  | 'INVALID_MGMT_TOKEN_RESPONSE'
  
  // Network errors
  | 'NETWORK_ERROR'
  | 'TOKEN_EXCHANGE_ERROR'
  | 'TOKEN_REFRESH_ERROR'
  | 'PASSWORD_RESET_ERROR'
  | 'PASSWORD_VERIFY_ERROR'
  | 'PASSWORD_UPDATE_ERROR'
  | 'PROFILE_FETCH_ERROR'
  | 'DETAILED_PROFILE_ERROR'
  | 'PROFILE_UPDATE_ERROR'
  | 'MGMT_TOKEN_ERROR'
  | 'MGMT_API_ERROR'
  
  // Validation errors
  | 'MISSING_EMAIL'
  | 'INVALID_EMAIL_FORMAT'
  | 'MISSING_PASSWORDS'
  | 'INVALID_PASSWORD_TYPE'
  | 'PASSWORD_TOO_SHORT'
  | 'PASSWORD_UNCHANGED'
  | 'INVALID_UPDATES_FORMAT'
  | 'EMPTY_UPDATES'
  | 'RESTRICTED_FIELD'
  | 'INVALID_PHONE_FORMAT'
  
  // URL and redirect errors
  | 'INVALID_AUTH_URL'
  | 'INVALID_LOGOUT_URL'
  
  // Generic operation errors
  | 'OPERATION_ERROR'
  | 'CALLBACK_ERROR'
  | 'LOGIN_INIT_ERROR'
  | 'RESET_REQUEST_ERROR'
  | 'PASSWORD_CHANGE_ERROR'
  | 'PROFILE_RETRIEVAL_ERROR'
  | 'DETAILED_PROFILE_RETRIEVAL_ERROR'
  | 'PROFILE_UPDATE_OPERATION_ERROR'
  | 'TOKEN_RETRIEVAL_ERROR'
  | 'TOKEN_REFRESH_FAILED'
  | 'LOGOUT_ERROR'
  | 'VERIFY_REQUEST_ERROR'
  | 'REFRESH_OPERATION_ERROR';

// Helper object for error codes (can be used in implementation files, not declaration files)
declare const AuthErrorCodes: {
  readonly MISSING_CONFIG: 'MISSING_CONFIG';
  readonly INCOMPLETE_CONFIG: 'INCOMPLETE_CONFIG';
  readonly INVALID_DOMAIN: 'INVALID_DOMAIN';
  readonly LOGIN_CONFIG_ERROR: 'LOGIN_CONFIG_ERROR';
  readonly NOT_AUTHENTICATED: 'NOT_AUTHENTICATED';
  readonly INVALID_STATE: 'INVALID_STATE';
  readonly MISSING_AUTH_CODE: 'MISSING_AUTH_CODE';
  readonly INCORRECT_PASSWORD: 'INCORRECT_PASSWORD';
  readonly USER_NOT_FOUND: 'USER_NOT_FOUND';
  readonly INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS';
  readonly INVALID_PROFILE_DATA: 'INVALID_PROFILE_DATA';
  readonly TOKEN_EXPIRED: 'TOKEN_EXPIRED';
  readonly INVALID_REFRESH_TOKEN: 'INVALID_REFRESH_TOKEN';
  readonly NO_REFRESH_TOKEN: 'NO_REFRESH_TOKEN';
  readonly MISSING_REFRESH_TOKEN: 'MISSING_REFRESH_TOKEN';
  readonly INVALID_ACCESS_TOKEN: 'INVALID_ACCESS_TOKEN';
  readonly NO_ACCESS_TOKEN: 'NO_ACCESS_TOKEN';
  readonly MISSING_ACCESS_TOKEN: 'MISSING_ACCESS_TOKEN';
  readonly NO_MANAGEMENT_TOKEN: 'NO_MANAGEMENT_TOKEN';
  readonly INVALID_MANAGEMENT_TOKEN: 'INVALID_MANAGEMENT_TOKEN';
  readonly INVALID_REFRESH_RESPONSE: 'INVALID_REFRESH_RESPONSE';
  readonly INVALID_MGMT_TOKEN_RESPONSE: 'INVALID_MGMT_TOKEN_RESPONSE';
  readonly NETWORK_ERROR: 'NETWORK_ERROR';
  readonly TOKEN_EXCHANGE_ERROR: 'TOKEN_EXCHANGE_ERROR';
  readonly TOKEN_REFRESH_ERROR: 'TOKEN_REFRESH_ERROR';
  readonly PASSWORD_RESET_ERROR: 'PASSWORD_RESET_ERROR';
  readonly PASSWORD_VERIFY_ERROR: 'PASSWORD_VERIFY_ERROR';
  readonly PASSWORD_UPDATE_ERROR: 'PASSWORD_UPDATE_ERROR';
  readonly PROFILE_FETCH_ERROR: 'PROFILE_FETCH_ERROR';
  readonly DETAILED_PROFILE_ERROR: 'DETAILED_PROFILE_ERROR';
  readonly PROFILE_UPDATE_ERROR: 'PROFILE_UPDATE_ERROR';
  readonly MGMT_TOKEN_ERROR: 'MGMT_TOKEN_ERROR';
  readonly MGMT_API_ERROR: 'MGMT_API_ERROR';
  readonly MISSING_EMAIL: 'MISSING_EMAIL';
  readonly INVALID_EMAIL_FORMAT: 'INVALID_EMAIL_FORMAT';
  readonly MISSING_PASSWORDS: 'MISSING_PASSWORDS';
  readonly INVALID_PASSWORD_TYPE: 'INVALID_PASSWORD_TYPE';
  readonly PASSWORD_TOO_SHORT: 'PASSWORD_TOO_SHORT';
  readonly PASSWORD_UNCHANGED: 'PASSWORD_UNCHANGED';
  readonly INVALID_UPDATES_FORMAT: 'INVALID_UPDATES_FORMAT';
  readonly EMPTY_UPDATES: 'EMPTY_UPDATES';
  readonly RESTRICTED_FIELD: 'RESTRICTED_FIELD';
  readonly INVALID_PHONE_FORMAT: 'INVALID_PHONE_FORMAT';
  readonly INVALID_AUTH_URL: 'INVALID_AUTH_URL';
  readonly INVALID_LOGOUT_URL: 'INVALID_LOGOUT_URL';
  readonly OPERATION_ERROR: 'OPERATION_ERROR';
  readonly CALLBACK_ERROR: 'CALLBACK_ERROR';
  readonly LOGIN_INIT_ERROR: 'LOGIN_INIT_ERROR';
  readonly RESET_REQUEST_ERROR: 'RESET_REQUEST_ERROR';
  readonly PASSWORD_CHANGE_ERROR: 'PASSWORD_CHANGE_ERROR';
  readonly PROFILE_RETRIEVAL_ERROR: 'PROFILE_RETRIEVAL_ERROR';
  readonly DETAILED_PROFILE_RETRIEVAL_ERROR: 'DETAILED_PROFILE_RETRIEVAL_ERROR';
  readonly PROFILE_UPDATE_OPERATION_ERROR: 'PROFILE_UPDATE_OPERATION_ERROR';
  readonly TOKEN_RETRIEVAL_ERROR: 'TOKEN_RETRIEVAL_ERROR';
  readonly TOKEN_REFRESH_FAILED: 'TOKEN_REFRESH_FAILED';
  readonly LOGOUT_ERROR: 'LOGOUT_ERROR';
  readonly VERIFY_REQUEST_ERROR: 'VERIFY_REQUEST_ERROR';
  readonly REFRESH_OPERATION_ERROR: 'REFRESH_OPERATION_ERROR';
};

export { AuthErrorCodes };

declare const gmfCiamAuth: GMFCIAMAuth;
export default gmfCiamAuth;
