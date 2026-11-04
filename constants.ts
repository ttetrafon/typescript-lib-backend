export const ABSOLUTE_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days; measured from login
export const ACCESS_TOKEN_TTL_S = 10 * 60; // 10 minutes
export const DPOP_IAT_TOLERANCE_S = 60; // accepted clock skew for a DPoP proof's iat, in either direction
export const IDLE_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days; measured from the last refresh
export const JTI_WINDOW_MS = 120 * 1000; // must be >= the accepted DPoP iat window (both directions)
export const JWT_COOKIE_NAME = 'token';
export const JWT_DURATION_S = 7 * 24 * 60 * 60; // 7 days
export const MIDDLEWARE_AUTH_DATA_KEY = "auth";
export const PASSWORD_HASH_KEY = 'auth:password_hash';
export const REFRESH_COOKIE_NAME = 'refresh_token';
export const REFRESH_GRACE_MS = 15 * 1000; // the previous refresh token stays usable this long after a rotation
export const SESSION_COOKIE_NAME = 'token';
export const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
export const SESSION_PREFIX = 'session:';
