package com.bearmod.core.auth;

import com.bearmod.core.config.BearModConfiguration;
import com.bearmod.core.container.BearModContainer;

import java.util.Date;
import java.util.Set;
import java.util.HashSet;

/**
 * Authentication data models and enums for BearMod AAR
 */

// Authentication request from host application
public class AuthenticationRequest {
    private final HostContext hostContext;
    private final BearModConfiguration configuration;
    private final String username;
    private final String password;
    private final String authToken;
    private final boolean useKeyAuth;
    private final boolean requireChallenge;
    
    private AuthenticationRequest(Builder builder) {
        this.hostContext = builder.hostContext;
        this.configuration = builder.configuration;
        this.username = builder.username;
        this.password = builder.password;
        this.authToken = builder.authToken;
        this.useKeyAuth = builder.useKeyAuth;
        this.requireChallenge = builder.requireChallenge;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public HostContext getHostContext() { return hostContext; }
    public BearModConfiguration getConfiguration() { return configuration; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getAuthToken() { return authToken; }
    public boolean isUseKeyAuth() { return useKeyAuth; }
    public boolean isRequireChallenge() { return requireChallenge; }
    
    public static class Builder {
        private HostContext hostContext;
        private BearModConfiguration configuration;
        private String username;
        private String password;
        private String authToken;
        private boolean useKeyAuth = false;
        private boolean requireChallenge = true;
        
        public Builder setHostContext(HostContext hostContext) {
            this.hostContext = hostContext;
            return this;
        }
        
        public Builder setConfiguration(BearModConfiguration configuration) {
            this.configuration = configuration;
            return this;
        }
        
        public Builder setKeyAuthCredentials(String username, String password) {
            this.username = username;
            this.password = password;
            this.useKeyAuth = true;
            return this;
        }
        
        public Builder setAuthToken(String authToken) {
            this.authToken = authToken;
            return this;
        }
        
        public Builder setRequireChallenge(boolean requireChallenge) {
            this.requireChallenge = requireChallenge;
            return this;
        }
        
        public AuthenticationRequest build() {
            if (hostContext == null) {
                throw new IllegalArgumentException("HostContext is required");
            }
            return new AuthenticationRequest(this);
        }
    }
}

// Host application context information
public class HostContext {
    private final String hostId;
    private final String packageName;
    private final String appName;
    private final String version;
    private final String signature;
    private final String secretKey;
    
    public HostContext(String hostId, String packageName, String appName, 
                      String version, String signature, String secretKey) {
        this.hostId = hostId;
        this.packageName = packageName;
        this.appName = appName;
        this.version = version;
        this.signature = signature;
        this.secretKey = secretKey;
    }
    
    // Getters
    public String getHostId() { return hostId; }
    public String getPackageName() { return packageName; }
    public String getAppName() { return appName; }
    public String getVersion() { return version; }
    public String getSignature() { return signature; }
    public String getSecretKey() { return secretKey; }
}

// Authentication result
public class AuthenticationResult {
    private final boolean authenticated;
    private final AuthLevel authLevel;
    private final Set<BearModPermission> permissions;
    private final HostContext hostContext;
    private final String sessionToken;
    private final ChallengeResult challenge;
    private final long expiresAt;
    private final String errorMessage;
    private final Exception exception;
    private BearModContainer container;
    
    private AuthenticationResult(Builder builder) {
        this.authenticated = builder.authenticated;
        this.authLevel = builder.authLevel;
        this.permissions = builder.permissions;
        this.hostContext = builder.hostContext;
        this.sessionToken = builder.sessionToken;
        this.challenge = builder.challenge;
        this.expiresAt = builder.expiresAt;
        this.errorMessage = builder.errorMessage;
        this.exception = builder.exception;
    }
    
    public static AuthenticationResult denied(String message) {
        return new Builder()
            .setAuthenticated(false)
            .setAuthLevel(AuthLevel.DENIED)
            .setErrorMessage(message)
            .build();
    }
    
    public static AuthenticationResult failure(String message, Exception exception) {
        return new Builder()
            .setAuthenticated(false)
            .setAuthLevel(AuthLevel.DENIED)
            .setErrorMessage(message)
            .setException(exception)
            .build();
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public boolean isAuthenticated() { return authenticated; }
    public AuthLevel getAuthLevel() { return authLevel; }
    public Set<BearModPermission> getPermissions() { return permissions; }
    public HostContext getHostContext() { return hostContext; }
    public String getSessionToken() { return sessionToken; }
    public ChallengeResult getChallenge() { return challenge; }
    public long getExpiresAt() { return expiresAt; }
    public String getErrorMessage() { return errorMessage; }
    public Exception getException() { return exception; }
    public BearModContainer getContainer() { return container; }
    
    public void setContainer(BearModContainer container) {
        this.container = container;
    }
    
    public static class Builder {
        private boolean authenticated = false;
        private AuthLevel authLevel = AuthLevel.DENIED;
        private Set<BearModPermission> permissions = new HashSet<>();
        private HostContext hostContext;
        private String sessionToken;
        private ChallengeResult challenge;
        private long expiresAt;
        private String errorMessage;
        private Exception exception;
        
        public Builder setAuthenticated(boolean authenticated) {
            this.authenticated = authenticated;
            return this;
        }
        
        public Builder setAuthLevel(AuthLevel authLevel) {
            this.authLevel = authLevel;
            return this;
        }
        
        public Builder setPermissions(Set<BearModPermission> permissions) {
            this.permissions = permissions;
            return this;
        }
        
        public Builder setHostContext(HostContext hostContext) {
            this.hostContext = hostContext;
            return this;
        }
        
        public Builder setSessionToken(String sessionToken) {
            this.sessionToken = sessionToken;
            return this;
        }
        
        public Builder setChallenge(ChallengeResult challenge) {
            this.challenge = challenge;
            return this;
        }
        
        public Builder setExpiresAt(long expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }
        
        public Builder setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }
        
        public Builder setException(Exception exception) {
            this.exception = exception;
            return this;
        }
        
        public AuthenticationResult build() {
            return new AuthenticationResult(this);
        }
    }
}

// Authentication levels
public enum AuthLevel {
    DENIED,     // No access
    BASIC,      // Signature verification only
    STANDARD,   // Token-based authentication
    PREMIUM,    // KeyAuth authentication
    ENTERPRISE  // Full enterprise features
}

// BearMod permissions
public enum BearModPermission {
    // Basic permissions
    BASIC_HOOKS,
    SIGNATURE_VERIFICATION,
    
    // Security bypass permissions
    SSL_BYPASS,
    ROOT_BYPASS,
    SIGNATURE_BYPASS,
    FRIDA_DETECTION_BYPASS,
    
    // Advanced features
    ADVANCED_HOOKS,
    CUSTOM_HOOKS,
    REAL_TIME_ANALYSIS,
    SECURITY_MONITORING,
    
    // Administrative permissions
    CONTAINER_MANAGEMENT,
    PLUGIN_MANAGEMENT,
    CONFIGURATION_OVERRIDE
}

// Authentication session
public class AuthenticationSession {
    private final String sessionToken;
    private final HostContext hostContext;
    private final BearModContainer container;
    private final long expiresAt;
    private final long createdAt;
    
    public AuthenticationSession(String sessionToken, HostContext hostContext, 
                               BearModContainer container, long expiresAt) {
        this.sessionToken = sessionToken;
        this.hostContext = hostContext;
        this.container = container;
        this.expiresAt = expiresAt;
        this.createdAt = System.currentTimeMillis();
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAt;
    }
    
    public long getRemainingTime() {
        return Math.max(0, expiresAt - System.currentTimeMillis());
    }
    
    // Getters
    public String getSessionToken() { return sessionToken; }
    public HostContext getHostContext() { return hostContext; }
    public BearModContainer getContainer() { return container; }
    public long getExpiresAt() { return expiresAt; }
    public long getCreatedAt() { return createdAt; }
}

// Session validation result
public class SessionValidationResult {
    private final boolean valid;
    private final String errorMessage;
    private final AuthenticationSession session;
    private final long remainingTime;
    
    private SessionValidationResult(boolean valid, String errorMessage, 
                                  AuthenticationSession session, long remainingTime) {
        this.valid = valid;
        this.errorMessage = errorMessage;
        this.session = session;
        this.remainingTime = remainingTime;
    }
    
    public static SessionValidationResult valid(AuthenticationSession session) {
        return new SessionValidationResult(true, null, session, session.getRemainingTime());
    }
    
    public static SessionValidationResult invalid(String errorMessage) {
        return new SessionValidationResult(false, errorMessage, null, 0);
    }
    
    // Getters
    public boolean isValid() { return valid; }
    public String getErrorMessage() { return errorMessage; }
    public AuthenticationSession getSession() { return session; }
    public long getRemainingTime() { return remainingTime; }
}
