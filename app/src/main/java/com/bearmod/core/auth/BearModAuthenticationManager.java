package com.bearmod.core.auth;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.container.BearModContainer;
import com.bearmod.core.container.BearModContainerManager;
import com.bearmod.core.config.BearModConfiguration;
import com.bearmod.targetapp.SignatureVerifier;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Central authentication manager for BearMod AAR library
 * Handles multi-layer authentication and container management
 */
public class BearModAuthenticationManager {
    
    private static final String TAG = "BearModAuth";
    private static BearModAuthenticationManager instance;
    
    private final BearModAuthenticator signatureAuth;
    private final TokenAuthenticator tokenAuth;
    private final CryptoAuthenticator cryptoAuth;
    private final KeyAuthIntegrator keyAuthIntegrator;
    private final BearModContainerManager containerManager;
    
    private final Map<String, AuthenticationSession> activeSessions;
    
    private BearModAuthenticationManager() {
        this.signatureAuth = new BearModAuthenticator();
        this.tokenAuth = new TokenAuthenticator();
        this.cryptoAuth = new CryptoAuthenticator();
        this.keyAuthIntegrator = new KeyAuthIntegrator();
        this.containerManager = new BearModContainerManager();
        this.activeSessions = new ConcurrentHashMap<>();
    }
    
    public static synchronized BearModAuthenticationManager getInstance() {
        if (instance == null) {
            instance = new BearModAuthenticationManager();
        }
        return instance;
    }
    
    /**
     * Perform complete authentication handshake for host application
     */
    public CompletableFuture<AuthenticationResult> authenticateHostApplication(
            Context context, 
            AuthenticationRequest request) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                Log.i(TAG, "Starting authentication for host: " + context.getPackageName());
                
                // Step 1: Verify host application signature
                AuthResult signatureResult = signatureAuth.authenticateHostApplication(context);
                if (!signatureResult.isAuthenticated()) {
                    Log.w(TAG, "Host application signature verification failed");
                    return AuthenticationResult.denied("Host application not authorized");
                }
                
                // Step 2: KeyAuth authentication (if enabled)
                KeyAuthResult keyAuthResult = null;
                if (request.isUseKeyAuth() && request.getUsername() != null) {
                    try {
                        keyAuthResult = keyAuthIntegrator.authenticateWithKeyAuth(
                            request.getUsername(),
                            request.getPassword(),
                            request.getHostContext()
                        ).get(); // Blocking call for simplicity
                    } catch (Exception e) {
                        Log.e(TAG, "KeyAuth authentication failed", e);
                        return AuthenticationResult.failure("KeyAuth authentication failed", e);
                    }
                }
                
                // Step 3: Token validation (if provided)
                TokenValidationResult tokenResult = null;
                if (request.getAuthToken() != null) {
                    tokenResult = tokenAuth.validateAuthToken(
                        request.getAuthToken(), 
                        request.getHostContext()
                    );
                }
                
                // Step 4: Generate cryptographic challenge
                ChallengeResult challengeResult = cryptoAuth.performChallengeResponse(
                    request.getHostContext()
                );
                
                // Step 5: Combine authentication results
                AuthenticationResult result = combineAuthenticationResults(
                    signatureResult,
                    keyAuthResult,
                    tokenResult,
                    challengeResult,
                    request
                );
                
                // Step 6: Create container if authentication successful
                if (result.isAuthenticated()) {
                    BearModContainer container = createContainerForHost(context, request, result);
                    result.setContainer(container);
                    
                    // Store active session
                    AuthenticationSession session = new AuthenticationSession(
                        result.getSessionToken(),
                        result.getHostContext(),
                        container,
                        result.getExpiresAt()
                    );
                    activeSessions.put(result.getSessionToken(), session);
                }
                
                Log.i(TAG, "Authentication completed for host: " + context.getPackageName() + 
                          ", Result: " + (result.isAuthenticated() ? "SUCCESS" : "FAILED"));
                
                return result;
                
            } catch (Exception e) {
                Log.e(TAG, "Authentication process failed", e);
                return AuthenticationResult.failure("Authentication process failed", e);
            }
        });
    }
    
    /**
     * Validate existing session token
     */
    public SessionValidationResult validateSession(String sessionToken) {
        AuthenticationSession session = activeSessions.get(sessionToken);
        
        if (session == null) {
            return SessionValidationResult.invalid("Session not found");
        }
        
        if (session.isExpired()) {
            activeSessions.remove(sessionToken);
            return SessionValidationResult.invalid("Session expired");
        }
        
        return SessionValidationResult.valid(session);
    }
    
    /**
     * Get container for authenticated session
     */
    public BearModContainer getContainerForSession(String sessionToken) {
        AuthenticationSession session = activeSessions.get(sessionToken);
        return session != null ? session.getContainer() : null;
    }
    
    /**
     * Invalidate session and cleanup container
     */
    public void invalidateSession(String sessionToken) {
        AuthenticationSession session = activeSessions.remove(sessionToken);
        if (session != null) {
            containerManager.destroyContainer(session.getContainer().getId());
            Log.i(TAG, "Session invalidated: " + sessionToken);
        }
    }
    
    /**
     * Create isolated container for authenticated host
     */
    private BearModContainer createContainerForHost(
            Context context,
            AuthenticationRequest request,
            AuthenticationResult authResult) {
        
        ContainerConfig config = ContainerConfig.builder()
            .setIsolationLevel(determineIsolationLevel(authResult))
            .setSecurityPolicy(createSecurityPolicy(authResult))
            .setConfiguration(request.getConfiguration())
            .build();
        
        return containerManager.createContainer(authResult.getHostContext(), config);
    }
    
    /**
     * Combine multiple authentication results into final result
     */
    private AuthenticationResult combineAuthenticationResults(
            AuthResult signatureResult,
            KeyAuthResult keyAuthResult,
            TokenValidationResult tokenResult,
            ChallengeResult challengeResult,
            AuthenticationRequest request) {
        
        AuthLevel authLevel = determineAuthLevel(signatureResult, keyAuthResult, tokenResult);
        Set<BearModPermission> permissions = combinePermissions(keyAuthResult, tokenResult);
        
        if (authLevel == AuthLevel.DENIED) {
            return AuthenticationResult.denied("Authentication failed");
        }
        
        String sessionToken = generateSessionToken(request.getHostContext(), permissions);
        long expiresAt = calculateSessionExpiry(keyAuthResult, tokenResult);
        
        return AuthenticationResult.builder()
            .setAuthenticated(true)
            .setAuthLevel(authLevel)
            .setPermissions(permissions)
            .setHostContext(request.getHostContext())
            .setSessionToken(sessionToken)
            .setChallenge(challengeResult)
            .setExpiresAt(expiresAt)
            .build();
    }
    
    private AuthLevel determineAuthLevel(
            AuthResult signatureResult,
            KeyAuthResult keyAuthResult,
            TokenValidationResult tokenResult) {
        
        if (!signatureResult.isAuthenticated()) {
            return AuthLevel.DENIED;
        }
        
        if (keyAuthResult != null && keyAuthResult.isSuccess()) {
            return AuthLevel.PREMIUM; // KeyAuth provides premium access
        }
        
        if (tokenResult != null && tokenResult.isValid()) {
            return AuthLevel.STANDARD; // Token provides standard access
        }
        
        return AuthLevel.BASIC; // Signature only provides basic access
    }
    
    private Set<BearModPermission> combinePermissions(
            KeyAuthResult keyAuthResult,
            TokenValidationResult tokenResult) {
        
        Set<BearModPermission> permissions = new HashSet<>();
        
        if (keyAuthResult != null && keyAuthResult.isSuccess()) {
            permissions.addAll(keyAuthResult.getPermissions());
        }
        
        if (tokenResult != null && tokenResult.isValid()) {
            permissions.addAll(tokenResult.getPermissions());
        }
        
        // Default basic permissions for signature-only auth
        if (permissions.isEmpty()) {
            permissions.add(BearModPermission.BASIC_HOOKS);
            permissions.add(BearModPermission.SIGNATURE_VERIFICATION);
        }
        
        return permissions;
    }
    
    private String generateSessionToken(HostContext hostContext, Set<BearModPermission> permissions) {
        // Generate secure session token
        String data = hostContext.getHostId() + ":" + 
                     hostContext.getPackageName() + ":" + 
                     System.currentTimeMillis() + ":" +
                     permissions.hashCode();
        
        return CryptoUtils.sha256Hash(data);
    }
    
    private long calculateSessionExpiry(KeyAuthResult keyAuthResult, TokenValidationResult tokenResult) {
        long defaultExpiry = System.currentTimeMillis() + (24 * 60 * 60 * 1000); // 24 hours
        
        if (keyAuthResult != null && keyAuthResult.getExpiresAt() > 0) {
            return Math.min(defaultExpiry, keyAuthResult.getExpiresAt());
        }
        
        if (tokenResult != null && tokenResult.getExpiresAt() != null) {
            return Math.min(defaultExpiry, tokenResult.getExpiresAt().getTime());
        }
        
        return defaultExpiry;
    }
    
    private IsolationLevel determineIsolationLevel(AuthenticationResult authResult) {
        switch (authResult.getAuthLevel()) {
            case PREMIUM:
                return IsolationLevel.FULL;
            case STANDARD:
                return IsolationLevel.MEDIUM;
            case BASIC:
            default:
                return IsolationLevel.BASIC;
        }
    }
    
    private SecurityPolicy createSecurityPolicy(AuthenticationResult authResult) {
        return SecurityPolicy.builder()
            .setPermissions(authResult.getPermissions())
            .setAuthLevel(authResult.getAuthLevel())
            .setRestrictedPackages(getRestrictedPackages(authResult))
            .setAllowedHookTargets(getAllowedHookTargets(authResult))
            .build();
    }
    
    private Set<String> getRestrictedPackages(AuthenticationResult authResult) {
        // Define restricted packages based on auth level
        Set<String> restricted = new HashSet<>();
        
        if (authResult.getAuthLevel() == AuthLevel.BASIC) {
            restricted.add("com.android.system");
            restricted.add("android.system");
        }
        
        return restricted;
    }
    
    private Set<String> getAllowedHookTargets(AuthenticationResult authResult) {
        // Define allowed hook targets based on permissions
        Set<String> allowed = new HashSet<>();
        
        if (authResult.getPermissions().contains(BearModPermission.SSL_BYPASS)) {
            allowed.add("javax.net.ssl.*");
            allowed.add("okhttp3.*");
        }
        
        if (authResult.getPermissions().contains(BearModPermission.ROOT_BYPASS)) {
            allowed.add("java.lang.Runtime");
            allowed.add("java.lang.ProcessBuilder");
        }
        
        return allowed;
    }
}
