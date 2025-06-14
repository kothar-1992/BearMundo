/**
 * Bear-Mod SSL Pinning Bypass
 * 
 * This script bypasses SSL certificate pinning by hooking
 * various certificate validation methods and making them
 * always return true/success.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] SSL Pinning Bypass Loaded");

// Enable stealth mode by loading the anti-detection module
try {
    const antiDetection = require('../stealth/anti_detection.js');
    antiDetection.setupAntiDetection();
    console.log("[*] Anti-detection measures enabled");
} catch (e) {
    console.log("[!] Anti-detection module not available: " + e);
}

Java.perform(function() {
    console.log("[*] Java VM initialized");
    
    // Bypass X509TrustManager certificate verification
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        
        X509TrustManager.checkClientTrusted.implementation = function (chain, authType) {
            console.log("[+] X509TrustManager.checkClientTrusted bypassed");
        };

        X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
            console.log("[+] X509TrustManager.checkServerTrusted bypassed");
        };
        
        console.log("[+] X509TrustManager hooks installed");
    } catch (e) {
        console.log("[-] X509TrustManager not found: " + e);
    }
    
    // Bypass OkHttp3 certificate pinning
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 CertificatePinner.check() bypassed for " + hostname);
            return;
        };
        
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 CertificatePinner.check() bypassed for " + hostname);
            return;
        };
        
        console.log("[+] OkHttp3 CertificatePinner hooks installed");
    } catch (e) {
        console.log("[-] OkHttp3 CertificatePinner not found: " + e);
    }
    
    // Bypass TrustManagerImpl certificate verification
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] TrustManagerImpl.verifyChain() bypassed for " + host);
            return untrustedChain;
        };
        
        console.log("[+] TrustManagerImpl hooks installed");
    } catch (e) {
        console.log("[-] TrustManagerImpl not found: " + e);
    }
    
    // Bypass hostname verification
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        HostnameVerifier.verify.implementation = function(hostname, session) {
            console.log("[+] Hostname verification bypassed for: " + hostname);
            return true;
        };
        
        console.log("[+] HostnameVerifier hooks installed");
    } catch (e) {
        console.log("[-] HostnameVerifier not found: " + e);
    }
    
    // Bypass Android WebViewClient certificate verification
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        
        WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
            console.log("[+] WebViewClient.onReceivedSslError() bypassed");
            sslErrorHandler.proceed();
            return;
        };
        
        console.log("[+] WebViewClient hooks installed");
    } catch (e) {
        console.log("[-] WebViewClient not found: " + e);
    }
    
    console.log("[*] SSL pinning bypass complete");
});

console.log("[*] SSL pinning bypass script initialized");
