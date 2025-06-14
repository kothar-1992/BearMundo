package com.bearmod.test;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.bearmod.core.security.BearMundoSecurity;

public class SecurityTestActivity extends Activity {
    private static final String TAG = "SecurityTest";
    private TextView statusText;
    private BearMundoSecurity security;

    static {
        System.loadLibrary("bearmundo_security");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_security_test);

        statusText = findViewById(R.id.status_text);
        security = new BearMundoSecurity();

        // Initialize security
        if (!security.initialize(this)) {
            showError("Failed to initialize security");
            return;
        }

        // Run security tests
        runSecurityTests();
    }

    private void runSecurityTests() {
        StringBuilder status = new StringBuilder();
        status.append("Security Test Results:\n\n");

        // Test environment validation
        status.append("Environment Validation: ");
        if (security.validateEnvironment()) {
            status.append("PASS\n");
        } else {
            status.append("FAIL - ").append(security.getLastError()).append("\n");
        }

        // Test integrity check
        status.append("Integrity Check: ");
        if (security.checkIntegrity()) {
            status.append("PASS\n");
        } else {
            status.append("FAIL - ").append(security.getLastError()).append("\n");
        }

        // Test authentication
        status.append("Authentication: ");
        if (security.verifyAuthentication()) {
            status.append("PASS\n");
        } else {
            status.append("FAIL - ").append(security.getLastError()).append("\n");
        }

        // Test memory protection
        status.append("Memory Protection: ");
        if (security.protectMemory()) {
            status.append("PASS\n");
        } else {
            status.append("FAIL - ").append(security.getLastError()).append("\n");
        }

        // Test container security
        status.append("Container Security: ");
        if (security.isContainerSecure()) {
            status.append("PASS\n");
        } else {
            status.append("FAIL - ").append(security.getLastError()).append("\n");
        }

        // Test stealth mode
        status.append("Stealth Mode: ");
        if (security.isStealthActive()) {
            status.append("PASS\n");
        } else {
            status.append("FAIL - ").append(security.getLastError()).append("\n");
        }

        // Update UI
        statusText.setText(status.toString());
    }

    private void showError(String message) {
        Log.e(TAG, message);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        statusText.setText("Error: " + message);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (security != null) {
            security.cleanup();
        }
    }
} 