package com.bearmod.security.test;

import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.bearmod.security.BearModSecurityAAR;
import org.json.JSONObject;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SecurityTestActivity extends AppCompatActivity {
    private static final String TAG = "SecurityTest";
    private TextView statusText;
    private Button testButton;
    private BearModSecurityAAR security;
    private ScheduledExecutorService executor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_security_test);

        statusText = findViewById(R.id.statusText);
        testButton = findViewById(R.id.testButton);

        // Initialize security
        security = BearModSecurityAAR.getInstance(this);
        security.setListener(new BearModSecurityAAR.SecurityEventListener() {
            @Override
            public void onSecurityStateChanged(JSONObject state) {
                runOnUiThread(() -> {
                    try {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Security State:\n");
                        sb.append("Hook Detected: ").append(state.optBoolean("hook_detected")).append("\n");
                        sb.append("Debugger Detected: ").append(state.optBoolean("debugger_detected")).append("\n");
                        sb.append("Emulator Detected: ").append(state.optBoolean("emulator_detected")).append("\n");
                        sb.append("Root Detected: ").append(state.optBoolean("root_detected")).append("\n");
                        statusText.setText(sb.toString());
                    } catch (Exception e) {
                        Log.e(TAG, "Error updating status", e);
                    }
                });
            }

            @Override
            public void onThreatDetected(String threatType, String details) {
                runOnUiThread(() -> {
                    String currentText = statusText.getText().toString();
                    statusText.setText(currentText + "\nThreat: " + threatType + " - " + details);
                });
            }

            @Override
            public void onOffsetUpdated(String name, long value) {
                runOnUiThread(() -> {
                    String currentText = statusText.getText().toString();
                    statusText.setText(currentText + "\nOffset Updated: " + name + " = 0x" + Long.toHexString(value));
                });
            }

            @Override
            public void onUpdateFailed(String error) {
                runOnUiThread(() -> {
                    String currentText = statusText.getText().toString();
                    statusText.setText(currentText + "\nUpdate Failed: " + error);
                });
            }
        });

        // Initialize with test KeyAuth token
        security.initialize("test_keyauth_token");

        // Add test offsets
        security.addGameOffset("GWorld", 0xE3732C0);
        security.addGameOffset("GName", 0xDD879E0);
        security.addGameOffset("VMatrix", 0xE34B570);
        security.addGameOffset("VWorld", 0xDE570C8);

        // Enable kernel protection
        security.enableKernelProtection();

        // Set up periodic tests
        executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(this::runSecurityTests, 0, 5, TimeUnit.SECONDS);

        // Test button
        testButton.setOnClickListener(v -> runSecurityTests());
    }

    private void runSecurityTests() {
        try {
            // Test offset retrieval
            long gworld = security.getGameOffset("GWorld");
            long gname = security.getGameOffset("GName");
            long vmatrix = security.getGameOffset("VMatrix");
            long vworld = security.getGameOffset("VWorld");

            // Test kernel protection
            boolean isProtected = security.isKernelProtected();

            runOnUiThread(() -> {
                StringBuilder sb = new StringBuilder();
                sb.append("Offset Tests:\n");
                sb.append("GWorld: 0x").append(Long.toHexString(gworld)).append("\n");
                sb.append("GName: 0x").append(Long.toHexString(gname)).append("\n");
                sb.append("VMatrix: 0x").append(Long.toHexString(vmatrix)).append("\n");
                sb.append("VWorld: 0x").append(Long.toHexString(vworld)).append("\n");
                sb.append("Kernel Protection: ").append(isProtected).append("\n");
                statusText.setText(sb.toString());
            });
        } catch (Exception e) {
            Log.e(TAG, "Error running security tests", e);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executor != null) {
            executor.shutdown();
        }
        if (security != null) {
            security.shutdown();
        }
    }
} 