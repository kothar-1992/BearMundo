package com.bearmod.targetapp;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Button;
import android.view.View;
import android.util.Log;
import android.widget.Toast;

// Import SignatureVerifier from the same package
import com.bearmod.targetapp.SignatureVerifier;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    // Load the native library
    static {
        try {
            System.loadLibrary("bearmod");
            Log.d(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
        }
    }

    // Native methods
    public native String checkNativeSetup();
    public native String getNativeVersion();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Get the TextView
        TextView textView = findViewById(R.id.sample_text);

        // Check signature
        boolean isSignatureValid = SignatureVerifier.isSignatureValid(this);
        String signatureHash = SignatureVerifier.getSignatureHex(this);

        // Display signature status
        String message = "Signature Status: " + (isSignatureValid ? "Valid" : "Invalid") +
                         "\n\nSignature Hash:\n" + signatureHash;

        textView.setText(message);

        // Log signature information
        Log.d(TAG, "Signature valid: " + isSignatureValid);
        Log.d(TAG, "Signature hash: " + signatureHash);

        // Add button to check native setup
        Button checkNativeButton = findViewById(R.id.check_native_button);
        if (checkNativeButton != null) {
            checkNativeButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        String nativeStatus = checkNativeSetup();
                        String nativeVersion = getNativeVersion();
                        Toast.makeText(MainActivity.this,
                                      "Native Status: " + nativeStatus + "\nVersion: " + nativeVersion,
                                      Toast.LENGTH_LONG).show();
                        Log.d(TAG, "Native Status: " + nativeStatus);
                        Log.d(TAG, "Native Version: " + nativeVersion);
                    } catch (UnsatisfiedLinkError e) {
                        Toast.makeText(MainActivity.this,
                                      "Native method not found: " + e.getMessage(),
                                      Toast.LENGTH_LONG).show();
                        Log.e(TAG, "Native method error", e);
                    }
                }
            });
        }
    }
}
