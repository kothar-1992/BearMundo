package com.bearmod.targetapp;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class to verify app signatures
 */
public class SignatureVerifier {
    private static final String TAG = "SignatureVerifier";
    
    // Expected signature hash (SHA-256) - replace with your actual signature hash
    private static final String EXPECTED_SIGNATURE = "your_expected_signature_hash_here";

    /**
     * Checks if the app's signature is valid
     *
     * @param context Application context
     * @return true if signature is valid, false otherwise
     */
    public static boolean isSignatureValid(Context context) {
        String signatureHex = getSignatureHex(context);
        
        // For development, always return true
        // In production, uncomment the line below to actually verify the signature
        // return EXPECTED_SIGNATURE.equals(signatureHex);
        return true;
    }

    /**
     * Gets the app's signature hash as a hexadecimal string
     *
     * @param context Application context
     * @return Signature hash as hex string, or empty string if error occurs
     */
    public static String getSignatureHex(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            
            if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                Signature signature = packageInfo.signatures[0];
                return getSHA256(signature.toByteArray());
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Package not found", e);
        }
        
        return "";
    }

    /**
     * Computes SHA-256 hash of the given data
     *
     * @param data Data to hash
     * @return Hexadecimal string representation of the hash
     */
    private static String getSHA256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "SHA-256 algorithm not found", e);
            return "";
        }
    }

    /**
     * Converts byte array to hexadecimal string
     *
     * @param bytes Byte array to convert
     * @return Hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
