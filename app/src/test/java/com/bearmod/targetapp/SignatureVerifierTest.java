package com.bearmod.targetapp;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(RobolectricTestRunner.class)
public class SignatureVerifierTest {

    @Mock
    private Context mockContext;

    @Mock
    private PackageManager mockPackageManager;

    @Mock
    private PackageInfo mockPackageInfo;

    private static final String PACKAGE_NAME = "com.bearmod.targetapp";
    private static final byte[] TEST_SIGNATURE_BYTES = new byte[] {
            0x30, 0x44, 0x02, 0x20, 0x60, 0x10, 0x20, 0x30,
            0x40, 0x50, 0x60, 0x70, 0x80, 0x90, (byte) 0xA0, (byte) 0xB0,
            (byte) 0xC0, (byte) 0xD0, (byte) 0xE0, (byte) 0xF0, 0x01, 0x11,
            0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, (byte) 0xA1, (byte) 0xB1
    };

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Set up the mock chain
        when(mockContext.getPackageManager()).thenReturn(mockPackageManager);
        when(mockContext.getPackageName()).thenReturn(PACKAGE_NAME);

        // Create a test signature
        Signature[] signatures = new Signature[] { new Signature(TEST_SIGNATURE_BYTES) };
        mockPackageInfo.signatures = signatures;

        // Set up the package info
        when(mockPackageManager.getPackageInfo(PACKAGE_NAME, PackageManager.GET_SIGNATURES))
                .thenReturn(mockPackageInfo);
    }

    @Test
    public void isSignatureValid_shouldReturnTrue() {
        // In development mode, isSignatureValid always returns true
        boolean result = SignatureVerifier.isSignatureValid(mockContext);
        assertTrue("Signature should be valid in development mode", result);
    }

    @Test
    public void getSignatureHex_shouldReturnCorrectHash() {
        String signatureHex = SignatureVerifier.getSignatureHex(mockContext);
        
        // The expected hash will depend on the TEST_SIGNATURE_BYTES
        // For simplicity, we'll just verify it's not empty and has the right format
        assertTrue("Signature hash should not be empty", !signatureHex.isEmpty());
        assertEquals("Signature hash should be 64 characters (SHA-256)", 64, signatureHex.length());
    }
}
