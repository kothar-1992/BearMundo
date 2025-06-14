package com.bearmod;

import android.content.Context;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for NativeUtils class
 */
@RunWith(MockitoJUnitRunner.class)
public class NativeUtilsTest {

    @Mock
    Context mockContext;

    @Before
    public void setUp() {
        // Mock static Log class to prevent errors
        try (MockedStatic<Log> mockedLog = mockStatic(Log.class)) {
            mockedLog.when(() -> Log.d(NativeUtils.class.getSimpleName(), "Native library loaded successfully"))
                    .thenReturn(0);
            mockedLog.when(() -> Log.w(NativeUtils.class.getSimpleName(), "Native library not loaded, returning default value"))
                    .thenReturn(0);
            mockedLog.when(() -> Log.e(NativeUtils.class.getSimpleName(), "Native method not found", null))
                    .thenReturn(0);
        }
    }

    @Test
    public void testIsLibraryLoaded() {
        // Since we can't actually load the native library in a unit test,
        // we're just testing the method exists and returns a boolean
        boolean result = NativeUtils.isLibraryLoaded();
        // The result will be false in the test environment
        assertFalse(result);
    }

    @Test
    public void testGetVersion() {
        // Since we can't call the actual native method, we're just testing
        // that the method returns the default value when the library isn't loaded
        String version = NativeUtils.getVersion();
        assertEquals("1.0.0", version);
    }

    @Test
    public void testIsGameServiceConnectedWithRetry() {
        // Test the retry logic with a small number of retries and delay
        boolean result = NativeUtils.isGameServiceConnectedWithRetry(2, 10);
        assertFalse(result);
    }

    @Test
    public void testConcurrentAccess() throws InterruptedException {
        // Test concurrent access to the NativeUtils methods
        int threadCount = 10;
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            executorService.submit(() -> {
                try {
                    // Call various methods concurrently
                    NativeUtils.getVersion();
                    NativeUtils.isLibraryLoaded();
                    NativeUtils.isGameServiceConnected();
                    NativeUtils.isGameServiceConnectedWithRetry(1, 10);
                    
                    // If we get here without exceptions, count as success
                    successCount.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            });
        }

        // Wait for all threads to complete
        assertTrue(latch.await(5, TimeUnit.SECONDS));
        executorService.shutdown();
        
        // All threads should complete successfully
        assertEquals(threadCount, successCount.get());
    }
}
