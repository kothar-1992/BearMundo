package com.bearmod.security;

import android.content.Context;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class KeyAuthIntegrator {
    private static final String TAG = "KeyAuthIntegrator";
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final int TIMEOUT_SECONDS = 30;

    private static KeyAuthIntegrator instance;
    private final Context context;
    private final OkHttpClient client;
    private final Gson gson;
    private String sessionToken;
    private String licenseKey;
    private boolean isAuthenticated;

    private KeyAuthIntegrator(Context context) {
        this.context = context.getApplicationContext();
        this.client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build();
        this.gson = new Gson();
    }

    public static synchronized KeyAuthIntegrator getInstance(Context context) {
        if (instance == null) {
            instance = new KeyAuthIntegrator(context);
        }
        return instance;
    }

    public CompletableFuture<Boolean> authenticate(String username, String password) {
        CompletableFuture<Boolean> future = new CompletableFuture<>();

        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("username", username);
        requestBody.addProperty("password", password);

        Request request = new Request.Builder()
            .url("https://keyauth.win/api/seller/")
            .post(RequestBody.create(gson.toJson(requestBody), JSON))
            .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Authentication failed", e);
                future.complete(false);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful() && response.body() != null) {
                    String responseBody = response.body().string();
                    JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
                    
                    if (jsonResponse.has("success") && jsonResponse.get("success").getAsBoolean()) {
                        sessionToken = jsonResponse.get("sessionid").getAsString();
                        licenseKey = jsonResponse.get("license").getAsString();
                        isAuthenticated = true;
                        future.complete(true);
                    } else {
                        Log.e(TAG, "Authentication failed: " + responseBody);
                        future.complete(false);
                    }
                } else {
                    Log.e(TAG, "Authentication failed with code: " + response.code());
                    future.complete(false);
                }
            }
        });

        return future;
    }

    public boolean validateSession() {
        if (!isAuthenticated || sessionToken == null) {
            return false;
        }

        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("sessionid", sessionToken);
        requestBody.addProperty("type", "check");

        Request request = new Request.Builder()
            .url("https://keyauth.win/api/seller/")
            .post(RequestBody.create(gson.toJson(requestBody), JSON))
            .build();

        try {
            Response response = client.newCall(request).execute();
            if (response.isSuccessful() && response.body() != null) {
                String responseBody = response.body().string();
                JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);
                return jsonResponse.has("success") && jsonResponse.get("success").getAsBoolean();
            }
        } catch (IOException e) {
            Log.e(TAG, "Session validation failed", e);
        }

        return false;
    }

    public void logout() {
        if (sessionToken != null) {
            JsonObject requestBody = new JsonObject();
            requestBody.addProperty("sessionid", sessionToken);
            requestBody.addProperty("type", "logout");

            Request request = new Request.Builder()
                .url("https://keyauth.win/api/seller/")
                .post(RequestBody.create(gson.toJson(requestBody), JSON))
                .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Log.e(TAG, "Logout failed", e);
                }

                @Override
                public void onResponse(Call call, Response response) {
                    // Clean up regardless of response
                    sessionToken = null;
                    licenseKey = null;
                    isAuthenticated = false;
                }
            });
        }
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public String getLicenseKey() {
        return licenseKey;
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }
} 