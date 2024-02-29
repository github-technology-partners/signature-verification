package com.github.partner;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.concurrent.CompletableFuture;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class SignatureVerifier {
    public static final String GITHUB_SECRET_SCANNING_KEYS_URI = "https://api.github.com/meta/public_keys/secret_scanning";
    public static final String GITHUB_COPILOT_KEYS_URI = "https://api.github.com/meta/public_keys/copilot";
    private static final String ENCRYPTION_ALGORTHIM = "EC";
    private static final String HASH_ENCRYPTION_ALGORITHM = "SHA256withECDSA";

    private final String GITHUB_KEYS_URI;

    public SignatureVerifier(String KeysURI) {
        this.GITHUB_KEYS_URI = KeysURI;
    }

    public boolean verify(String payload, String signature, String keyID)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        // Fetch the list of GitHub Public Keys
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request;
        // if GITHUB_PRODUCTION_TOKEN is set use the token for higher rate limit
        if (System.getenv("GITHUB_PRODUCTION_TOKEN") != null) {
            request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(this.GITHUB_KEYS_URI))
            .header("Authorization", "Bearer " + System.getenv("GITHUB_PRODUCTION_TOKEN"))
            .build();
        } else {
            request = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(this.GITHUB_KEYS_URI))
            .build();
        }
        CompletableFuture<HttpResponse<String>> response =
        client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        JsonObject responseJSON = new Gson().fromJson(response.thenApply(HttpResponse::body).join(),
        JsonObject.class);

        if (!responseJSON.has("public_keys")) {
            throw new RuntimeException("No public keys found");
        }

        // Find the key used to sign the payload, decode it, and build a java.security.PublicKey
        String encodedKeyData = SignatureVerifier.findKey(responseJSON.getAsJsonArray("public_keys"), keyID);
        byte[] decodedKeyData = Base64.getDecoder().decode(encodedKeyData);
        PublicKey publicKey = SignatureVerifier.buildPublicKey(decodedKeyData);

        // The signature provided by GitHub is Base64 encoded
        byte[] decodedSignature = Base64.getDecoder().decode(signature);

        return SignatureVerifier.verifySignature(payload.getBytes(), decodedSignature, publicKey);
    }

    private static boolean verifySignature(byte[] payload, byte[] signature, PublicKey publicKey)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureObject = Signature.getInstance(SignatureVerifier.HASH_ENCRYPTION_ALGORITHM);
        signatureObject.initVerify(publicKey);
        signatureObject.update(payload);
        return signatureObject.verify(signature);
    }

    private static String findKey(JsonArray keyArray, String keyID) {
        for (JsonElement elem : keyArray) {
            JsonObject elemObj = elem.getAsJsonObject();
            if (elemObj.get("key_identifier").getAsString().equals(keyID)) {
                // extract just the key value
                return elemObj.get("key").getAsString()
                .replaceAll("-*BEGIN.*KEY-*", "")
                .replaceAll("-*END.*KEY-*", "")
                .replaceAll("\n", "")
                .replaceAll("\r", "");
            }
        }
        throw new RuntimeException(String.format("Key %s not found in public keys", keyID));
    }

    private static PublicKey buildPublicKey(byte[] publicKey)
    throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory keyFactory = KeyFactory.getInstance(SignatureVerifier.ENCRYPTION_ALGORTHIM);
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
        return keyFactory.generatePublic(publicKeySpec);
    }
}
