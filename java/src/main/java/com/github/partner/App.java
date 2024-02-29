package com.github.partner;

public class App {
    public static void main(String[] args) {
        SignatureVerifier secretScanningVerifier = new SignatureVerifier(SignatureVerifier.GITHUB_SECRET_SCANNING_KEYS_URI);
        String payload = "[{\"source\":\"commit\",\"token\":\"some_token\",\"type\":\"some_type\",\"url\":\"https://example.com/base-repo-url/\"}]";
        String keyID = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c";
        String signature = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg==";

        try {
            if (secretScanningVerifier.verify(payload, signature, keyID)) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature verification failed");
            }
        } catch (Exception e) {
            System.out.println("Signature verification failed with error: " + e.getMessage());
        }
    }
}
