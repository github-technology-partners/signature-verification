<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;

class GithubSignatureVerifier
{
    public const GITHUB_SECRET_SCANNING_KEYS_URI = "https://api.github.com/meta/public_keys/secret_scanning";
    public const GITHUB_COPILOT_KEYS_URI = "https://api.github.com/meta/public_keys/copilot_api";
    protected const ALGORITHM = OPENSSL_ALGO_SHA256;

    public static function verify(string $signature, string $publicKey, string $token, string $payload): bool
    {
        // Fetch public keys from GitHub
        $client = new Client();

        $options = [];
        if (!empty($token)) {
            $options['headers'] = [
            'Authorization' => 'Bearer ' . $token,
            ];
        }

        $response = $client->get(self::GITHUB_SECRET_SCANNING_KEYS_URI, $options);

        $keyResponse = json_decode($response->getBody()->getContents());

        foreach ($keyResponse->public_keys as $key) {
            if ($key->key_identifier === $publicKey) {
                $publicKey = $key->key;
                break;
            }
        }

        if (!$publicKey) {
            echo 'Public key not found for copilot request';
            return false;
        }

        $key = openssl_pkey_get_public($publicKey);
        $valid = openssl_verify($payload, base64_decode($signature), $key, self::ALGORITHM);

        if ($valid < 0) {
            echo 'Error verifying signature: ' . openssl_error_string();
            return false;
        }

        return $valid === 1;
    }
}

const PAYLOAD = '[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]';
const SIGNATURE = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg==";
const KEY_IDENTIFIER = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c";
$token = getenv('GITHUB_PRODUCTION_TOKEN');

$isValid = GithubSignatureVerifier::verify(SIGNATURE, KEY_IDENTIFIER, $token, PAYLOAD);

if ($isValid) {
    echo "Signature is valid.";
} else {
    echo "Signature is invalid.";
}
