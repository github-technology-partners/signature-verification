<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

class GithubSignatureVerifier
{
    public static function verify(string $signature, string $publicKey, string $token, string $payload): bool
    {
        // Fetch public keys from GitHub
        $client = new Client();
        $response = $client->get('https://api.github.com/copilot-keys', [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
            ]
        ]);

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

        // Decode the base64 signature
        $sigData = base64_decode($signature);

        $sigSerializer = new DerSignatureSerializer();
        $sig = $sigSerializer->parse($sigData);

        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator384();
        $algorithm = 'sha256';

        // Parse public key 
        $derSerializer = new DerPublicKeySerializer($adapter);
        $pemSerializer = new PemPublicKeySerializer($derSerializer);
        $key = $pemSerializer->parse($publicKey);

        $hasher = new SignHasher($algorithm);
        $hash = $hasher->makeHash($payload, $generator);

        $signer = new Signer($adapter);
        return $signer->verify($key, $sig, $hash);
    }
}

// Example usage -- these will come from the GitHub webhook request
$signature = 'base64-encoded-signature';
$publicKey = 'public-key-identifier';
$githubToken = 'your-github-token';
$payload = 'payload-data';

$isValid = GithubSignatureVerifier::verify($signature, $publicKey, $githubToken, $payload);

if ($isValid) {
    echo "Signature is valid.";
} else {
    echo "Signature is invalid.";
}