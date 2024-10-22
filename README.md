# Signature Verification

GitHub uses asymmetric cryptography to provide signatures for select integration methods, including the Secret Scanning Partner Program and Copilot Extensibility. This allows you to verify that the payload was sent by GitHub and not modified.

This repository contains simple examples of how to verify a signature using GitHub's public keys.

We have built a codespace to allow people to easily run the code and see how it works.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/github-technology-partners/signature-verification/)

Each example is in a separate directory, first level directories are the language used, and any subdirectories indicate specific libraries or frameworks used.

## Examples
- [`go`](go/)
- [`java`](java/)
- [`javascript`](javascript/)
- [`php`](php/)
- [`python/cyrptodome`](python/cryptodome/)
- [`python/ecdsa`](python/ecdsa)
- [`ruby`](ruby/)
- [`typescript`](typescript/)

## Implementing signature verification in your service

The HTTP request to your service will also contain headers that we strongly recommend using to validate the messages you receive are genuinely from GitHub, and are not malicious.

The two HTTP headers to look for are:

- `Github-Public-Key-Identifier`: Which `key_identifier` to use from our API
- `Github-Public-Key-Signature`: Signature of the payload

You can retrieve the GitHub public key for the appropriate integration from [the URIs list](#URIs) and validate the message using the `ECDSA-NIST-P256V1-SHA256` algorithm. The endpoint will provide several `key_identifier` and public keys. You can determine which public key to use based on the value of `Github-Public-Key-Identifier`.

> [!TIP]
> When you send a request to the public key endpoint above, you may hit rate limits. To avoid hitting rate limits, you can use a personal access token (classic) (no scopes required), a fine-grained personal access token (only the automatic public repositories read access required), a [GitHub App user access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app), or use a conditional request. For more information, see "Getting started with the REST API."

> [!IMPORTANT]
> The signature was generated using the raw message body. So it's important you also use the raw message body for signature validation, instead of parsing and stringifying the JSON, to avoid rearranging the message or changing spacing.

## Usage

You can use these code examples as a starting point/reference for verifying signatures in your own code. The examples all use a sample payload and signature from our [secret scanning partner program](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partner-program#create-a-secret-alert-service), and thus we use the public key from that program to verify the signature. However, you can change the public key uri to fetch the public key for the integration you are using.

### URIs
- `https://api.github.com/meta/public_keys/copilot_api`
- `https://api.github.com/meta/public_keys/secret_scanning`
