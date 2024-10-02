# Signature Verification in javascript

This is a simple example of how to verify a signature in php. It uses mdanter's ecc library to do so.

## Usage

To run the example you can run:

```
composer update
php verify.php
```

Note that the example as written will fail. You will need to replace:

```php
$signature = 'base64-encoded-signature';
$publicKey = 'public-key-identifier';
$githubToken = 'your-github-token';
$payload = 'payload-data';
```

with actual values obtained from a Copilot request in order for the example to work. 