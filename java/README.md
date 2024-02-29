# Signature Verification in Java

This is a simple example of how to verify a signature in Java. The example uses the `java.security` package to verify a signature and `com.google.gson` to parse the JSON object containing the public keys.

## Usage

To run the example you can run `mvn package` and execute the `snapshot-with-dependencies.jar` file in the `target` directory.

[`App.java`](src/main/java/com/github/partner/App.java) contains the main method with a test case.

[`SignatureVerifier.java`](src/main/java/com/github/partner/SignatureVerifier.java) contains the logic to verify the signature.
