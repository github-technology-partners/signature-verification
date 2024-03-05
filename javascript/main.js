const crypto = require("crypto");
const axios = require("axios");

const GITHUB_KEYS_URI = "https://api.github.com/meta/public_keys/secret_scanning";

/**
 * Verify a payload and signature against a public key
 * @param {String} payload the value to verify
 * @param {String} signature the expected value
 * @param {String} keyID the id of the key used to generated the signature
 * @param {String} token the token to use for the request
 * @return {void} throws if the signature is invalid
 */
const verify_signature = async (payload, signature, keyID, token) => {
  if (typeof payload !== "string" || payload.length === 0) {
    throw new Error("Invalid payload");
  }
  if (typeof signature !== "string" || signature.length === 0) {
    throw new Error("Invalid signature");
  }
  if (typeof keyID !== "string" || keyID.length === 0) {
    throw new Error("Invalid keyID");
  }
  headers = null
  if (token) headers = { headers: { Authorization: `Bearer ${token}` } };
  const keys = (await axios.get(GITHUB_KEYS_URI, headers)).data;
  if (!(keys?.public_keys instanceof Array) || keys.length === 0) {
    throw new Error("No public keys found");
  }

  const publicKey = keys.public_keys.find((k) => k.key_identifier === keyID) ?? null;
  if (publicKey === null) {
    throw new Error("No public key found matching key identifier");
  }

  const verify = crypto.createVerify("SHA256").update(payload);
  if (!verify.verify(publicKey.key, Buffer.from(signature, "base64"), "base64")) {
    throw new Error("Signature does not match payload");
  }
};

const PAYLOAD = `[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]`;
const SIGNATURE = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg==";
const KEY_IDENTIFIER = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c";

verify_signature(PAYLOAD, SIGNATURE, KEY_IDENTIFIER, process.env.GITHUB_PRODUCTION_TOKEN).then(() => {
  console.log("successfully verified");
}).catch(e => {
  console.error(e)
})
