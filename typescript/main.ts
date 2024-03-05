import crypto from "crypto";

const GITHUB_KEYS_URI = "https://api.github.com/meta/public_keys/secret_scanning";

interface GitHubKeysPayload {
  public_keys: Array<{
    key: string;
    key_identifier: string;
    is_current: boolean;
  }>;
}

async function verifySignature(
  payload: string,
  signature: string,
  keyID: string,
  tokenForUser: string | null
): Promise<void> {
  if (typeof payload !== "string" || payload.length === 0) {
    throw new Error("Invalid payload");
  }
  if (typeof signature !== "string" || signature.length === 0) {
    throw new Error("Invalid signature");
  }
  if (typeof keyID !== "string" || keyID.length === 0) {
    throw new Error("Invalid keyID");
  }
  let headers: HeadersInit | undefined
  if (tokenForUser != null) {
    headers = {
      Authorization: `Bearer ${tokenForUser}`,
    }
  }

  const keys = (await fetch(GITHUB_KEYS_URI, {
    method: "GET",
    headers: headers,
  }).then((res) => res.json())) as GitHubKeysPayload;
  const publicKey =
    keys.public_keys.find((k) => k.key_identifier === keyID) ?? null;
  if (publicKey === null) {
    throw new Error("No public key found matching key identifier");
  }

  const verify = crypto.createVerify("SHA256").update(payload);
  if (!verify.verify(publicKey.key, signature, "base64")) {
    throw new Error("Signature does not match payload");
  }
}

const PAYLOAD = `[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]`;
const SIGNATURE = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg==";
const KEY_IDENTIFIER = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c";

verifySignature(PAYLOAD, SIGNATURE, KEY_IDENTIFIER, process.env.GITHUB_PRODUCTION_TOKEN).then(() => {
  console.log("successfully verified");
}).catch(e => {
  console.error(e)
})
