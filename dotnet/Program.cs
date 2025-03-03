
using Org.BouncyCastle.Security;
using System.Text.Json;
using System.Text.RegularExpressions;

const string GITHUB_SECRET_SCANNING_KEYS_ENDPOINT = "https://api.github.com/meta/public_keys/secret_scanning";
//const string GITHUB_COPILOT_KEYS_ENDPOINT = "https://api.github.com/meta/public_keys/copilot_api";

const string payload = "[{\"source\":\"commit\",\"token\":\"some_token\",\"type\":\"some_type\",\"url\":\"https://example.com/base-repo-url/\"}]";
const string keyID = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c";
const string signature = "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg==";

byte[] publicKeyDecodedKeyData = await GetPublicKey(GITHUB_SECRET_SCANNING_KEYS_ENDPOINT, keyID);
byte[] decodedSignature = Convert.FromBase64String(signature);


var signer = SignerUtilities.GetSigner("SHA256withECDSA");
signer.Init(false, PublicKeyFactory.CreateKey(publicKeyDecodedKeyData));
var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
var verificationResult = signer.VerifySignature(decodedSignature);

Console.WriteLine(verificationResult ? "Signature verified" : "Signature verification failed");





// Fetches the public key from the GitHub API
static async Task<byte[]> GetPublicKey(string endpoint, string keyId, string githubToken = "")
{
    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, endpoint);
    request.Headers.Add("User-Agent", ".NET App");
    // Add the GitHub token if provided to avoid strict rate limiting
    if (!string.IsNullOrEmpty(githubToken))
    {
        request.Headers.Add("Authorization", $"Bearer {githubToken}");
    }
    var _httpClient = new HttpClient();
    HttpResponseMessage response = await _httpClient.SendAsync(request);
    response.EnsureSuccessStatusCode();
    string responseBody = await response.Content.ReadAsStringAsync();
    using JsonDocument document = JsonDocument.Parse(responseBody);
    JsonElement root = document.RootElement;
    if (!root.TryGetProperty("public_keys", out JsonElement publicKeysElement))
    {
        throw new InvalidOperationException("No public keys found");
    }
    string encodedKeyData = FindKey(publicKeysElement, keyId);
    byte[] decodedKeyData = Convert.FromBase64String(encodedKeyData);
    return decodedKeyData;
}

// Finds the key in the JSON element array by key identifier
static string FindKey(JsonElement keyArray, string keyID)
{
    foreach (JsonElement elem in keyArray.EnumerateArray())
    {
        if (elem.TryGetProperty("key_identifier", out JsonElement keyIdentifier) &&
            keyIdentifier.GetString() == keyID &&
            elem.TryGetProperty("key", out JsonElement key))
        {
            // Extract just the key value
            string keyValue = key.GetString() ?? string.Empty;
            return Regex.Replace(
                Regex.Replace(
                    Regex.Replace(
                        Regex.Replace(
                            Regex.Replace(keyValue, "-*BEGIN.*KEY-*", ""),
                            "-*END.*KEY-*", ""),
                        "\n", ""),
                    "\r", ""),
                "\\s", "");
        }
    }

    throw new InvalidOperationException($"Key {keyID} not found in public keys");
}