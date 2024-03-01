from base64 import b64decode
import os
import requests
from ecdsa import VerifyingKey, BadSignatureError, NIST256p
from ecdsa.util import sigdecode_der
from hashlib import sha256

GITHUB_KEYS_URI = "https://api.github.com/meta/public_keys/secret_scanning"

key_id = "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c"
payload = b'[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]'
signature = b"MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg=="
raw_sig = b64decode(signature)

github_token = os.environ.get("GITHUB_PRODUCTION_TOKEN", None)
headers = {"Authorization": f"Bearer: {github_token}"} if github_token else {}
key_resp = requests.get(GITHUB_KEYS_URI, headers=headers, timeout=5).json()
for k in key_resp["public_keys"]:
    if k["key_identifier"] == key_id:
        public_key = k["key"]
        break

ecdsa_verifier = VerifyingKey.from_pem(string=public_key, hashfunc=sha256)
try:
    ecdsa_verifier.verify(
        signature=raw_sig, data=payload, sigdecode=sigdecode_der
    )
    print("Message validated")
except (BadSignatureError, ValueError):
    print("Message not validated")
