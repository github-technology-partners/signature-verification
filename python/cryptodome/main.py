from base64 import b64decode
import requests
import os
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256

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

ecc_key = ECC.import_key(public_key)
msg_hash = SHA256.new(payload)

cdome_verifier = DSS.new(key=ecc_key, mode="fips-186-3", encoding="der")
try:
    cdome_verifier.verify(msg_hash=msg_hash, signature=raw_sig)
    print("Message validated")
except ValueError:
    print("Message not validated")
