"""config.json + 개인키 환경변수 → .well-known/did.json"""
import json
from pathlib import Path

from pipeline import keys

ROOT = Path(__file__).resolve().parent.parent


def build(config: dict) -> dict:
    did = f"did:web:{config['domain']}"
    ed = config["keys"]["ed25519"]
    vm_ed = {
        "id": f"{did}#{ed['id']}",
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": keys.ed25519_public_multibase(
            keys.load_private_pem(ed["env"])),
    }
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            # did/v1 defines neither Multikey nor publicKeyMultibase
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "alsoKnownAs": [f"https://github.com/{config['github_username']}"],
        "verificationMethod": [vm_ed],
        "authentication": [vm_ed["id"]],
        "assertionMethod": [vm_ed["id"]],
    }


def main():
    config = json.loads((ROOT / "config.json").read_text())
    out = ROOT / ".well-known" / "did.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build(config), indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
