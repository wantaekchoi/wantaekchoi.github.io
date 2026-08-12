"""config.json → security.txt (RFC 9116)"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(sec: dict) -> str:
    lines = [
        f"Contact: {sec['contact']}",
        f"Expires: {sec['expires']}",
        f"Preferred-Languages: {sec['preferred_languages']}",
        f"Canonical: {sec['canonical']}",
    ]
    return "\n".join(lines) + "\n"


def main():
    config = json.loads((ROOT / "config.json").read_text())
    out = ROOT / ".well-known" / "security.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(config["security_txt"]))
    print("wrote .well-known/security.txt")


if __name__ == "__main__":
    main()
