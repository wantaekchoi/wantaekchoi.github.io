"""GitHub profile -> /humans.txt (humanstxt.org convention).

Nothing here is written by hand. The name and location are whatever
GET /users/<login> returns at render time, and the DID is read back out of the
document the same run just rendered, so the two can never disagree.

There is no /* SITE */ section on purpose. Its conventional fields either
duplicate the site (Standards, Components, Software are all visible in
index.html or in this repository) or would have to come from the clock
(Last update), and output here is a function of its inputs alone, the same rule
generate_badge.py follows so an unchanged profile re-renders byte for byte.
"""
import json
from pathlib import Path

from pipeline.generate_badge import API, _get

ROOT = Path(__file__).resolve().parent.parent


def build(user: dict, did: str) -> str:
    fields = [
        ("Developer", user.get("name") or user["login"]),
        ("GitHub", f"github.com/{user['login']}"),
        ("DID", did),
    ]
    # Optional on a GitHub profile, and an empty label reads worse than none.
    location = (user.get("location") or "").strip()
    if location:
        fields.append(("Location", location))
    body = "\n".join(f"\t{label}: {value}" for label, value in fields)
    return f"/* TEAM */\n\n{body}\n"


def main() -> None:
    config = json.loads((ROOT / "config.json").read_text())
    login = config["github_username"]
    did = json.loads((ROOT / ".well-known" / "did.json").read_text())["id"]
    out = ROOT / "humans.txt"
    out.write_text(build(_get(f"{API}/users/{login}"), did))
    print("wrote humans.txt")


if __name__ == "__main__":
    main()
