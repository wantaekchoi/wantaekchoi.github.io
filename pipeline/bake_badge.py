"""Signed credential -> credentials/contributions.svg, an Open Badges 3.0 baked badge.

Baking (OB 3.0 section 5.3.2) puts the credential inside the image, so the proof
travels wherever the file is copied instead of only resolving from this domain.
The proof is embedded rather than VC-JWT, so per the specification the JSON goes
in the body of a single <openbadges:credential> tag wrapped in CDATA, and the
verify attribute is omitted.

Baking happens after signing and never touches the credential: whatever comes out
of the signer is what goes in, byte for byte. verify() takes it back out the way
section 5.3.2.2 says a reader would and fails the run on any difference, because
an image carrying a credential that no longer verifies is worse than no image.

The picture itself carries no counts. The credential inside is the record, and a
number painted on the outside is a second copy that can disagree with it.
"""
import base64
import json
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OB_NS = "https://purl.imsglobal.org/ob/v3p0"
CREDENTIAL_TAG = f"{{{OB_NS}}}credential"

# The avatar is drawn from bytes, not from its URL. A baked badge is meant to be
# copied, and an <image href="https://..."> would render as a hole everywhere the
# copy is opened offline or by a renderer that refuses remote references. It fills
# the whole frame now, so ask for the largest GitHub serves. Only a plain href:
# repeating the URI in xlink:href for pre-SVG2 renderers doubled the file.
AVATAR_SIZE = 460


def render(credential: dict, payload: str, avatar: str) -> str:
    """The picture is the issuer image and nothing else.

    A baked badge carries its meaning inside, not painted on the front: the
    achievement name, the issuer and every piece of evidence are in the credential
    a reader extracts. Drawing them on top would only add a second copy free to
    disagree with it."""
    name = credential["credentialSubject"]["achievement"]["name"]
    issuer = credential["issuer"]["name"]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:openbadges="{OB_NS}"
     viewBox="0 0 512 512" width="512" height="512"
     role="img" aria-label="{_esc(name)}, issued to {_esc(issuer)}">
<openbadges:credential><![CDATA[{payload}]]></openbadges:credential>
<title>{_esc(name)}</title>
<image x="0" y="0" width="512" height="512" preserveAspectRatio="xMidYMid slice"
       href="{avatar}"/>
</svg>
"""


def fetch_avatar(credential: dict) -> str:
    """The issuer image the credential already names, as a data URI.

    Asking for the URL in the credential rather than rebuilding it keeps the
    picture and the proof pointing at the same thing."""
    url = f"{credential['issuer']['image']['id']}?size={AVATAR_SIZE}"
    req = urllib.request.Request(url, headers={"User-Agent": "well-known-pipeline"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        media = resp.headers.get("Content-Type", "image/png").split(";")[0].strip()
        return f"data:{media};base64,{base64.b64encode(resp.read()).decode()}"


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def extract(svg: str) -> str:
    """Read the credential back out, as OB 3.0 section 5.3.2.2 describes."""
    root = ET.fromstring(svg)
    found = root.findall(CREDENTIAL_TAG)
    if len(found) != 1:
        # "There MUST be only one <openbadges:credential> tag in an SVG."
        raise ValueError(f"expected exactly one {CREDENTIAL_TAG}, found {len(found)}")
    if list(root)[0] is not found[0]:
        # "Directly after the <svg> tag, add an <openbadges:credential> tag."
        raise ValueError("openbadges:credential is not the first child of <svg>")
    return found[0].text or ""


def bake(credential: dict, payload: str, avatar: str) -> str:
    if "]]>" in payload:
        # CDATA has no escape for its own terminator, so a payload containing one
        # would close the section early and silently truncate the credential.
        raise ValueError("credential contains ]]> and cannot be wrapped in CDATA")
    svg = render(credential, payload, avatar)
    recovered = extract(svg)
    if recovered != payload:
        raise ValueError("credential does not survive a bake/extract round trip")
    return svg


def main() -> None:
    signed = ROOT / "credentials" / "contributions.json"
    payload = signed.read_text()
    out = ROOT / "credentials" / "contributions.svg"
    credential = json.loads(payload)
    out.write_text(bake(credential, payload, fetch_avatar(credential)))
    print(f"wrote credentials/contributions.svg ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
