"""생성물 검증. 기본은 오프라인 형식 검사, --live면 서빙본·resolver까지."""
import argparse
import datetime
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from pipeline import bake_badge
from pipeline import keys

ROOT = Path(__file__).resolve().parent.parent
EXPIRES_MARGIN_DAYS = 30


def check_did_document(doc):
    errors = []
    did = doc.get("id", "")
    if not did.startswith("did:web:"):
        errors.append(f"id must start with did:web: (got {did!r})")
    vms = {vm.get("id"): vm for vm in doc.get("verificationMethod", [])}
    if not vms:
        errors.append("verificationMethod is empty")
    for vm in vms.values():
        if vm.get("controller") != did:
            errors.append(f"{vm.get('id')}: controller != id")
        vtype = vm.get("type")
        if vtype == "Multikey":
            mb = vm.get("publicKeyMultibase", "")
            raw = keys.b58decode(mb[1:]) if mb.startswith("z") else b""
            if raw[:2] != bytes.fromhex("ed01") or len(raw) != 34:
                errors.append(f"{vm.get('id')}: not an Ed25519 Multikey (z + ed01 + 32B)")
        elif vtype == "JsonWebKey":
            if vm.get("publicKeyJwk", {}).get("kty") not in ("EC", "OKP"):
                errors.append(f"{vm.get('id')}: unexpected publicKeyJwk.kty")
        else:
            errors.append(f"{vm.get('id')}: unknown type {vtype!r}")
    for rel in ("authentication", "assertionMethod"):
        for ref in doc.get(rel, []):
            if ref not in vms:
                errors.append(f"{rel} references unknown key {ref}")
    return errors


def _expiry_error(label, value):
    """Fail 30 days out, so the weekly cron reports the lapse while there is
    still time to renew it. security.txt and the domain-linkage credential both
    expire, and both are renewed the same way: edit config.json and push."""
    if value is None:
        return f"{label} is missing"
    if not str(value).strip():
        return f"{label} is empty"
    try:
        exp = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return f"{label} not ISO 8601: {value!r}"
    if exp.tzinfo is None:
        # Dropping the trailing Z is the likeliest slip when renewing by hand,
        # and comparing naive to aware raises instead of reporting.
        return f"{label} has no timezone, add a trailing Z: {value!r}"
    margin = (datetime.datetime.now(datetime.timezone.utc)
              + datetime.timedelta(days=EXPIRES_MARGIN_DAYS))
    if exp < margin:
        return (f"{label} {value} is within {EXPIRES_MARGIN_DAYS} days — "
                "renew it in config.json and push")
    return None


def check_security_txt(text):
    errors = []
    fields = dict(line.split(": ", 1)
                  for line in text.strip().splitlines() if ": " in line)
    for req in ("Contact", "Expires"):
        if req not in fields:
            errors.append(f"security.txt missing {req}")
    if "Expires" in fields:
        expiry = _expiry_error("Expires", fields["Expires"])
        if expiry:
            errors.append(expiry)
    return errors


def check_baked_badge(svg, signed):
    """The image must carry the signed credential unchanged.

    Extraction follows OB 3.0 section 5.3.2.2, so this fails for the same reason
    a reader's extractor would: a malformed SVG, a missing or duplicated tag, or
    a payload that is not what the signer produced."""
    try:
        recovered = bake_badge.extract(svg)
    except Exception as e:
        return [f"contributions.svg: {e}"]
    if recovered != signed:
        return ["contributions.svg carries a credential that is not the signed one"]
    return []


def check_humans_txt(text, local_did):
    """The DID line is the one that can go stale: it is copied out of the
    rendered document, so a mismatch means the two were rendered apart."""
    errors = []
    if not text.startswith("/* TEAM */"):
        errors.append("humans.txt does not open with /* TEAM */")
    fields = dict(line.strip().split(": ", 1)
                  for line in text.splitlines() if ": " in line)
    for req in ("Developer", "GitHub", "DID"):
        if req not in fields:
            errors.append(f"humans.txt missing {req}")
    if fields.get("DID") not in (None, local_did["id"]):
        errors.append(f"humans.txt DID {fields['DID']!r} != did.json id "
                      f"{local_did['id']!r}")
    return errors


def check_domain_linkage(resource, config):
    """DIF Well-Known DID Configuration.

    The signature was verified in the signer against the key in the DID document,
    which is the one check that cannot be done here. What is left is that the
    document says what DIF requires it to say - and that it has not quietly
    expired, which is the reason the weekly cron exists.
    """
    did = f"did:web:{config['domain']}"
    origin = f"https://{config['domain']}"
    expected_vm = f"{did}#{config['keys']['ed25519']['id']}"
    linked = resource.get("linked_dids")
    if not isinstance(linked, list) or not linked:
        return ["did-configuration.json: linked_dids must be a non-empty array"]
    # DIF permits several entries and allows an entry to be a bare compact JWS
    # string. Only the JSON-LD entries for our own DID are ours to check; a
    # string entry carries its claims inside the JWS, out of reach from here.
    ours = [e for e in linked if isinstance(e, dict)
            and (e.get("credentialSubject") or {}).get("id") == did]
    if len(ours) != 1:
        return [f"did-configuration.json: expected exactly one JSON-LD entry for "
                f"{did}, found {len(ours)} among {len(linked)} entries"]
    credential = ours[0]
    errors = []
    if credential.get("issuer") != did:
        errors.append(f"did-configuration.json: issuer "
                      f"{credential.get('issuer')!r} != {did}")
    if (credential.get("credentialSubject") or {}).get("origin") != origin:
        errors.append(f"did-configuration.json: origin "
                      f"{(credential.get('credentialSubject') or {}).get('origin')!r} "
                      f"!= {origin}")
    for dif_name, vc_name in (("issuanceDate", "validFrom"),
                              ("expirationDate", "validUntil")):
        if credential.get(dif_name) != credential.get(vc_name):
            errors.append(f"did-configuration.json: {dif_name} and {vc_name} "
                          f"disagree - DIF verifiers read one, VC 2.0 the other")
    # A signature over the wrong key is still a signature. The proof itself was
    # verified in the signer; what is checked here is that it names the key this
    # repository publishes, which a rotation silently invalidates.
    proofs = credential.get("proof") or []
    proofs = [p for p in (proofs if isinstance(proofs, list) else [proofs])
              if isinstance(p, dict)]
    di = [p for p in proofs if p.get("cryptosuite") == "eddsa-rdfc-2022"]
    if not di:
        errors.append("did-configuration.json: no eddsa-rdfc-2022 proof")
    for p in di:
        if p.get("verificationMethod") != expected_vm:
            errors.append(f"did-configuration.json: proof verificationMethod "
                          f"{p.get('verificationMethod')!r} != {expected_vm}")
        if p.get("proofPurpose") != "assertionMethod":
            errors.append(f"did-configuration.json: proofPurpose "
                          f"{p.get('proofPurpose')!r} != 'assertionMethod'")
    expiry = _expiry_error("did-configuration.json validUntil",
                           credential.get("validUntil"))
    if expiry:
        errors.append(expiry)
    return errors


def _fetch(url):
    # urlopen raises on 4xx/5xx, which would abort the run at the first bad path
    # and hide every path after it. A status is a result, not an exception.
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()
    except urllib.error.URLError as e:
        # DNS or connection failure. Same contract: a result, not an exception.
        return 0, "", str(e.reason).encode()
    except OSError as e:
        # A read timeout raises TimeoutError, which is an OSError and not a
        # URLError, so it used to escape the two clauses above as a traceback.
        return 0, "", str(e).encode()


def check_live(config, local_did, identity_only=False):
    errors = []
    base = f"https://{config['domain']}"
    status, ctype, body = _fetch(f"{base}/.well-known/did.json")
    if status != 200:
        errors.append(f"did.json HTTP {status}")
    else:
        # Independent checks: a wrong Content-Type must not hide wrong content.
        if not ctype.startswith("application/json"):
            errors.append(f"did.json Content-Type {ctype!r}")
        try:
            if json.loads(body) != local_did:
                errors.append("served did.json differs from repository copy")
        except json.JSONDecodeError as e:
            errors.append(f"served did.json is not JSON: {e}")
    status, ctype, _ = _fetch(f"{base}/.well-known/security.txt")
    if status != 200:
        errors.append(f"security.txt HTTP {status}")
    elif not ctype.startswith("text/plain"):
        errors.append(f"security.txt Content-Type {ctype!r}")
    status, ctype, body = _fetch(f"{base}/humans.txt")
    if status != 200:
        errors.append(f"humans.txt HTTP {status}")
    else:
        if not ctype.startswith("text/plain"):
            errors.append(f"humans.txt Content-Type {ctype!r}")
        if body.decode() != (ROOT / "humans.txt").read_text():
            errors.append("served humans.txt differs from what this run rendered")
    if not identity_only:
        # Compare content, not just status: a stale Pages artifact serves 200.
        for path in ("/.well-known/did-configuration.json",
                     "/credentials/contributions.json",
                     "/credentials/achievements/contributions.json"):
            status, _, body = _fetch(f"{base}{path}")
            if status != 200:
                errors.append(f"{path} HTTP {status}")
                continue
            local = ROOT / path.lstrip("/")
            if not local.exists():
                errors.append(f"{path} served, but nothing was rendered locally")
            elif json.loads(body) != json.loads(local.read_text()):
                errors.append(f"served {path} differs from what this run rendered")
        status, ctype, body = _fetch(f"{base}/credentials/contributions.svg")
        if status != 200:
            errors.append(f"contributions.svg HTTP {status}")
        else:
            if not ctype.startswith("image/svg+xml"):
                errors.append(f"contributions.svg Content-Type {ctype!r}")
            svg = body.decode()
            if svg != (ROOT / "credentials" / "contributions.svg").read_text():
                errors.append("served contributions.svg differs from what this run baked")
            # The point of baking is that the image and the endpoint agree, so
            # check them against each other as served, not against local copies.
            _, _, served_json = _fetch(f"{base}/credentials/contributions.json")
            errors += check_baked_badge(svg, served_json.decode())
    errors += check_resolvable(local_did["id"])
    return errors


def check_resolvable(did):
    """Resolve the DID through a third party, as a reader would.

    Their outage is not our defect: an unreachable resolver warns, and only a
    resolver that answers with the wrong document fails the run. Getting this
    backwards once killed a run whose deploy had already succeeded.
    """
    status, _, body = _fetch(f"https://dev.uniresolver.io/1.0/identifiers/{did}")
    if status != 200:
        print(f"WARN  Universal Resolver unreachable ({body.decode()[:80]}) — "
              "not treating a third party's downtime as our failure")
        return []
    try:
        resolved = json.loads(body).get("didDocument") or {}
    except json.JSONDecodeError:
        print("WARN  Universal Resolver returned a non-JSON body")
        return []
    if resolved.get("id") != did:
        return [f"Universal Resolver resolved {did} to {resolved.get('id')!r}"]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="also verify served endpoints and DID resolution")
    ap.add_argument("--identity-only", action="store_true",
                    help="skip the credential paths. Used mid-rotation, when the "
                         "new key is being published but nothing is signed with it yet")
    args = ap.parse_args()
    config = json.loads((ROOT / "config.json").read_text())
    did_path = ROOT / ".well-known" / "did.json"
    if not did_path.exists():
        raise SystemExit("nothing rendered yet. The endpoints are generated, not "
                         "committed:\n  python3 -m pipeline.generate_did_document")
    local_did = json.loads(did_path.read_text())
    errors = check_did_document(local_did)
    errors += check_security_txt((ROOT / ".well-known" / "security.txt").read_text())
    errors += check_humans_txt((ROOT / "humans.txt").read_text(), local_did)
    linkage = ROOT / ".well-known" / "did-configuration.json"
    # Absent until the first signed run, and never rewritten during a rotation:
    # missing is a state to tolerate, not a failure. --live catches it once the
    # file is supposed to be there, because a 404 is unambiguous.
    if not args.identity_only and linkage.exists():
        errors += check_domain_linkage(json.loads(linkage.read_text()), config)
    baked = ROOT / "credentials" / "contributions.svg"
    if not args.identity_only and baked.exists():
        errors += check_baked_badge(
            baked.read_text(),
            (ROOT / "credentials" / "contributions.json").read_text())
    if args.live:
        errors += check_live(config, local_did, args.identity_only)
    for e in errors:
        print(f"FAIL {e}", file=sys.stderr)
    print("ok" if not errors else f"{len(errors)} error(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
