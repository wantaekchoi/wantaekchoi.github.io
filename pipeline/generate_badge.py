"""Render the unsigned Open Badges 3.0 credential from config.json and badge.json.

Contributions are discovered, not listed: the GitHub search API is asked for every
merged pull request authored by the subject. Search is only the shortlist - each hit
is then re-read from the pulls endpoint and re-checked for merge status and
authorship, because search results are an index and an index can be stale.

badge.json holds the achievement wording and, in its "exclude" list, the refs to
leave out. Pull requests merged into the subject's own repositories are dropped
automatically, since the achievement claims upstream maintainers merged them and
there the subject is the maintainer. (The file was allowlist.json while it
enumerated contributions; it never allowed anything again once discovery landed.)

Output is a function of its inputs alone - validFrom comes from the newest merge, not
from the clock, and the list is sorted - so an unchanged set of merges re-renders
byte for byte and the workflow has nothing to commit.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"


ATTEMPTS = 3


def _get(url: str) -> dict:
    """One GitHub API call, retried while the failure still looks transient.

    A run reads the search index once and every discovered pull request after
    it, so a single blip anywhere in ~26 calls used to lose the whole run. Two
    of those happened in one afternoon: a read timeout, and a TLS handshake the
    runner could not verify. Neither says anything about the credential.

    Only transient failures are retried. A 404 or a 401 is an answer, and
    repeating the question does not change it.
    """
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "well-known-pipeline",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            # 403 is how GitHub reports a rate limit as well as a real refusal.
            transient = e.code >= 500 or e.code in (403, 429)
            if not transient or attempt == ATTEMPTS:
                raise
            # A primary rate limit can be an hour out; 2s then 4s is guaranteed
            # to fail, and hammering a secondary limit lengthens the block.
            wait = e.headers.get("Retry-After") or e.headers.get("x-ratelimit-reset")
            reason = f"HTTP {e.code}"
        except OSError as e:
            # Covers URLError, TimeoutError and the TLS failures underneath both.
            if attempt == ATTEMPTS:
                raise
            reason, wait = str(e), None
        delay = 2 ** attempt
        if wait:
            try:
                asked = int(wait)
                # x-ratelimit-reset is absolute; Retry-After is relative.
                delay = max(delay, min(asked if asked < 3600 else 0, 300))
            except ValueError:
                pass
        print(f"  retrying  {reason} — attempt {attempt}/{ATTEMPTS}, waiting {delay}s")
        time.sleep(delay)


def discover(author: str, exclude: set) -> list:
    """Every merged pull request authored by `author`, as 'owner/repo#123' refs.

    Sorted, so the credential does not churn when search reorders its results.
    """
    refs, page = [], 1
    # is:public is load-bearing, not a nicety. This credential is world-readable
    # and names every repository it lists, so a private one must never reach it.
    # Without the filter the result depends on how much the caller's token can
    # see: a maintainer running this locally would publish repositories that CI,
    # with a repo-scoped token, cannot even enumerate.
    query = f"is:pr is:merged is:public author:{author}"
    while True:
        url = (f"{API}/search/issues?q={urllib.parse.quote(query)}"
               f"&per_page=100&page={page}")
        try:
            result = _get(url)
        except urllib.error.HTTPError as e:
            hint = (" — the search API needs GITHUB_TOKEN"
                    if e.code in (401, 403) else "")
            raise SystemExit(f"search for {author} returned HTTP {e.code}{hint}")
        items = result.get("items", [])
        for item in items:
            # repository_url is .../repos/owner/name
            repo = "/".join(item["repository_url"].split("/")[-2:])
            if repo.split("/")[0].lower() == author.lower():
                continue          # own repository: no upstream maintainer merged it
            ref = f"{repo}#{item['number']}"
            if ref not in exclude:
                refs.append(ref)
        if len(items) < 100 or len(refs) >= result.get("total_count", 0):
            break
        if page == 10:
            # Search serves at most 1000 results; asking for page 11 is a 422.
            # Failing here beats failing there, where the message blames the token.
            raise SystemExit(
                f"{author} has more than 1000 merged public pull requests, which is "
                "more than the GitHub search API will enumerate. Narrow the query in "
                "discover() — by date range or by repository — before this can run.")
        page += 1
    return sorted(set(refs))


def fetch(ref: str, expected_author: str) -> dict:
    """Resolve 'owner/repo#123' to the facts the credential will assert."""
    repo, _, number = ref.partition("#")
    try:
        pr = _get(f"{API}/repos/{repo}/pulls/{number}")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{ref}: GitHub API returned {e.code}")
    if ((pr.get("base") or {}).get("repo") or {}).get("private"):
        print(f"  skipped   {ref:<40} repository is private")
        return None
    if not pr.get("merged"):
        raise SystemExit(f"{ref}: search says merged, the pulls endpoint disagrees")
    author = (pr.get("user") or {}).get("login")
    if author != expected_author:
        raise SystemExit(f"{ref}: authored by {author}, not {expected_author}")
    return {"ref": ref, "url": pr["html_url"], "title": pr["title"], "merged_at": pr["merged_at"]}


def build(config: dict, badge: dict, merged: list) -> dict:
    base = f"https://{config['domain']}/credentials"
    did = f"did:web:{config['domain']}"
    validFrom = max(m["merged_at"] for m in merged)
    spec = badge["achievement"]
    # GitHub redirects <user>.png to the current avatar, so the badge picks up a
    # changed profile picture without a re-signing run. The URL is what the proof
    # covers, not the bytes behind it.
    avatar = {"id": f"https://github.com/{config['github_username']}.png",
              "type": "Image"}
    achievement = {
        "id": f"{base}/achievements/contributions.json",
        "type": ["Achievement"],
        "name": spec["name"],
        "description": spec["description"],
        "image": avatar,
        "criteria": spec["criteria"],
    }
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            # 1EdTechJsonSchemaValidator2019 lives here, not in the OB context
            "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json",
        ],
        "id": f"{base}/contributions.json",
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": {
            "id": did,
            "type": ["Profile"],
            "name": config["github_username"],
            "url": f"https://github.com/{config['github_username']}",
            "image": avatar,
        },
        "validFrom": validFrom,
        "credentialSubject": {
            "id": did,
            "type": ["AchievementSubject"],
            "achievement": achievement,
        },
        "evidence": [
            {
                "id": m["url"],
                "type": ["Evidence"],
                "name": m["ref"],
                "description": m["title"],
            }
            for m in reversed(merged)
        ],
        "credentialSchema": [{
            "id": "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/"
                  "ob_v3p0_achievementcredential_schema.json",
            "type": "1EdTechJsonSchemaValidator2019",
        }],
    }


def main() -> None:
    config = json.load(open("config.json"))
    badge = json.load(open("badge.json"))
    exclude = set(badge.get("exclude", []))
    refs = discover(config["github_username"], exclude)
    if not refs:
        raise SystemExit("no merged pull requests found - refusing to issue "
                         "a credential that claims nothing")
    print(f"  discovered {len(refs)} merged pull request(s), "
          f"{len(exclude)} excluded by badge.json")

    found = (fetch(r, config["github_username"]) for r in refs)
    merged = sorted((m for m in found if m is not None),
                    key=lambda m: (m["merged_at"], m["ref"]))
    if not merged:
        raise SystemExit("every discovered pull request was skipped — refusing to "
                         "issue a credential that claims nothing")
    for m in merged:
        print(f"  verified  {m['ref']:<40} merged {m['merged_at']}")

    credential = build(config, badge, merged)
    os.makedirs("build", exist_ok=True)
    os.makedirs("credentials/achievements", exist_ok=True)
    for path, doc in (("build/contributions.unsigned.json", credential),
                      ("credentials/achievements/contributions.json",
                       {"@context": credential["@context"][:2],
                        **credential["credentialSubject"]["achievement"]})):
        with open(path, "w") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"  wrote     {path}")
    # The signer needs the same two values; hand them over instead of re-deriving
    # them in shell. The proof timestamp comes from the data, so re-running changes
    # nothing.
    with open("build/params.env", "w") as f:
        f.write(f"VERIFICATION_METHOD=did:web:{config['domain']}#{config['keys']['ed25519']['id']}\n")
        f.write(f"CREATED={credential['validFrom']}\n")
    print(f"  wrote     build/params.env")


if __name__ == "__main__":
    main()
