#!/usr/bin/env bash
# One-time setup. Generates the signing key, puts it in this repository's
# secrets, writes a backup sheet for you to keep, and starts the first run.
#
#   ./setup.sh
#
# Run it once, from a clone of your own copy. After that there is nothing to
# edit: every merged public pull request you authored is discovered on each run.
# The key stays in GitHub and you never need it locally again.
set -euo pipefail

SECRET=DID_ED25519_PRIVATE_B64
BACKUP_DIR=${BACKUP_DIR:-./backup}

die() { printf '\n%s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

command -v gh      >/dev/null || die "gh is not installed: https://cli.github.com"
command -v openssl >/dev/null || die "openssl is not installed"
command -v python3 >/dev/null || die "python3 is not installed"
gh auth status >/dev/null 2>&1 || die "gh is not logged in. Run: gh auth login"

REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner) \
  || die "not inside a GitHub repository"
OWNER=${REPO%%/*}
NAME=${REPO##*/}

[ "$NAME" = "$OWNER.github.io" ] || die \
"this repository is named '$NAME', but GitHub only serves a user site from
'$OWNER.github.io'. Rename it in Settings, or the .well-known endpoints will
sit under a project path where did:web cannot find them."

step "1/8  Repository"
echo "  $REPO  ->  https://$OWNER.github.io/"

step "2/8  Signing key"
if gh secret list --repo "$REPO" 2>/dev/null | grep -q "^$SECRET"; then
  die "$SECRET already exists on $REPO.
Setup will not overwrite a key that is already signing credentials. To replace
it deliberately, delete the secret and read the rotation note in README.md -
a new key needs two runs before credentials validate."
fi
KEYDIR=$(mktemp -d)
trap 'rm -rf "$KEYDIR"' EXIT
openssl genpkey -algorithm ED25519 -out "$KEYDIR/did-ed25519.pem"
chmod 600 "$KEYDIR/did-ed25519.pem"
# stdin, never --body: an argv value is visible to any `ps` while the call runs.
base64 < "$KEYDIR/did-ed25519.pem" | tr -d '\n' | gh secret set "$SECRET" --repo "$REPO"
echo "  generated and stored as $SECRET"

step "3/8  Configuration"
python3 - "$OWNER" <<'PY'
import datetime, json, sys
owner = sys.argv[1]
config = json.load(open("config.json"))
config["domain"] = f"{owner}.github.io"
config["github_username"] = owner
config["security_txt"]["contact"] = f"https://github.com/{owner}"
config["security_txt"]["canonical"] = f"https://{owner}.github.io/.well-known/security.txt"
# Every date in here is read by the pipeline and never by a clock, so setup is
# the one place they can be set. Inheriting the template author's dates means
# inheriting their expiry: the weekly cron would start failing on someone
# else's calendar, for a file the new owner never edited.
today = datetime.datetime.now(datetime.timezone.utc).date()
year = (today.replace(year=today.year + 1)).isoformat() + "T00:00:00Z"
config["security_txt"]["expires"] = year
config["security_txt"]["preferred_languages"] = "en"
config["domain_linkage"] = {"valid_from": today.isoformat() + "T00:00:00Z",
                            "valid_until": year}
with open("config.json", "w") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"  config.json points at {owner}.github.io, dated {today}, expiring {year[:10]}")
PY

step "4/8  Backup sheet"
mkdir -p "$BACKUP_DIR"
DID="did:web:$OWNER.github.io" BACKUP_DATE="$(date +%F)" \
  python3 scripts/backup/render.py "$KEYDIR/did-ed25519.pem:gh-ed25519" --out "$BACKUP_DIR"
python3 scripts/backup/verify_sheet.py "$BACKUP_DIR" "$KEYDIR/did-ed25519.pem:gh-ed25519"

step "5/8  GitHub Actions"
if [ "$(gh repo view --json isFork -q .isFork)" = "true" ]; then
  # A fork keeps its workflows disabled until someone clicks through. Nothing
  # else in this script would notice: `gh workflow run` just reports no runs.
  gh api -X PUT "repos/$REPO/actions/permissions" -F enabled=true >/dev/null 2>&1 || true
  if ! gh api "repos/$REPO/actions/permissions" -q .enabled 2>/dev/null | grep -q true; then
    die "this is a fork, and GitHub keeps a fork's workflows disabled until you
enable them by hand. Nothing will build until you do:

    https://github.com/$REPO/actions

Click 'I understand my workflows, go ahead and enable them', then re-run this
script. Creating from the template instead of forking avoids this entirely:

    gh repo create $OWNER.github.io --template $REPO --public --clone"
  fi
  echo "  fork detected, workflows enabled"
else
  echo "  enabled"
fi

step "6/8  Landing page"
python3 - "$OWNER" <<'LANDING'
import re, sys
owner = sys.argv[1]
page = open("index.html").read()
page = re.sub(r"(?<=<title>)[^<]*", owner, page)
page = re.sub(r"(?<=<h1>)[^<]*", owner, page)
page = page.replace("wantaekchoi.github.io", owner + ".github.io")
open("index.html", "w").write(page)
print("  index.html now announces " + owner)
LANDING

step "7/8  GitHub Pages"
if gh api "repos/$REPO/pages" >/dev/null 2>&1; then
  echo "  already enabled"
else
  gh api -X POST "repos/$REPO/pages" -f build_type=workflow >/dev/null
  echo "  enabled, deploying from Actions"
fi

step "8/8  First run"
git add config.json index.html
git diff --cached --quiet || {
  git commit -qm "Point the configuration at $OWNER"
  git push -q
  echo "  pushed; the workflow is starting"
}
gh workflow run publish --repo "$REPO" 2>/dev/null || true

cat <<EOF

Done. Watch it with:  gh run watch --repo $REPO

  https://$OWNER.github.io/.well-known/did.json
  https://$OWNER.github.io/credentials/contributions.json

Before anything else, deal with $BACKUP_DIR:

  The secret cannot be read back out of GitHub, so that sheet is the only
  remaining copy of the key. Print it, or store it somewhere you trust, then
  shred the files:

      rm -P $BACKUP_DIR/backup.*

From here you never touch the key again, and you never add contributions by
hand: each run discovers every merged public pull request you authored, checks
it against the GitHub API, re-signs, and refuses to publish anything the
1EdTech validator rejects. To leave one out, add its owner/repo#123 ref to the
"exclude" list in badge.json.
EOF
