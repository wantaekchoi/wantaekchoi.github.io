# wantaekchoi.github.io

[한국어](README.ko.md)

Identity and credential endpoints, rendered and signed by GitHub Actions.

| | |
|---|---|
| [`/.well-known/did.json`](https://wantaekchoi.github.io/.well-known/did.json) | `did:web:wantaekchoi.github.io` |
| [`/.well-known/security.txt`](https://wantaekchoi.github.io/.well-known/security.txt) | RFC 9116 |
| [`/.well-known/did-configuration.json`](https://wantaekchoi.github.io/.well-known/did-configuration.json) | DIF domain linkage |
| [`/credentials/contributions.json`](https://wantaekchoi.github.io/credentials/contributions.json) | Open Badges 3.0 |
| [`/credentials/achievements/contributions.json`](https://wantaekchoi.github.io/credentials/achievements/contributions.json) | the achievement it awards |

Every run rebuilds all five, signs the two credentials with `eddsa-rdfc-2022`,
and puts each through a validator. The badge goes through 1EdTech's
`OB30Inspector`; the domain linkage, which `OB30Inspector` rejects out of hand,
is checked against the DID document rendered in the same run. Nothing that
fails is published, and nothing is committed back: the endpoints exist only on
the runner and on the deployed site.

## Using this for yourself

```bash
gh repo create <your-username>.github.io --template wantaekchoi/wantaekchoi.github.io --public --clone
cd <your-username>.github.io
./setup.sh
```

The name must be `<your-username>.github.io`. `did:web` resolves a bare domain
to `/.well-known/did.json`, which only a user site serves from the root.

Create from the template rather than forking: GitHub leaves a fork's workflows
disabled until you enable them by hand.

`setup.sh` generates the signing key, stores it as a repository secret, fills in
`config.json` (dating both expiry fields a year out), writes a backup sheet,
enables Pages, and starts the first run. It refuses to touch a repository that
already has a key.

**Keep the backup sheet.** The secret cannot be read back out of GitHub, so it
is the only remaining copy of the key. It carries the same 32 bytes three ways,
so a slip in one is caught by the others. Run `scripts/backup/verify_sheet.py`
against it before you trust the paper.

## Adding a contribution

Nothing to edit. Each run discovers every merged public pull request you
authored, re-checks it against the GitHub API, and lists it as evidence. To drop
one, put its `owner/repo#123` ref in the `exclude` list in `badge.json`.

## Rotating the key

A credential signed with a new key cannot validate until the document
announcing that key is the one being served, so rotation takes two runs.

```bash
gh workflow run publish -f identity_only=true   # publish did.json with the new key
gh workflow run publish                          # now sign and validate against it
```

## Layout

```
config.json                 domain, username, key id, both expiry dates
badge.json                  the achievement wording, and refs to leave out
pipeline/                   renders the endpoints and both credentials
signer/                     signs with eddsa-rdfc-2022, then proves the result
contexts/                   JSON-LD contexts, pinned by hash; signing never fetches
scripts/backup/             paper backup: render, verify, restore
scripts/lint-workflows.py   fails on an unpinned action or a broken block scalar
.github/workflows/          the one workflow that does all of the above
```

The weekly cron watches both expiry dates in `config.json` and fails 30 days
before either lapses. Renew by editing the file and pushing.
