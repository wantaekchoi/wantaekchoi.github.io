# wantaekchoi.github.io

[한국어](README.ko.md)

Identity and credential endpoints, rendered and signed by GitHub Actions.
What is served, and where: <https://wantaekchoi.github.io>

Nothing that fails validation is published, and nothing is committed back — the
endpoints exist only on the runner and on the deployed site.

## Using this for yourself

```bash
gh repo create <your-username>.github.io --template wantaekchoi/wantaekchoi.github.io --public --clone
cd <your-username>.github.io
./setup.sh
```

The name must be `<your-username>.github.io`. `did:web` resolves a bare domain
to `/.well-known/did.json`, which only a user site serves from the root. Create
from the template rather than forking: GitHub leaves a fork's workflows disabled
until you enable them by hand.

`setup.sh` generates the signing key, stores it as a repository secret, fills in
`config.json`, writes a backup sheet, enables Pages, and starts the first run. It
refuses to touch a repository that already has a key.

**Keep the backup sheet.** The secret cannot be read back out of GitHub, so it is
the only remaining copy of the key. It carries the same 32 bytes three ways, so a
slip in one is caught by the others. Run `scripts/backup/verify_sheet.py` against
it before you trust the paper.

## Adding a contribution

Nothing to edit. Each run discovers every merged public pull request you authored
and re-checks it against the GitHub API. To drop one, put its `owner/repo#123` ref
in the `exclude` list in `badge.json`.

## Rotating the key

A credential signed with a new key cannot validate until the document announcing
that key is the one being served, so rotation takes two runs.

```bash
gh workflow run publish -f identity_only=true   # publish did.json with the new key
gh workflow run publish                          # now sign and validate against it
```

## Renewing

`config.json` carries both expiry dates. The weekly cron fails 30 days before
either lapses. Edit the file and push.
