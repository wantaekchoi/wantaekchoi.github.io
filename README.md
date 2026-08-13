# wantaekchoi.github.io

[한국어](README.ko.md) — Identity and credential endpoints, rendered and signed by
GitHub Actions on every run: <https://wantaekchoi.github.io>

```bash
gh repo create <your-username>.github.io --template wantaekchoi/wantaekchoi.github.io --public --clone
cd <your-username>.github.io && ./setup.sh
```

`setup.sh` checks the name, makes the key, and tells you what to do with the
backup sheet. Nothing here is edited by hand afterwards.
