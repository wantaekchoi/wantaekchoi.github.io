# wantaekchoi.github.io

[한국어](README.ko.md) — my personal site: <https://wantaekchoi.github.io>

The page itself is one hand-written `index.html`. Everything else under
`.well-known/` and `credentials/` is rendered and signed by GitHub Actions on
every push and once a week, from `config.json` and `badge.json`. Those files
are not edited by hand.

The contribution credential lists pull requests that upstream maintainers
merged. The workflow re-checks authorship and merge status against the GitHub
API on every run and refuses to issue the credential if any listed
contribution fails that check.

`setup.sh` creates the signing key and prints the backup sheet. It is a
one-time step, kept here as the reference for rotating that key.
