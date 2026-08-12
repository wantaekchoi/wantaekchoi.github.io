#!/usr/bin/env python3
"""Render an offline paper backup sheet for raw key material.

  python3 render.py <pem>:<label> [<pem>:<label> ...] --out DIR

Writes backup.html (printable, colour-coded) and backup.txt (plain) side by side.
Both files contain PRIVATE KEY MATERIAL: keep them local, print, then shred.

Each key is written three ways so no single transcription error is fatal:
  hex        - ground truth, recoverable with openssl alone
  RFC 1751   - key bytes <-> words, no derivation layer (S/Key heritage)
  BIP-39     - same 32 bytes, ubiquitous tooling, 8-bit SHA-256 checksum
Cross-checking the two word lists catches an error that either alone would hide.
"""
import base64, hashlib, html, os, subprocess, sys
import bip39, rfc1751, visual

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def published_form(pem: str) -> tuple:
    """(alphabet, label, value) exactly as it appears in did.json."""
    der = bip39.public_der(pem)
    if bip39.is_ed25519(pem):
        return "base58btc", "publicKeyMultibase", "z" + b58(b"\xed\x01" + der[-32:])
    raw = der[-65:]
    assert raw[0] == 4
    return "base64url", "publicKeyJwk x | y", f"{b64url(raw[1:33])} | {b64url(raw[33:])}"


def collect(pem: str, label: str) -> dict:
    seed = bip39.scalar_of(pem)
    ed = bip39.is_ed25519(pem)
    alphabet, field, value = published_form(pem)
    return dict(label=label, alg="Ed25519" if ed else "P-256", seed=seed,
                alphabet=alphabet, field=field, value=value,
                art=visual.randomart(hashlib.sha256(bip39.public_der(pem)).digest(),
                                     "Ed25519" if ed else "P-256"),
                rfc=rfc1751.encode(seed), bip=bip39.encode(seed),
                prefix=(bip39.ED25519_PKCS8_PREFIX + " + 32B  ->  PRIVATE KEY") if ed else
                       (bip39.P256_SEC1_PREFIX + " + 32B + " + bip39.P256_SEC1_SUFFIX
                        + "  ->  EC PRIVATE KEY"))


# ---------------------------------------------------------------- plain text
def as_text(keys: list, did: str, date: str) -> str:
    L = [f"{did}   paper backup   {date}", "=" * 72,
         "PRIVATE KEY MATERIAL - anyone holding this sheet holds the keys.", ""]
    for k in keys:
        L += [f"[{k['label']}]  {k['alg']}", "", k["art"], "",
              f"  {k['field']} ({k['alphabet']})", f"    {k['value']}", "",
              "  private scalar (hex)"]
        L += ["    " + " ".join(visual.chunk(k["seed"].hex(), 4)[i:i + 8]) for i in range(0, 16, 8)]
        for name, ws in (("RFC 1751 (24 words, 2-bit parity per 6 words)", k["rfc"]),
                         ("BIP-39   (24 words, 8-bit checksum, use ENTROPY not seed)", k["bip"])):
            L += ["", f"  {name}"]
            L += ["    " + "  ".join(f"{i + 1:2}.{ws[i]:<9}" for i in range(r, r + 4))
                  for r in range(0, 24, 4)]
        L += ["", f"  rebuild: {k['prefix']}", "", "-" * 72]
    L += ["", "RECOVERY", "  1. hex is enough on its own; the word lists are for handwriting.",
          "  2. RFC 1751 maps words straight to key bytes - no seed derivation.",
          "  3. BIP-39 tools must return ENTROPY (32 bytes), not seed (64 bytes).",
          "  4. Rebuild the DER above, base64 it, wrap in PEM headers, then check:",
          "       openssl pkey -in <recovered> -pubout",
          "     against the published value printed for each key.",
          "", "CONFUSABLE CHARACTERS: " + " / ".join(visual.HOMOGLYPHS)]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------- html
def _chunks_html(s: str, n: int = 4) -> str:
    return "".join(
        f'<span class="ch" style="background:{visual.chunk_color(c, i)}">{html.escape(c)}</span>'
        for i, c in enumerate(visual.chunk(s, n)))


def _words_html(ws: list, prefix_bold: bool) -> str:
    cells = []
    for i, w in enumerate(ws):
        shown = f"<b>{w[:4]}</b>{w[4:]}" if prefix_bold else w
        cells.append(f'<td class="n">{i + 1}</td><td class="w">{shown}</td>')
    rows = "".join(f'<tr class="{"odd" if r // 4 % 2 else "even"}">'
                   + "".join(cells[r:r + 4]) + "</tr>" for r in range(0, 24, 4))
    return f"<table class=words>{rows}</table>"


def as_html(keys: list, did: str, date: str) -> str:
    secs = []
    for k in keys:
        secs.append(f"""<section>
<h2>{html.escape(k['label'])} <em>{k['alg']}</em></h2>
<div class=row>
  <pre class=art>{html.escape(k['art'])}</pre>
  <div class=pub>
    <h3>{html.escape(k['field'])}</h3>
    <p class=mono>{_chunks_html(k['value'].replace(' | ', '|'), 4)}</p>
    <p class=note>{html.escape(visual.ALPHABET_NOTE[k['alphabet']])}</p>
    <h3>private scalar (hex)</h3>
    <p class=mono>{_chunks_html(k['seed'].hex(), 4)}</p>
  </div>
</div>
<h3>RFC 1751 <em>key bytes &harr; words, no derivation layer &middot; 2-bit parity per 6 words</em></h3>
{_words_html(k['rfc'], False)}
<h3>BIP-39 <em>same 32 bytes &middot; 8-bit checksum &middot; tools must return ENTROPY, not seed</em></h3>
{_words_html(k['bip'], True)}
<p class=note>rebuild: <code>{html.escape(k['prefix'])}</code></p>
</section>""")
    homo = "".join(f"<li><span class=mono>{html.escape(p)}</span></li>" for p in visual.HOMOGLYPHS)
    return f"""<title>{html.escape(did)} paper backup</title>
<style>
:root{{--fg:#111;--line:#bbb;--warn:#a00}}
*{{box-sizing:border-box}}
body{{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif;
color:var(--fg);background:#fff;max-width:52em;margin:2em auto;padding:0 1.5em}}
h1{{font-size:1.3em;margin:0}}
h2{{font-size:1.1em;border-bottom:2px solid var(--fg);padding-bottom:.2em;margin:0 0 .8em}}
h3{{font-size:.85em;text-transform:uppercase;letter-spacing:.06em;margin:1.2em 0 .4em}}
em{{font-style:normal;font-weight:400;font-size:.78em;color:#555;text-transform:none;letter-spacing:0}}
.warn{{border:2px solid var(--warn);color:var(--warn);padding:.6em .9em;font-weight:600;margin:1em 0}}
.mono,code,pre{{font-family:ui-monospace,"SF Mono",Menlo,monospace}}
.ch{{padding:.15em .1em;letter-spacing:.05em}}
.mono{{font-size:1.05em;word-break:break-all;line-height:2}}
.row{{display:flex;gap:1.5em;align-items:flex-start;flex-wrap:wrap}}
.art{{font-size:11px;line-height:1.15;margin:0;border:1px solid var(--line);padding:.4em}}
.pub{{flex:1;min-width:18em}}
.note{{font-size:.8em;color:#555;margin:.3em 0}}
table.words{{border-collapse:collapse;width:100%;font-size:.95em}}
table.words td{{border:1px solid var(--line);padding:.28em .4em}}
td.n{{width:2.2em;text-align:right;color:#777;font-size:.8em;background:#fafafa}}
td.w{{font-family:ui-monospace,Menlo,monospace;letter-spacing:.04em}}
tr.odd td.w{{background:#f2f2f2}}
section{{margin:2.5em 0}}
ul{{columns:3;font-size:.85em;padding-left:1.2em}}
@media print{{body{{margin:0;max-width:none;font-size:11px}}
section{{break-inside:avoid;page-break-inside:avoid}}
.ch{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
</style>
<h1>{html.escape(did)} &mdash; paper backup</h1>
<p class=note>{date} &middot; print, store offline, then shred the file</p>
<p class=warn>PRIVATE KEY MATERIAL &mdash; anyone holding this sheet holds the keys.</p>
<p class=note>Each key appears three ways. <b>Hex</b> is ground truth and needs only
<code>openssl</code>. <b>RFC 1751</b> maps words straight to key bytes with no seed
derivation. <b>BIP-39</b> encodes the same 32 bytes with wider tool support. Cross-check
the two word lists: an error in one shows as a disagreement with the other. Background
colours are derived from the characters themselves, so a substituted character changes
the colour even when the glyphs look alike.</p>
{''.join(secs)}
<section>
<h2>Recovery</h2>
<ol>
<li>Word list &rarr; 32 bytes. RFC 1751 gives the bytes directly. With BIP-39 ask the tool
for <b>entropy</b> (32 bytes), never <b>seed</b> (64 bytes, PBKDF2) &mdash; that is a different value.</li>
<li>32 bytes &rarr; DER using the <code>rebuild</code> line under each key, then base64 and wrap in PEM headers.</li>
<li>Verify with <code>openssl pkey -in &lt;recovered&gt; -pubout</code> and compare against the published value above.</li>
</ol>
<h3>Confusable characters</h3>
<ul>{homo}</ul>
</section>"""


if __name__ == "__main__":
    a = sys.argv[1:]
    out = a[a.index("--out") + 1] if "--out" in a else "."
    specs = [s for s in a if ":" in s and not s.startswith("--")]
    keys = [collect(os.path.expanduser(p), l) for p, l in (s.rsplit(":", 1) for s in specs)]
    did = os.environ.get("DID", "did:web:example.com")
    date = os.environ.get("BACKUP_DATE", "")
    for name, body in (("backup.html", as_html(keys, did, date)),
                       ("backup.txt", as_text(keys, did, date))):
        path = os.path.join(os.path.expanduser(out), name)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(body)
        print(f"wrote {path}")
