#!/usr/bin/env python3
"""Convert mdoc credentials from an eudi-dev wallet into this wallet's store.

`eudi issue mdoc` can mint any doctype, which makes it a quick source of test
credentials -- but only `--wallet` binds the document to a holder key, and
that key stays in the eudi wallet. Without the key a credential is
unpresentable: the wallet would store it and then fail device authentication
with nothing to say about why.

So this reads both halves. The credential comes from the eudi wallet's
store, the key from `holder.pem` beside it -- one key shared by every
credential that wallet holds -- and the two are checked against each other
before anything is written.

    eudi issue mdoc --wallet --doc-type eu.europa.ec.eudi.employee.1 \\
        --namespace eu.europa.ec.eudi.employee.1 --claims @claims.json
    tools/eudi_to_wallet.py --all > credentials.json

Then either hand the JSON to `FlutterWallet.instance.addCredentials()`, or on
a debug build push it straight into the app:

    adb shell run-as <package> sh -c 'cat > files/wallet_credentials.json' \\
        < credentials.json

That file is the whole store, so pushing it replaces everything the wallet
holds. Registration happens at app start, so restart the app afterwards.

What you get is a software-keyed credential signed by the eudi demo CA: good
enough to exercise matching, labels and a verifier that trusts that CA, and
no evidence at all about hardware-backed keys.

Needs `openssl` and `eudi` on PATH; no Python dependencies.
"""

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

DEFAULT_WALLET_DIR = Path.home() / ".eudi-dev" / "wallet"
LOCALE = "en-US"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def run(argv, stdin=None) -> bytes:
    result = subprocess.run(argv, input=stdin, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"{argv[0]} failed: {result.stderr.decode().strip()}")
    return result.stdout


def holder_key(pem: Path):
    """The holder key as the store wants it, plus its public point.

    PKCS#8 because `loadECPrivateKey` hands the bytes to PKCS8EncodedKeySpec,
    and holder.pem is SEC1.
    """
    if not pem.exists():
        sys.exit(f"no holder key at {pem}; has this wallet issued anything?")
    pkcs8 = run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem), "-outform", "DER"])
    spki = run(["openssl", "ec", "-in", str(pem), "-pubout", "-outform", "DER"])
    point = spki[-65:]
    if point[0] != 0x04:
        sys.exit("holder key is not an uncompressed P-256 point")
    return pkcs8, spki, point[1:33], point[33:65]


def device_key(raw: str):
    """What the MSO says the credential is bound to, via `eudi decode`."""
    decoded = json.loads(run(["eudi", "decode", "--json", raw]))
    key = decoded.get("deviceKey") or {}
    return bool(key.get("bound")), key.get("coseKey") or {}


def label(element: str) -> str:
    """A display name for an element id, since the eudi store keeps none.

    Guessed, not authoritative: `employment_start_date` becomes "Employment
    Start Date", which is what our own issuer happens to call it.
    """
    acronyms = {"Id": "ID", "Url": "URL", "Uri": "URI"}
    words = element.replace("_", " ").title().split()
    return " ".join(acronyms.get(word, word) for word in words)


def first_sentence(text: str, limit: int = 80) -> str:
    sentence = (text or "").split(". ")[0].strip()
    return sentence if len(sentence) <= limit else sentence[:limit].rstrip() + "…"


def convert(cred: dict, pkcs8: bytes, spki: bytes, x: bytes, y: bytes, strict: bool) -> dict:
    raw = cred["raw"]
    bound, cose = device_key(raw)
    problem = None
    if not bound:
        problem = "not bound to any holder key -- issue it with --wallet"
    elif cose.get("x") != b64u(x) or cose.get("y") != b64u(y):
        problem = "bound to a different key than holder.pem"
    if problem:
        message = f"{cred['id']}: {problem}"
        if strict:
            sys.exit(message)
        print(f"warning: {message}", file=sys.stderr)

    doctype = cred["doctype"]
    paths = []
    for key in sorted(cred.get("claims", {})):
        namespace, _, element = key.partition(":")
        paths.append(
            {
                "path": [namespace, element],
                "display": [{"name": label(element), "locale": LOCALE}],
            }
        )

    display = cred.get("display") or {}
    title = display.get("name") or doctype
    subtitle = first_sentence(display.get("description", ""))

    return {
        "id": cred["id"],
        "config": {
            "format": "mso_mdoc",
            "doctype": doctype,
            # Both shapes, because issuers disagree about where claims live
            # and the wallet reads either.
            "claims": paths,
            "credential_metadata": {
                "display": [
                    {"name": title, "locale": LOCALE, "description": subtitle}
                ],
                "claims": paths,
            },
        },
        "displayData": {"title": title, "subtitle": subtitle},
        "credentials": [
            {
                "key": {
                    "type": "SOFTWARE",
                    "publicKey": base64.b64encode(spki).decode(),
                    "privateKey": b64u(pkcs8),
                },
                "credential": raw,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--wallet-dir", type=Path, default=DEFAULT_WALLET_DIR)
    parser.add_argument("--id", action="append", default=[],
                        help="credential id to convert (repeatable)")
    parser.add_argument("--all", action="store_true",
                        help="convert every mdoc the wallet holds")
    parser.add_argument("--strict", action="store_true",
                        help="fail instead of warning when a credential has no usable key")
    parser.add_argument("--out", type=Path, help="write here instead of stdout")
    args = parser.parse_args()

    if not args.all and not args.id:
        parser.error("give --id, or --all")

    store = args.wallet_dir / "wallet.json"
    if not store.exists():
        sys.exit(f"no eudi wallet at {store}")
    credentials = json.loads(store.read_text()).get("credentials", [])

    mdocs = [c for c in credentials if c.get("format") == "mso_mdoc"]
    if args.id:
        by_id = {c["id"]: c for c in mdocs}
        missing = [i for i in args.id if i not in by_id]
        if missing:
            sys.exit(f"no mdoc credential with id {', '.join(missing)}")
        mdocs = [by_id[i] for i in args.id]
    if not mdocs:
        sys.exit("that wallet holds no mdoc credentials")

    pkcs8, spki, x, y = holder_key(args.wallet_dir / "holder.pem")
    out = [convert(c, pkcs8, spki, x, y, args.strict) for c in mdocs]

    text = json.dumps(out, indent=2)
    if args.out:
        args.out.write_text(text + "\n")
        print(f"wrote {len(out)} credential(s) to {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
