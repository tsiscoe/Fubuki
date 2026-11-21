#!/usr/bin/env python3
"""HKP/HTTPS OpenPGP Public Key Fetch Utility for Fubuki (`authorized_keys/`).

Resolves ASCII-armored OpenPGP public keys from standard HTTPS HKP keyservers
(such as `https://keys.openpgp.org/pks/lookup` or `https://pgp.mit.edu/pks/lookup`)
and stores them atomically into `./authorized_keys/<user>.asc` (`O_EXCL` unless `--force`).
"""

from __future__ import annotations

import argparse
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request

SAFE_USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ARMOR_BLOCK_RE = re.compile(
    r"(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)",
    re.DOTALL,
)


def fetch_keyserver_key(
    query: str,
    username: str | None = None,
    keys_dir: str = "./authorized_keys",
    keyserver_url: str = "https://keys.openpgp.org/pks/lookup",
    force: bool = False,
) -> bool:
    """Fetch an ASCII-armored PGP public key over HTTPS and store `<user>.asc` safely."""
    parsed = urllib.parse.urlparse(keyserver_url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        print("[-] Error: Only HTTPS keyserver URLs are permitted.", file=sys.stderr)
        return False

    query_clean = query.strip()
    if not query_clean:
        print("[-] Error: Search query cannot be empty.", file=sys.stderr)
        return False

    target_name = (username or query_clean).strip()
    if not SAFE_USER_RE.match(target_name):
        print(
            "[-] Error: Output username must match ^[A-Za-z0-9_-]{1,64}$ "
            "(pass --user <safe_alias> when querying by email or fingerprint).",
            file=sys.stderr,
        )
        return False

    url = f"{keyserver_url}?search={urllib.parse.quote(query_clean)}&op=get"
    req = urllib.request.Request(url, headers={"User-Agent": "fubuki-keyfetch/0.2"})
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            content = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        print(f"[-] Keyserver fetch error: {exc}", file=sys.stderr)
        return False

    match = ARMOR_BLOCK_RE.search(content)
    if not match:
        print("[-] Error: No OpenPGP public key block detected in server response.", file=sys.stderr)
        return False

    armored_block = match.group(1).strip() + "\n"
    os.makedirs(keys_dir, exist_ok=True)
    out_file = os.path.join(keys_dir, f"{target_name}.asc")

    if force:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write(armored_block)
    else:
        try:
            fd = os.open(out_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            print(
                f"[-] Error: {out_file} already exists (pass --force to overwrite).",
                file=sys.stderr,
            )
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(armored_block)

    print(f"[+] Stored armored public key: {out_file}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch ASCII-armored public keys from HTTPS HKP keyservers into authorized_keys."
    )
    parser.add_argument("query", help="Keyserver search term (username, email, or 0xKeyID)")
    parser.add_argument("-u", "--user", help="Local authorized_keys alias (defaults to query)")
    parser.add_argument("-d", "--dir", default="./authorized_keys", help="Authorized keys directory")
    parser.add_argument(
        "-s",
        "--server",
        default="https://keys.openpgp.org/pks/lookup",
        help="HTTPS HKP lookup endpoint (e.g., https://pgp.mit.edu/pks/lookup)",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite an existing .asc file")
    args = parser.parse_args()

    ok = fetch_keyserver_key(args.query, args.user, args.dir, args.server, args.force)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
