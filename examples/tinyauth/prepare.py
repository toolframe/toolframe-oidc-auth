"""Prepare explicitly local fixture credentials; never overwrite existing files."""

import argparse
import os
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--issuer", default="https://tinyauth.localhost:18443")
parser.add_argument("--app-origin", default="https://app.localhost:18444")
parser.add_argument("--callback")
args = parser.parse_args()
root = Path(__file__).resolve().parent
(root / "secrets").mkdir(mode=0o700, exist_ok=True)
(root / "certs").mkdir(exist_ok=True)
files = {
    ".env": "TINYAUTH_URL="
    + args.issuer
    + "\nTOOLFRAME_URL="
    + args.app_origin
    + "\nTOOLFRAME_OIDC_CALLBACK="
    + (args.callback or args.app_origin + "/_toolframe/oidc/callback/tinyauth")
    + "\n",
    "secrets/tinyauth-users": "user:$2a$10$UdLYoJ5lgPsC0RKqYH/jMua7zIn0g9kPqWmhYayJYLaZQ/FTmH2/u\n",
    "secrets/tinyauth-client-secret": "fixture-only-toolframe-client-secret-not-for-production\n",
}
for name, content in files.items():
    path = root / name
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        continue
    with os.fdopen(descriptor, "w") as handle:
        handle.write(content)
print(
    "Prepared local-only fixture. Prepare mkcert certificates as described in "
    "README.md, then run docker compose up -d --wait."
)
