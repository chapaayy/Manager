"""Generate a candidate Caddyfile with one reversible v2 site.

Used only when the EXISTING XPPN v1 Caddy owns HTTPS/80/443.
The installer validates and reloads the candidate inside that running Caddy
container; this script alone never writes or reloads the live Caddyfile.
"""
import argparse
from pathlib import Path
import re
import sys
from .setup_env import DOMAIN, SetupError

START = "# BEGIN XPPN-V2 MANAGED SITE"
END = "# END XPPN-V2 MANAGED SITE"


def candidate(old: str, domain: str) -> str:
    if not DOMAIN.fullmatch(domain):
        raise SetupError("Некорректный домен для Caddy")
    if old.count(START) != old.count(END) or old.count(START) > 1:
        raise SetupError("В Caddyfile повреждён блок XPPN v2. Ничего не перезаписываем.")
    if START in old:
        left, rest = old.split(START, 1)
        _, right = rest.split(END, 1)
        old = left + right
    # Protect existing v1 and manually administered virtual hosts.
    if re.search(r"(?m)^\s*" + re.escape(domain) + r"\s*\{", old):
        raise SetupError("Домен уже используется другим сайтом Caddy")
    block = (
        "\n" + START + "\n"
        + domain + " {\n"
        + "    encode zstd gzip\n"
        + "    header {\n"
        + '        Strict-Transport-Security "max-age=31536000"\n'
        + '        X-Content-Type-Options "nosniff"\n'
        + '        Referrer-Policy "no-referrer"\n'
        + "    }\n"
        + "    reverse_proxy manager-v2:8000\n"
        + "}\n"
        + END + "\n"
    )
    return old.rstrip() + "\n" + block


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()
    source = Path(args.original)
    proposed = Path(args.candidate)
    if not source.is_file():
        raise SetupError("Caddyfile прежнего менеджера не найден")
    original = source.read_text(encoding="utf-8")
    updated = candidate(original, args.domain)
    proposed.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError) as e:
        print("Caddy: " + str(e), file=sys.stderr)
        raise SystemExit(1)
