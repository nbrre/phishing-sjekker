"""Kommandolinje: python -m phishing_sjekker eksempler/dnb_falsk.eml [--uten-ki]"""
from __future__ import annotations

import argparse
import os
import sys

from .regler import analyser

FARGER = {"lav": "\033[32m", "middels": "\033[33m", "høy": "\033[31m", "trygg": "\033[32m",
          "mistenkelig": "\033[33m", "phishing": "\033[31m"}
NULL = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phishing_sjekker", description="Sjekk om en e-post er phishing.")
    p.add_argument("fil", nargs="?", help="E-postfil (.eml eller .txt). Utelat for å lese fra stdin.")
    p.add_argument("--uten-ki", action="store_true", help="Bare regelmotor, ingen API-kall.")
    a = p.parse_args(argv)

    tekst = open(a.fil, encoding="utf-8", errors="replace").read() if a.fil else sys.stdin.read()
    res = analyser(tekst)
    print(f"Regelmotor: {FARGER[res.nivaa]}{res.nivaa.upper()}{NULL} risiko ({res.poeng} poeng)")
    for f in res.funn:
        print(f"  • {f.forklaring}")

    if a.uten_ki:
        return 0
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("\n(Ingen ANTHROPIC_API_KEY satt – hopper over KI-vurderingen. Se README.)")
        return 0

    from .ki import vurder

    v = vurder(tekst, res)
    print(f"\nKI-vurdering: {FARGER.get(v['konklusjon'], '')}{v['konklusjon'].upper()}{NULL} ({v['sikkerhet']} % sikker)")
    for g in v["grunner"]:
        print(f"  • {g}")
    print(f"\nRåd: {v['rad']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
