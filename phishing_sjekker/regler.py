"""Regelbasert analyse av e-post (fungerer uten internett og uten API-nøkkel).

Hver regel gir poeng og en forklaring. Summen gir en foreløpig risikovurdering
som også sendes med til KI-modellen som ekstra kontekst.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import parseaddr
from urllib.parse import urlparse

HASTE_ORD = [
    "haster", "umiddelbart", "innen 24 timer", "kontoen din blir stengt",
    "siste varsel", "bekreft nå", "suspendert", "urgent", "immediately",
    "account will be closed", "verify now", "final notice", "within 24 hours",
]
SENSITIVE_ORD = [
    "passord", "bankid", "kortnummer", "cvc", "personnummer", "fødselsnummer",
    "password", "credit card", "social security", "login details",
]
PENGE_ORD = [
    "gavekort", "bitcoin", "krypto", "overfør", "betal gebyr", "toll",
    "gift card", "wire transfer", "refund", "tilbakebetaling",
]
KJENTE_MERKER = ["dnb", "posten", "nav", "skatteetaten", "vipps", "bring", "microsoft", "apple", "paypal", "netflix"]
URL_FORKORTERE = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
RISIKO_TLD = {".zip", ".mov", ".xyz", ".top", ".click", ".country", ".gq", ".tk", ".ru"}

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
ANKER_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)


@dataclass
class Funn:
    regel: str
    poeng: int
    forklaring: str


@dataclass
class Resultat:
    funn: list[Funn] = field(default_factory=list)

    @property
    def poeng(self) -> int:
        return sum(f.poeng for f in self.funn)

    @property
    def nivaa(self) -> str:
        if self.poeng >= 6:
            return "høy"
        if self.poeng >= 3:
            return "middels"
        return "lav"


def _domene(adresse: str) -> str:
    return adresse.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in adresse else ""


def _offisielt(vert: str, merke: str) -> bool:
    """Sant hvis vert er merkets eget domene (f.eks. dnb.no eller www.dnb.no)."""
    return any(vert == f"{merke}{t}" or vert.endswith(f".{merke}{t}") for t in (".no", ".com"))


def _vertsnavn(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def les_epost(raa_tekst: str) -> tuple[str, str, str, str]:
    """Returnerer (avsender, reply_to, emne, brødtekst). Godtar både rå e-post med
    headere og vanlig innlimt tekst."""
    if re.match(r"^(from|to|subject|received|return-path|reply-to|date|message-id|mime-version|delivered-to):\s", raa_tekst.lstrip(), re.IGNORECASE):
        msg = message_from_string(raa_tekst)
        deler = []
        if msg.is_multipart():
            for del_ in msg.walk():
                if del_.get_content_type() in ("text/plain", "text/html"):
                    nyttelast = del_.get_payload(decode=True)
                    if nyttelast:
                        deler.append(nyttelast.decode(del_.get_content_charset() or "utf-8", "replace"))
        else:
            nyttelast = msg.get_payload(decode=True)
            deler.append(nyttelast.decode(msg.get_content_charset() or "utf-8", "replace") if nyttelast else str(msg.get_payload()))
        return msg.get("From", ""), msg.get("Reply-To", ""), msg.get("Subject", ""), "\n".join(deler)
    return "", "", "", raa_tekst


def analyser(raa_tekst: str) -> Resultat:
    avsender, reply_to, emne, tekst = les_epost(raa_tekst)
    res = Resultat()
    liten = f"{emne}\n{tekst}".lower()
    avs_navn, avs_adr = parseaddr(avsender)
    avs_dom = _domene(avs_adr)

    treff = [o for o in HASTE_ORD if o in liten]
    if treff:
        res.funn.append(Funn("hastverk", 2, f"Presser deg til å handle raskt: «{treff[0]}»."))
    treff = [o for o in SENSITIVE_ORD if o in liten]
    if treff:
        res.funn.append(Funn("sensitiv_info", 3, f"Ber om eller nevner sensitiv informasjon: «{treff[0]}»."))
    treff = [o for o in PENGE_ORD if o in liten]
    if treff:
        res.funn.append(Funn("penger", 2, f"Handler om betaling eller uvanlige betalingsmåter: «{treff[0]}»."))

    if reply_to and avs_dom:
        rt_dom = _domene(parseaddr(reply_to)[1])
        if rt_dom and rt_dom != avs_dom:
            res.funn.append(Funn("reply_to", 2, f"Svar-adressen ({rt_dom}) er et annet domene enn avsenderen ({avs_dom})."))

    if avs_navn and avs_dom:
        for merke in KJENTE_MERKER:
            if merke in avs_navn.lower() and not _offisielt(avs_dom, merke):
                res.funn.append(Funn("falsk_avsender", 3, f"Avsendernavnet sier «{avs_navn}», men e-posten kommer fra {avs_dom}."))
                break

    for href, synlig in ANKER_RE.findall(tekst):
        synlig_url = URL_RE.search(re.sub(r"<[^>]+>", "", synlig))
        if synlig_url and _vertsnavn(synlig_url.group()) != _vertsnavn(href):
            res.funn.append(Funn("lenke_maske", 3, f"Lenken viser {_vertsnavn(synlig_url.group())}, men går egentlig til {_vertsnavn(href)}."))
            break

    sett = set()
    for url in URL_RE.findall(tekst):
        vert = _vertsnavn(url)
        if not vert or vert in sett:
            continue
        sett.add(vert)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", vert):
            res.funn.append(Funn("ip_lenke", 3, f"Lenke til en IP-adresse i stedet for et domene: {vert}."))
        elif vert in URL_FORKORTERE:
            res.funn.append(Funn("forkortet_lenke", 1, f"Forkortet lenke skjuler hvor du havner: {vert}."))
        elif any(vert.endswith(t) for t in RISIKO_TLD):
            res.funn.append(Funn("risiko_domene", 2, f"Domene med endelse som ofte brukes i svindel: {vert}."))
        elif vert.startswith("xn--") or ".xn--" in vert:
            res.funn.append(Funn("punycode", 3, f"Domenet bruker spesialtegn som kan etterligne et kjent navn: {vert}."))
        else:
            for merke in KJENTE_MERKER:
                if merke in vert and not _offisielt(vert, merke):
                    res.funn.append(Funn("lookalike", 2, f"Domenet {vert} ligner på {merke}, men er ikke det offisielle."))
                    break
    return res
