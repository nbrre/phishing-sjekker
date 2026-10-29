import pathlib
import unittest
from types import SimpleNamespace

from phishing_sjekker.regler import analyser
from phishing_sjekker import ki

EKS = pathlib.Path(__file__).resolve().parent.parent / "eksempler"


class TestRegler(unittest.TestCase):
    def test_falsk_dnb_er_hoy_risiko(self):
        res = analyser((EKS / "dnb_falsk.eml").read_text(encoding="utf-8"))
        regler = {f.regel for f in res.funn}
        self.assertEqual(res.nivaa, "høy")
        for forventet in ("hastverk", "sensitiv_info", "reply_to", "falsk_avsender", "lenke_maske"):
            self.assertIn(forventet, regler)

    def test_posten_sms_er_mistenkelig(self):
        res = analyser((EKS / "posten_toll.txt").read_text(encoding="utf-8"))
        self.assertIn("forkortet_lenke", {f.regel for f in res.funn})
        self.assertIn(res.nivaa, ("middels", "høy"))

    def test_vanlig_epost_er_lav(self):
        res = analyser((EKS / "vanlig_jobbsvar.eml").read_text(encoding="utf-8"))
        self.assertEqual(res.nivaa, "lav")
        self.assertEqual(res.funn, [])

    def test_offisielt_domene_gir_ikke_lookalike(self):
        res = analyser("Se https://www.dnb.no/privat og https://vipps.no")
        self.assertNotIn("lookalike", {f.regel for f in res.funn})

    def test_lookalike_domene(self):
        res = analyser("Logg inn: https://vipps-sikker.com/bekreft")
        self.assertIn("lookalike", {f.regel for f in res.funn})


class FalskKlient:
    """Later som den er Claude, så vi kan teste uten API-nøkkel."""

    def __init__(self):
        self.kall = None
        self.messages = self

    def create(self, **kwargs):
        self.kall = kwargs
        blokk = SimpleNamespace(type="tool_use", input={
            "konklusjon": "phishing", "sikkerhet": 95,
            "grunner": ["Lenken går til en IP-adresse"], "rad": "Ikke klikk. Slett e-posten."})
        return SimpleNamespace(content=[blokk])


class TestKI(unittest.TestCase):
    def test_vurder_bruker_verktoy_og_returnerer_dict(self):
        tekst = (EKS / "dnb_falsk.eml").read_text(encoding="utf-8")
        klient = FalskKlient()
        svar = ki.vurder(tekst, analyser(tekst), klient=klient)
        self.assertEqual(svar["konklusjon"], "phishing")
        self.assertEqual(klient.kall["tool_choice"]["name"], "vurdering")
        self.assertIn("<epost>", klient.kall["messages"][0]["content"])


if __name__ == "__main__":
    unittest.main()
