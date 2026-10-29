# 🛡️ Phishing-sjekker

Et verktøy som vurderer om en e-post eller SMS er **phishing/svindel**. Det kombinerer en
**regelmotor** (klassiske faresignaler) med en **KI-vurdering fra Claude** som forklarer
resultatet på enkelt norsk.

*A tool that detects phishing e-mails and SMS by combining rule-based checks with an AI
(Claude) assessment. Built for Norwegian users – text and examples are in Norwegian.*

![Tester](../../actions/workflows/tester.yml/badge.svg)

## Hvorfor

Phishing er den vanligste måten angripere kommer inn i bedrifter på. Mange kjenner ikke igjen
falske meldinger fra «DNB», «Posten» eller «Vipps». Dette prosjektet viser hvordan KI kan gjøre
sikkerhetsvurderinger forståelige for vanlige brukere.

## Hvordan det fungerer

```
E-post/SMS ──► Regelmotor ──► poeng + funn ──► Claude (strukturert svar) ──► konklusjon + råd
```

**1. Regelmotor** (`phishing_sjekker/regler.py`, bare Python-standardbiblioteket) sjekker blant annet:

| Regel | Eksempel |
|---|---|
| Hastverk | «kontoen din blir stengt innen 24 timer» |
| Sensitiv info | ber om BankID, passord, kortnummer |
| Falsk avsender | navnet sier «DNB», men domenet er `dnb-verifisering.xyz` |
| Ulik svar-adresse | `Reply-To` går til et annet domene |
| Maskert lenke | teksten viser `dnb.no`, men lenken går et annet sted |
| IP-lenker, forkortede lenker, risikable domeneendelser, look-alike-domener, punycode | |

**2. KI-vurdering** (`phishing_sjekker/ki.py`) sender e-posten og regelfunnene til Claude.
Modellen må svare gjennom et **verktøykall med fast JSON-skjema**
(`konklusjon`, `sikkerhet`, `grunner`, `rad`), slik at svaret alltid kan leses av programmet.
E-posten pakkes inn i `<epost>`-markører og modellen får beskjed om å behandle den som data –
et enkelt vern mot *prompt injection* fra innholdet i e-posten.

## Kom i gang

```bash
git clone https://github.com/nbrre/phishing-sjekker.git
cd phishing-sjekker
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Sett API-nøkkelen (fra [console.anthropic.com](https://console.anthropic.com)):

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
```

**Kommandolinje:**

```bash
python -m phishing_sjekker eksempler/dnb_falsk.eml
python -m phishing_sjekker eksempler/posten_toll.txt --uten-ki   # bare regelmotor, ingen nøkkel trengs
```

**Nettside:**

```bash
streamlit run app.py
```

## Eksempel

```
$ python -m phishing_sjekker eksempler/dnb_falsk.eml --uten-ki
Regelmotor: HØY risiko (16 poeng)
  • Presser deg til å handle raskt: «innen 24 timer».
  • Ber om eller nevner sensitiv informasjon: «bankid».
  • Svar-adressen (gmail-support.ru) er et annet domene enn avsenderen (dnb-verifisering.xyz).
  • Avsendernavnet sier «DNB Kundeservice», men e-posten kommer fra dnb-verifisering.xyz.
  • Lenken viser www.dnb.no, men går egentlig til 185.22.14.9.
  • Lenke til en IP-adresse i stedet for et domene: 185.22.14.9.
```

## Tester

```bash
python -m unittest -v
```

Testene kjører uten internett og uten API-nøkkel – KI-delen testes med en falsk klient.
GitHub Actions kjører dem automatisk ved hver push.

## Videre arbeid

- Sjekke lenker mot kjente svartelister (f.eks. Google Safe Browsing)
- Lese SPF/DKIM/DMARC-resultater fra e-postheaderne
- Utvidelse til Outlook/Gmail

## Om meg

Laget av **Barre**, bachelor i informasjonsteknologi/informasjonssikkerhet.

> ⚠️ Verktøyet er et hjelpemiddel, ikke en garanti. Er du i tvil: ikke klikk, og kontakt avsenderen
> via en kanal du vet er ekte.

Lisens: MIT
