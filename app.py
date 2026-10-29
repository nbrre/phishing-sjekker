"""Enkel nettside for phishing-sjekkeren. Start med:  streamlit run app.py"""
import os

import streamlit as st

from phishing_sjekker.regler import analyser

st.set_page_config(page_title="Phishing-sjekker", page_icon="🛡️")
st.title("🛡️ Phishing-sjekker")
st.write("Lim inn en e-post eller SMS. Regelmotoren sjekker kjente tegn på svindel, og Claude gir en vurdering med forklaring.")

tekst = st.text_area("E-post eller SMS", height=250, placeholder="Lim inn hele meldingen her …")
bruk_ki = st.toggle("Bruk KI-vurdering (krever ANTHROPIC_API_KEY)", value=bool(os.getenv("ANTHROPIC_API_KEY")))

if st.button("Sjekk", type="primary") and tekst.strip():
    res = analyser(tekst)
    farge = {"lav": "green", "middels": "orange", "høy": "red"}[res.nivaa]
    st.subheader(f"Regelmotor: :{farge}[{res.nivaa.upper()} risiko] ({res.poeng} poeng)")
    for f in res.funn:
        st.write(f"• {f.forklaring}")
    if not res.funn:
        st.write("Ingen kjente faresignaler funnet.")

    if bruk_ki:
        from phishing_sjekker.ki import vurder

        with st.spinner("Claude vurderer meldingen …"):
            try:
                v = vurder(tekst, res)
            except Exception as feil:  # vis feilen pent i stedet for å krasje
                st.error(f"KI-vurderingen feilet: {feil}")
            else:
                farge = {"trygg": "green", "mistenkelig": "orange", "phishing": "red"}[v["konklusjon"]]
                st.subheader(f"KI: :{farge}[{v['konklusjon'].upper()}] – {v['sikkerhet']} % sikker")
                for g in v["grunner"]:
                    st.write(f"• {g}")
                st.info(v["rad"])

st.caption("Verktøyet er et hjelpemiddel, ikke en garanti. Er du i tvil: ikke klikk, og kontakt avsenderen via en kanal du vet er ekte.")
