# Criterio di successo (pre-registrato prima dei risultati)

Registrato il 15 novembre 2026, **prima** che la prima finestra prospettica si chiuda (15 dicembre
2026). Serve a evitare di decidere il successo dopo aver visto i numeri. Acronimi: EPSS = *Exploit
Prediction Scoring System* (FIRST); KEV = *Known Exploited Vulnerabilities* (CISA).

## Domanda

Il modello sperimentale **EPSS + età** produce, nel funzionamento quotidiano, **allerte migliori di
EPSS grezzo** nell'anticipare l'ingresso di una CVE nel catalogo KEV?

## Budget di allerta (quante ne esaminiamo al giorno)

**20 CVE al giorno.** È il numero che un piccolo team può triagare tra le CVE non ancora in KEV.
La valutazione confronta le prime 20 per punteggio del modello con le prime 20 per EPSS, sulla
stessa popolazione congelata, giorno per giorno (registro prospettico).

## Metrica

**precision@20 prospettica**: su ogni finestra conclusa e coperta dai dati, la quota delle 20
allerte che sono davvero entrate in KEV entro l'orizzonte (30 giorni). Confronto diretto
modello vs EPSS, pooled sulle finestre.

## Soglia di «utile»

Il modello è considerato utile solo se, a parità di budget (20/giorno):

- precision@20 del **modello ≥ 1,25 × precision@20 di EPSS** (almeno +25% relativo di allerte
  corrette), **e**
- non peggiore di EPSS sulla calibrazione (Brier) nel confronto retrospettivo già fatto.

Un miglioramento inferiore non giustifica il cambio operativo: si tiene EPSS come riferimento.

## Evidenza minima prima di concludere

Gli snapshot sono giornalieri, ma con orizzonte 30 giorni le finestre consecutive si **sovrappongono**
quasi del tutto: due giorni vicini danno quasi la stessa previsione e lo stesso esito, quindi **non**
sono osservazioni indipendenti. La decisione di successo si valuta perciò su **finestre disgiunte**
(una ogni ~30 giorni, prese senza sovrapposizione); gli snapshot giornalieri restano per il
monitoraggio continuo. Nessuna conclusione stabile prima di:

- **≥ 6 finestre disgiunte concluse e coperte** (circa sei mesi di accumulo), **e**
- **≥ 50 ingressi KEV osservati** complessivi in quelle finestre indipendenti.

La prima finestra (emessa 15 novembre, chiude 15 dicembre 2026) darà un **primo riscontro**, non una
conclusione. Fino alla soglia di evidenza, l'esito resta «dati insufficienti».

## Regola di decisione

- **Utile**: soglia superata con evidenza sufficiente → si espone una lista di allerte sperimentale,
  **separata ed etichettata**, accanto a EPSS; EPSS resta comunque il riferimento documentato.
- **Non utile / insufficiente**: si tiene EPSS; il modello resta candidato sperimentale.

## Vincoli

- Probabilità di sfruttamento e gravità delle conseguenze restano **problemi distinti**: questo
  criterio riguarda solo l'anticipazione dell'ingresso in KEV, non l'impatto (vedi
  `docs/IMPACT_SIZING.md`).
- Il bersaglio è l'ingresso nel **catalogo KEV**, non lo sfruttamento reale.
- Il candidato in valutazione **non si cambia** durante l'accumulo; una nuova versione si registra
  separatamente, preservando le previsioni precedenti.
