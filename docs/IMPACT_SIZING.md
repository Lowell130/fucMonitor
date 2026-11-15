# Dimensione dell'impatto (predisposizione)

Documento di preparazione. **Prevedere lo sfruttamento** di una vulnerabilità e **stimarne le
conseguenze** sono due problemi distinti e vanno tenuti separati.

## Due problemi, due dimensioni

1. **Probabilità/tempistica di sfruttamento** — ciò che il progetto misura ora: quanto è probabile,
   e quando, che una CVE entri nel catalogo KEV (modello sperimentale EPSS+età; riferimento EPSS).
   Non dice nulla su *quanto farebbe male*.
2. **Gravità delle conseguenze (impatto)** — quanto conta per *te* che quel prodotto/servizio venga
   colpito: dipende da cosa usi, da quanto è esposto e da cosa protegge. È un giudizio sul tuo
   ambiente, non una proprietà della CVE.

Le due dimensioni **non si moltiplicano alla cieca** né si fondono nel modello di probabilità. Una
priorità operativa, se la vorrai, sarà un **overlay esplicito e separato**: probabilità (misurata) ×
impatto (dichiarato da te), mostrato accanto alla probabilità, mai confuso con essa — come le
scansioni restano un flag accanto alla previsione.

## Cosa serve da te

Quali **prodotti, servizi e categorie tecnologiche** ti interessano, e con quale peso d'impatto. È
informazione sul tuo ambiente: il sistema non può inventarla. La si dichiara in una *watchlist*.

## Watchlist (scaffold, in attesa delle tue priorità)

File di esempio: `backend/app/watchlist.example.json`. Vuoto di contenuto, con lo schema pronto:

```json
{
  "version": 1,
  "note": "Prodotti/categorie che contano per noi, con un peso d'impatto. Non fuso nel modello.",
  "impact_weights": {"low": 1, "medium": 2, "high": 4},
  "categories": [
    {"category_id": "vpn_remote_access", "impact": "high", "why": "accesso perimetrale"}
  ],
  "products": [
    {"product": "vendor:product", "impact": "high", "why": "esempio; da sostituire"}
  ]
}
```

Quando la compilerai (copiandolo in `watchlist.json`), potremo:

- ordinare le allerte sperimentali anche per impatto, **in una vista separata ed etichettata**;
- riportare, accanto a ogni categoria, probabilità e peso d'impatto **distinti**, senza un unico
  numero che li mescoli.

Fino ad allora non c'è alcuna stima d'impatto attiva: il sistema continua a misurare solo la
probabilità/tempistica di ingresso in KEV. La previsione di eventi catastrofici (gravità reale delle
conseguenze) resta un obiettivo successivo e separato.
