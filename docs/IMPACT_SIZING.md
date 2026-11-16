# Dimensione dell'impatto (predisposizione)

Documento di preparazione. **Prevedere lo sfruttamento** di una vulnerabilità e **stimarne le
conseguenze** sono due problemi distinti e vanno tenuti separati.

L'overlay della watchlist è una **personalizzazione opzionale**, separata dall'osservatorio
globale: non cambia il punteggio sperimentale né il modello, e il punteggio prevede l'**ingresso
nel catalogo KEV**, non la compromissione del tuo ambiente. Non si calcola «probabilità × impatto»:
punteggio, impatto ed esposizione restano **tre dimensioni distinte**, e le allerte si raggruppano
in **fasce di priorità spiegabili**. Ciò che **non dichiari** è trattato come **sconosciuto**
(«da classificare»), **mai** come basso impatto; «**non lo uso**» (`not_used`) è un'esclusione
esplicita, diversa da «non so».

## Due problemi, due dimensioni

1. **Probabilità/tempistica di sfruttamento** — ciò che il progetto misura ora: quanto è probabile,
   e quando, che una CVE entri nel catalogo KEV (modello sperimentale EPSS+età; riferimento EPSS).
   Non dice nulla su *quanto farebbe male*.
2. **Gravità delle conseguenze (impatto)** — quanto conta per *te* che quel prodotto/servizio venga
   colpito: dipende da cosa usi, da quanto è esposto e da cosa protegge. È un giudizio sul tuo
   ambiente, non una proprietà della CVE.

Le due dimensioni **non si moltiplicano** né si fondono in un unico numero. L'overlay le tiene
distinte e aggiunge una terza colonna, l'**esposizione**: raggruppa le allerte in **fasce di
priorità spiegabili**, mostrando sempre punteggio, impatto ed esposizione separati.

## Cosa serve da te

Quali **categorie tecnologiche e prodotti** contano nel tuo ambiente, con tre informazioni per
ciascuno:

- **impatto** di un fermo/compromissione: `high` / `medium` / `low` / `not_used` (non lo uso);
- **esposizione**: `internet` (raggiungibile dall'esterno) o `internal`;
- facoltativo: *perché* (una riga).

«**Non lo uso**» (`not_used`) è un'esclusione esplicita. Ciò che **non elenchi** è **sconosciuto**,
non basso impatto: finisce nella fascia «da classificare». È informazione sul tuo ambiente, il
sistema non può inventarla.

## Watchlist (schema)

File di esempio: `backend/app/watchlist.example.json`. Copialo in `data/watchlist.json` e compilalo:

```json
{
  "version": 2,
  "categories": [
    {"category_id": "vpn_remote_access", "impact": "high", "exposure": "internet", "why": "accesso perimetrale"},
    {"category_id": "web_cms", "impact": "not_used", "why": "nessun CMS pubblico"}
  ],
  "products": [
    {"product": "vendor:product", "impact": "high", "exposure": "internet", "why": "da sostituire"}
  ]
}
```

## Fasce di priorità (spiegabili, nessuna aritmetica di fusione)

`GET /api/v1/analysis/watchlist/alerts` raggruppa le allerte così (ordine: fascia, poi esposizione
internet prima, poi punteggio sperimentale — tre chiavi in sequenza, non un prodotto):

- `priority_1_high_impact` / `priority_2_medium_impact` / `priority_3_low_impact`: la CVE tocca una
  categoria che hai marcato ad alto/medio/basso impatto;
- `needs_classification`: impatto **non dichiarato = sconosciuto**, da classificare (non basso);
- `set_aside`: tutte le categorie colpite sono `not_used`.

Filtri: `?bands=...` ed `?exposure=internet|internal`. Il punteggio sperimentale resta la
probabilità di **ingresso in KEV**, non di compromissione del tuo ambiente, e il modello non viene
toccato. La previsione della gravità reale delle conseguenze resta un obiettivo successivo e
separato.
