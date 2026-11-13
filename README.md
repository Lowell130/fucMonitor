# fucMonitor

Tendenze di sfruttamento delle vulnerabilità per categoria tecnologica, a livello globale.
Tendenze, non attribuzioni: nessun Paese o gruppo viene indicato come responsabile.

Questa è la prima versione: l'ambiente locale in Docker, l'archiviazione giornaliera di due
fonti reali (CISA KEV, EPSS, NVD e gli exploit pubblici), la raccolta oraria di notizie e
avvisi di sicurezza, e una dashboard di sviluppo per controllare la pipeline.
Modelli e previsioni arrivano nei passi successivi (vedi `docs/DECISIONS.md`).

## Avvio

Serve Docker Desktop, avviato.

```
docker compose up --build
```

- Dashboard: http://localhost:8501
- API e documentazione interattiva: http://localhost:8000/docs

Al primo avvio il backend scarica subito KEV ed EPSS. Poi ripete ogni giorno alle 06:15 e
18:15 UTC, e a ogni riavvio recupera lo snapshot di oggi se manca. I container ripartono da
soli con Docker Desktop, così lo storico continua ad accumularsi.

Per fermare: `docker compose down`. I dati restano in `./data`.

## Cosa c'è

| Cartella | Contenuto |
| --- | --- |
| `backend/` | API FastAPI, ingestione, scheduler, query DuckDB |
| `dashboard/` | Dashboard Streamlit, usa solo l'API, testi in `locales/en.json` e `it.json` |
| `data/` | Dati raccolti (esclusi da Git) |
| `docs/` | Decisioni di progetto e piano |

Dentro `data/`:

```
raw/<fonte>/<data>/            file originale così come scaricato, più meta.json
derived/                       dati ricalcolabili (etichette delle notizie)
curated/<fonte>/snapshot_date=<data>/data.parquet   tabella normalizzata
state/fucmonitor.sqlite        storico delle esecuzioni
```

Ogni riga conserva sia la data a cui i dati si riferiscono sia il momento in cui sono stati
raccolti: serve più avanti per addestrare i modelli senza usare informazioni dal futuro.

## Catalogo delle vulnerabilità (NVD)

NVD fornisce, per ogni CVE, data di pubblicazione, gravità CVSS, tipo di debolezza (CWE) e
soprattutto i **prodotti interessati** (CPE): è la base per collegare le vulnerabilità alle
categorie tecnologiche.

Il primo scarico prende l'intero catalogo (oltre 300.000 CVE) e richiede circa **15-20 minuti**
senza chiave API, pochi minuti con. Parte da solo al primo avvio e mostra l'avanzamento nella
sezione Pipeline. Gli scarichi successivi chiedono solo i record cambiati dall'ultima volta.

Una chiave API gratuita si richiede su https://nvd.nist.gov/developers/request-an-api-key e si
mette in `.env` come `FUC_NVD_API_KEY=...`: alza il limite da 5 a 50 richieste ogni 30 secondi.

NVD riscrive i record nel tempo (gravità e prodotti vengono spesso completati settimane dopo),
quindi ogni riga conserva il momento in cui è stata scaricata e viene archiviata una partizione
per giorno: lo stato attuale di un CVE è la sua riga più recente.

## Exploit pubblici

Tre fonti, tenute distinte perché sono evidenze diverse: un modulo **Metasploit** è pronto
all'uso, un template **Nuclei** di solito si limita a rilevare, una voce **Exploit-DB** è spesso
una prova di concetto. Ogni coppia exploit-CVE viene archiviata una sola volta, il giorno in cui
viene vista per la prima volta.

## Categorie tecnologiche

È il collegamento fra le vulnerabilità e l'obiettivo del progetto: le previsioni parlano di
categorie (VPN, firewall, CMS, virtualizzazione...), non di singoli prodotti.

La categoria viene assegnata al **prodotto**, non alla CVE: i prodotti distinti sono molti meno
e una decisione presa una volta vale per tutte le sue vulnerabilità. Tre livelli, in ordine di
autorità: assegnazione fatta a mano, regola a parole chiave (`backend/app/taxonomy/rules.json`),
oppure nessuna delle due e il prodotto resta "senza categoria".

Le assegnazioni manuali vincono sempre sulle regole e sopravvivono a una loro modifica. La
sezione "Categorie tecnologiche" della dashboard mostra la copertura e una coda di revisione:
i prodotti che nessuna regola ha riconosciuto, ordinati per quanto pesano (prima quelli dietro
a vulnerabilità già sfruttate). Sistemare i primi cambia i numeri più di tutti gli altri insieme.

## Previsioni

La pagina "Previsioni" risponde alla domanda di partenza — cosa potrebbe essere colpito e
quando — con una base di confronto deliberatamente semplice, non con un modello:

- **Quanto spesso accade**: la quota di vulnerabilità sfruttate entro 30, 90 o 365 giorni dalla
  pubblicazione, per categoria. Si contano solo le CVE abbastanza vecchie da avere avuto quel
  tempo, altrimenti le più recenti abbasserebbero la quota solo per non averne ancora avuto l'occasione.
- **Quanto in fretta**: i giorni fra pubblicazione e sfruttamento confermato, calcolati solo
  sulle vulnerabilità effettivamente sfruttate.
- **Attese nei prossimi N giorni**: il volume recente di CVE della categoria per il tasso storico,
  con un intervallo che mostra quanto poco dica un numero piccolo di casi.

Lo sfruttamento è datato all'inserimento in CISA KEV: più tardi dell'inizio reale e parziale,
quindi ogni numero è un minimo. La pagina lo dice, insieme agli altri limiti.

## Notizie e avvisi

Ogni ora il backend legge i feed RSS elencati in `backend/app/sources/feeds.json`: avvisi
ufficiali (CISA, CSIRT Italia, produttori), stampa di sicurezza e stampa generalista. Dalla
stampa generalista tiene solo gli articoli che contengono una delle parole chiave in
`general_keywords`.

Di ogni elemento si salvano titolo, link, un breve sommario, lingua, tipo di fonte, i CVE
citati, l'ora di pubblicazione e l'ora in cui è stato raccolto. Non si salvano gli articoli completi.

A ogni elemento vengono poi assegnate delle etichette con regole a parole chiave
(`backend/app/enrich/rules.json`): tipo di evento, se il testo riporta uno sfruttamento, quanto è
solida l'affermazione, i settori citati e la notizia a cui appartiene quando più feed la riprendono.
Sono etichette semplici, utili per vedere le tendenze, e una parte è sbagliata. Si ricalcolano
da zero a ogni modifica delle regole; i dati raccolti non vengono toccati.

Per aggiungere, correggere o sospendere un feed basta modificare `feeds.json`: la modifica
vale dalla raccolta successiva. Lo stato di ogni feed è nella sezione "Notizie e avvisi" della dashboard.

## Storico EPSS

I file giornalieri EPSS passati si possono recuperare, dal 2021-04-14 in poi (verificato il 12 novembre 2026). Dalla dashboard,
sezione Pipeline, "Recupero dello storico EPSS", oppure:

```
docker compose exec backend python -m app.cli backfill-epss 2026-10-01 2026-10-31
```

L'indirizzo dei file storici è impostato in `FUC_EPSS_DATED_URL`. Se il recupero fallisce con
un errore 404, controlla l'indirizzo attuale su https://www.first.org/epss/data e mettilo in `.env`.

## Comandi utili

```
docker compose exec backend python -m app.cli ingest        # scarica ora tutte le fonti
docker compose exec backend python -m app.cli ingest nvd    # solo il catalogo NVD
docker compose exec backend python -m pytest -q             # test del backend
docker compose exec dashboard python -m pytest -q tests     # test della dashboard
docker compose logs -f backend                              # log
```

Il codice è montato nei container: le modifiche a `backend/app` e `dashboard/` si applicano
senza ricostruire le immagini. Serve `--build` solo se cambiano i file `requirements`.

## Configurazione

Copia `.env.example` in `.env` per cambiare orari, indirizzi delle fonti o disattivare lo
scheduler. Tutto è opzionale.

Le porte sono esposte solo su `localhost` e non c'è autenticazione: non esporre l'app in rete.
