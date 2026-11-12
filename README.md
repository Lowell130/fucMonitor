# fucMonitor

Tendenze di sfruttamento delle vulnerabilità per categoria tecnologica, a livello globale.
Tendenze, non attribuzioni: nessun Paese o gruppo viene indicato come responsabile.

Questa è la prima versione: l'ambiente locale in Docker, l'archiviazione giornaliera di due
fonti reali (CISA KEV ed EPSS) e una dashboard di sviluppo per controllare la pipeline.
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
curated/<fonte>/snapshot_date=<data>/data.parquet   tabella normalizzata
state/fucmonitor.sqlite        storico delle esecuzioni
```

Ogni riga conserva sia la data a cui i dati si riferiscono sia il momento in cui sono stati
raccolti: serve più avanti per addestrare i modelli senza usare informazioni dal futuro.

## Storico EPSS

I file giornalieri EPSS passati si possono recuperare, dal 2021-04-14 in poi. Dalla dashboard,
sezione Pipeline, "Recupero dello storico EPSS", oppure:

```
docker compose exec backend python -m app.cli backfill-epss 2026-10-01 2026-10-31
```

L'indirizzo dei file storici è impostato in `FUC_EPSS_DATED_URL`. Se il recupero fallisce con
un errore 404, controlla l'indirizzo attuale su https://www.first.org/epss/data e mettilo in `.env`.

## Comandi utili

```
docker compose exec backend python -m app.cli ingest        # scarica ora tutte le fonti
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
