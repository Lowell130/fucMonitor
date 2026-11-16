# Decisioni di progetto

Aggiornato al 16 novembre 2026.

## Obiettivo

App locale, a costo zero, che stima quali categorie tecnologiche verranno sfruttate e in che
finestra temporale (7, 30, 90 giorni), a livello globale. Mostra tendenze, senza attribuzioni
a Paesi o gruppi.

## Dati e modelli

- Storico dal 2018-2019, aggiornamento giornaliero.
- 12-15 categorie tecnologiche con identificativo stabile, più una tassonomia degli eventi
  (sfruttamento di vulnerabilità, cyber-fisico/OT, falsi allarmi e disturbo, ransomware, violazioni di dati).
- Livello CVE come base, aggregazione per categoria come obiettivo.
- Etichette di sfruttamento da più fonti, tenute separate. EPSS è la baseline da battere.
- Survival analysis per il tempo allo sfruttamento. Valutazione walk-forward con Brier score,
  PR-AUC e calibrazione.
- Dati point-in-time: ogni riga ha la data di riferimento e il momento di raccolta.

## Notizie

- Fonti primarie e giornali, in italiano e in inglese, con deduplica multilingue.
- Estrazione di CVE, prodotti e categorie, con livello di confidenza e distinzione tra fatto e ipotesi.
- Si salvano metadati ed entità, non gli articoli completi.
- Test di ablation per capire se le notizie migliorano le previsioni.

## App

- Backend Python/FastAPI, DuckDB su Parquet, SQLite per lo stato. L'API è l'unica porta di accesso ai dati.
- Ora: dashboard Streamlit di sviluppo. Poi: frontend React/TypeScript sulla stessa API.
- Aree previste: Panoramica, Previsioni, Categoria, Segnali, Controllo.
- Tre livelli di lettura: Semplice, Dettagliato, Esperto. Provenienza di ogni numero ed esportazione dei dati.
- Interfaccia in inglese e italiano, inglese come riferimento.
- Uso personale e locale: nessuna autenticazione per ora.

## Stato

Fatto:

- Ambiente Docker locale, API, scheduler, storico delle esecuzioni.
- Archiviazione giornaliera di CISA KEV ed EPSS, recupero dello storico EPSS.
- Dashboard di sviluppo bilingue: Panoramica, Pipeline, KEV, EPSS.
- Bozza della tassonomia (15 categorie, 6 tipi di evento), non ancora usata dai dati.
- Raccolta grezza oraria di notizie e avvisi da feed RSS in italiano e inglese, con estrazione dei CVE citati.

- Etichette derivate sulle notizie, da regole a parole chiave: tipo di evento, segnale di sfruttamento,
  solidità (fonte ufficiale, riportato, rivendicazione o ipotesi), settori citati, raggruppamento della
  stessa notizia tra feed diversi nella stessa lingua.

- Catalogo NVD completo (CVE, CVSS, CWE, prodotti CPE), aggiornato in modo incrementale.
- Exploit pubblici da Metasploit, Nuclei ed Exploit-DB, tenuti separati per fonte.
- Profilo unificato di un CVE: NVD, KEV, EPSS, exploit pubblici e citazioni nelle notizie.

- Mappatura prodotto → categoria tecnologica: regole a parole chiave, assegnazioni manuali
  prioritarie e coda di revisione ordinata per impatto.

- Tassi storici di sfruttamento per categoria (30/90/365 giorni, con censura corretta) e
  tempo allo sfruttamento.
- Previsione per categoria basata sul tasso recente di sfruttamento, con intervalli di Poisson.
- Backtest mese per mese che confronta i metodi: date di pubblicazione e sfruttamento
  point-in-time a ogni data, ma categoria di ogni CVE dal catalogo e dalla mappatura attuali (non
  ricostruita alla data). Ha scartato il metodo iniziale (volume × quota) e ha scelto quello in
  uso. Limite: la dimensione *categoria* è una ricostruzione retrospettiva, non un fatto as-of.

Limiti noti delle notizie:

- Le regole sono semplici e sbagliano su una parte degli elementi. Ogni etichetta riporta la versione delle regole.
- La stessa notizia in italiano e in inglese non viene ancora raggruppata: serve un modello multilingue.
- Il feed Microsoft pubblica una voce per ogni CVE, quindi pesa molto sui conteggi degli avvisi.

Modello a livello CVE vs EPSS (fatto, vedi `docs/EXPERIMENT_EPSS_CVE.md`):

- Bersaglio: ingresso nel catalogo KEV entro 30 giorni (non la data reale di sfruttamento).
- Valutazione walk-forward, 56 date mensili 2022-03→2026-10, 881 positivi, senza contaminazioni
  temporali (9 test anti-leakage). Metriche: ROC-AUC entro-data e pooled, PR-AUC, Brier con BSS
  rispetto alla frequenza base, precisione/richiamo a parità di allerte, anticipo, stabilità.
- Risultato: EPSS+età ordina gli ingressi imminenti in KEV meglio di EPSS da solo (ROC-AUC
  entro-data 0,64 → 0,87, stabile 2023–2026). **Tutto il guadagno viene dall'età della CVE; il
  trend EPSS non aggiunge nulla.** La ricalibrazione non cambia l'ordine (monotòna) e sul Brier
  eguaglia soltanto la frequenza base. Performance assoluta bassa; bersaglio = catalogo, non
  sfruttamento reale. EPSS resta il riferimento; la previsione aggregata non è toccata.
- Integrato come esperimento separato: endpoint `epss-experiment` e scorer sperimentale EPSS+età,
  mai fusi nella previsione per categoria.
- Ablation exploit pubblici (`epss-experiment --exploit-ablation`, endpoint `.../exploit-ablation`):
  feature point-in-time «esiste un exploit pubblico (Exploit-DB/Metasploit) entro D», tenuta
  distinta da scansioni e da sfruttamento confermato. Risultato: da solo l'exploit ordina debolmente
  (ROC entro-data 0,61, segnale in calo negli anni) e **aggiunto a EPSS+età non cambia il ranking**
  (0,87→0,88, pooled identico, inconsistente fra anni). Decisione: **non** aggiungere la feature
  exploit; EPSS+età resta il modello sperimentale. Limite: la `provider_date` dice quando l'exploit
  è apparso, ma il collegamento exploit↔CVE è quello corrente (nessuno snapshot storico), quindi è
  una **ricostruzione retrospettiva approssimata**, forse ottimista — e anche così non aiuta.
  Nuclei escluso perché senza data.

Prossimi passi, in ordine:

1. Segnali anticipatori: scansioni aggregate da SANS ISC per porta e categoria, con rilevatore
   di impennate, affiancate alla previsione (mai fuse) e con un controllo storico — fatto — che
   misura se le impennate anticipano lo sfruttamento. Honeypot proprio o GreyNoise rimandati.
2. Esperimenti separati sul contributo oltre EPSS+età, a disponibilità di exploit, scansione e
   sfruttamento distinti:
   - **exploit pubblici — fatto, nessun contributo** (ricostruzione approssimata, vedi sopra).
   - **notizie — storico insufficiente oggi** (~4 giorni; `first_seen_at`, non recuperabile
     all'indietro). Nessun esperimento ora; sonda di prontezza
     `news-readiness`/`news_history_readiness` (soglia ~365 giorni) e protocollo futuro
     documentato (feature «CVE citata entro D», walk-forward a finestre disgiunte, periodo finale
     tenuto fuori dalla scelta delle feature). Lo storico cresce in avanti dalla raccolta.
   - **scansioni — fatto, nessun beneficio misurabile.** Verifica dedicata a livello di categoria
     (`scan-experiment`, endpoint `scan-forecast-experiment`): previsione attuale (recent_rate) vs
     previsione + scansioni, walk-forward con β scelto solo sull'addestramento e **periodo finale
     di hold-out** escluso dalla scelta; metriche su hold-out = errore dei conteggi (MAE/RMSE),
     copertura degli intervalli, allerte catturate a parità di budget. Risultato (orizzonte 90,
     hold-out 7 date, 582 eventi): β=0 già in addestramento → nessun miglioramento; le **scansioni
     restano un flag**, non fuse nella previsione. Coerente con `signal_check`. Limite: lato
     scansioni la valutazione è **retrospettiva e approssimata** — conserviamo solo il valore
     corretto successivamente (niente prima-disponibilità né revisioni) e quasi tutto è backfillato
     ~1 anno dopo. Preparata la verifica futura: `scans.py` ora registra il valore di prima
     osservazione (`first_sources`/`first_seen_at`) in avanti, così un run futuro sarà verificabile.
     Chiarimenti nel report: MAE/RMSE sono in **numero di vulnerabilità per categoria per finestra**;
     gli intervalli hanno copertura **nominale 95%** (Byar/Poisson) contro il 71% osservato (la
     previsione corre bassa); l'incertezza dalle sole 7 date di hold-out è riportata come CI 90%
     bootstrap a livello di data; β=0 è descritto come assenza di beneficio della **combinazione
     provata** (forecast × (1+β·relu(z))), non come prova che nessuna forma possa aiutare.
     `first_seen_at` è il momento in cui *noi* abbiamo memorizzato il valore, mai una disponibilità
     alla data osservata: va confrontato con `observed_date` (un divario ampio = backfill).

Consolidamento e valutazione prospettica (fatto):

- **Valutazione prospettica silenziosa** (`prediction_log.py`): ogni giorno lo scheduler congela,
  in un log **append-only** (`data/derived/predictions`, mai sovrascritto), l'ordinamento del
  modello CVE (EPSS+età) **insieme a quello di EPSS grezzo** (top-N di ciascuno, stessa popolazione
  congelata), con data di emissione, versione del modello e firma degli input. Consolidamento:
  1. salva modello **ed EPSS originale** insieme, per un confronto prospettico equo;
  2. valuta **solo finestre realmente concluse e coperte dai dati** (ultima `date_added` KEV ≥ fine
     finestra), altrimenti resta in attesa;
  3. protegge lo storico con **scrittura atomica** (temp + replace) e **copia di sicurezza**;
  4. registra in `_runs.jsonl` **esecuzioni, fallimenti, dati troppo vecchi** (`stale_inputs`) e
     **giornate saltate**;
  5. `score-prospective` confronta precision@k di **modello vs EPSS**. Verifica reale, senza
     ricostruzione retrospettiva. Endpoint `POST predictions/snapshot`, `GET predictions/prospective`.
- **Esperimento scansioni, separazione temporale corretta**: embargo di un orizzonte tra training e
  hold-out — le date di training la cui finestra d'esito arriva nel periodo di hold-out vengono
  scartate, così la scelta di β non usa informazioni dal periodo di valutazione.
- **Modello per singola CVE e previsione per categoria restano distinti**: il log prospettico
  riguarda solo il modello CVE; la previsione per categoria ha il suo backtest e la sua verifica
  scansioni.
- **Notizie**: si lascia accumulare lo storico (sonda `news-readiness`); nessuna valutazione del
  contributo finché non è pronto.
3. Notizie (contenuto app): raggruppamento multilingue e verifica a campione della qualità delle regole.
   - *Controllo qualità notizie (fatto, solo misura — non tocca il modello).* Endpoint
     `GET /api/v1/news/quality`. Tiene gli avvisi **interi** ma li separa in tre lenti: **avvisi
     tecnici** (feed ufficiali), **attenzione editoriale** (stampa specializzata e generalista) e
     **segnalazioni di incidenti** (etichetta di tipo incidente, trasversale; riportate, non
     verificate). Il **grafico di attenzione** (`news/trend`, osservatorio incluso) **esclude per
     default i feed per singola vulnerabilità** (Microsoft MSRC: una voce per CVE, ~75% degli
     articoli), filtro reso **esplicito** con vista completa accessibile. Le **lacune di raccolta**
     distinguono **fallimenti** (un run è fallito, dallo stato operativo), **giorni quieti** (run
     eseguito, nulla di nuovo) e **nessun run**; i feed silenziosi sono marcati «in errore» se lo
     stato lo indica. **Onestà sul campione**: il campione è **solo generato, non revisionato** →
     `label_quality_measured: false`; il tasso di errore delle etichette e dei duplicati **non è
     misurato** finché qualcuno non etichetta il campione. Da non dichiarare «qualità misurata»
     prima di quel controllo.
4. Revisione della coda delle categorie, a partire dai prodotti dietro alle CVE sfruttate.
   - *Fatto, primo giro (regole, versione `2026.11.16-1`).* Sulla coda reale, i prodotti non
     classificati con più peso sono quelli dietro CVE **già in KEV**: alla revisione risultavano 280
     CVE KEV su 1779 senza categoria (16%) e **zero** assegnazioni manuali. Aggiunte regole mirate per
     le famiglie emerse: F5 (BIG-IQ/Enterprise Manager/Traffix), Cisco (ISE→identity, ASYNCOS→security
     appliance, UCM→collaboration, SD-WAN→network edge), file-transfer/condivisione (Accellion, CrushFTP,
     Gladinet), mail server (SmarterMail), storage (Oracle ZFS/StorageTek, IBM Storwize), agent di
     gestione Microsoft (System Center, OMI, Log Analytics, Container Monitoring→remote management),
     più JetBrains TeamCity, LiteLLM, SysAid, Red Hat Fuse/CodeReady, Mitel, 3DS Delmia Apriso,
     Telerik, Gigabyte. **Corretto un bug reale**: `dnnsoftware:dotnetnuke` sfuggiva perché la regola
     era `^dotnetnuke` (ancorata) mentre il vendor è `dnnsoftware`. Scelta documentata: le piattaforme
     software di comunicazione unificata (UCM, MiCollab) vanno in `mail_collaboration`, accanto a
     Teams/Zoom/Mattermost; i telefoni/edge (Avaya, Polycom) restano in `router_network_edge` com'erano.
   - *Effetto sulle misure (non sul candidato).* Cambia solo l'assegnazione prodotto→categoria, quindi
     i **denominatori per categoria** dell'osservatorio e la baseline `recent_rate` per categoria; **non**
     tocca il modello CVE sperimentale né il registro prospettico. Le assegnazioni restano riproducibili
     dalle regole + eventuali decisioni manuali (storico versionato); le regole sono coperte da test.
     Meccanismo, delta misurato e snapshot per categoria: `docs/CATEGORY_COVERAGE.md`.
5. **Aggregazione per categoria — che cosa esiste già e che cosa manca** (una baseline c'è già).
   - *Esiste.* `analysis/exploitation.py::forecast` (metodo `recent_rate`): per ogni categoria, il
     conteggio atteso di CVE che entrano in KEV nell'orizzonte = volume recente di pubblicazioni ×
     tasso storico censurato per orizzonte, con intervallo di Byar/Poisson. È **descrittiva**, non un
     modello, calcolata uguale ogni volta; è la baseline che l'Osservatorio mostra come
     `category_forecast` e che qualsiasi modello deve battere. La previsione per categoria **non è
     scoperta**: manca semmai di *validazione prospettica* propria (oggi ha solo il backtest).
   - *Manca, ma con cautela.* Un'eventuale aggregazione **per categoria dei punteggi del modello
     sperimentale** (EPSS+età) non è ancora giustificata: quei punteggi battono EPSS **solo
     sull'ordinamento**, e sul Brier non migliorano la frequenza base (vedi esperimento). Sommare
     punteggi non calibrati **non** produce automaticamente un conteggio atteso affidabile per
     categoria (un ranking non è una probabilità). Regola: **non aggregare i punteggi sperimentali
     come probabilità o conteggi attesi** finché non esiste una calibrazione per categoria validata
     in modo prospettico. Fino ad allora la baseline `recent_rate` resta l'unica stima di conteggio
     per categoria; il modello sperimentale resta una **lista di allerte ordinata**, separata.
   - *Lavoro definito (senza toccare il candidato).* (a) dare alla previsione per categoria una
     verifica prospettica propria, analoga al registro CVE (conteggi attesi vs osservati per
     finestra, copertura degli intervalli); (b) solo dopo, valutare se una calibrazione per categoria
     del punteggio sperimentale aggiunge qualcosa, come esperimento separato e misurato.
6. Pagina Previsioni e segnali live, poi frontend React.
