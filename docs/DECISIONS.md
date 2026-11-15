# Decisioni di progetto

Aggiornato al 12 novembre 2026.

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
- Backtest mese per mese che confronta i metodi usando solo ciò che era noto a ogni data: ha
  scartato il metodo iniziale (volume × quota) e ha scelto quello in uso.

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

Prossimi passi, in ordine:

1. Segnali anticipatori: scansioni aggregate da SANS ISC per porta e categoria, con rilevatore
   di impennate, affiancate alla previsione (mai fuse) e con un controllo storico — fatto — che
   misura se le impennate anticipano lo sfruttamento. Honeypot proprio o GreyNoise rimandati.
2. Esperimenti separati: misurare se exploit pubblici, notizie o scansioni aggiungono capacità
   predittiva oltre EPSS+età, tenendo distinti disponibilità di exploit, scansione e sfruttamento.
3. Notizie: raggruppamento multilingue e verifica a campione della qualità delle regole.
4. Revisione manuale della coda delle categorie, a partire dai prodotti dietro alle CVE sfruttate.
5. Aggregazione per categoria e pagina Previsioni.
6. Segnali live, poi frontend React.
