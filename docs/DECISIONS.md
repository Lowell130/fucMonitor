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

Prossimi passi, in ordine:

1. Notizie: deduplica tra feed diversi, classificazione del tipo di evento, distinzione tra fatto e ipotesi.
2. NVD e CPE, exploit pubblici (Exploit-DB, Metasploit, Nuclei), altre etichette di sfruttamento.
3. Mappatura prodotto → categoria con editor e coda di revisione.
4. Dataset a livello CVE, baseline e primo modello, confronto con EPSS.
5. Aggregazione per categoria e pagina Previsioni.
6. Segnali live, poi frontend React.
