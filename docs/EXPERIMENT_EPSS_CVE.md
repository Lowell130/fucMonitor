# Esperimento: previsione a livello di singola CVE vs EPSS

Aggiornato al 15 novembre 2026. Codice: `backend/app/analysis/epss_experiment.py`.
Riproducibile con `docker compose exec backend python -m app.cli epss-experiment --horizon 30`
(oppure l'endpoint `GET /api/v1/analysis/epss-experiment`).

**Acronimi.** CVE = singola vulnerabilità catalogata. EPSS (*Exploit Prediction Scoring
System*, FIRST) = punteggio 0–1 che stima la probabilità che una CVE sia sfruttata entro 30
giorni. KEV (*Known Exploited Vulnerabilities*, CISA) = catalogo delle vulnerabilità di cui è
stato **osservato** lo sfruttamento. NVD = *National Vulnerability Database* (data di
pubblicazione, CVSS, prodotti). ROC-AUC = area sotto la curva ROC, qualità dell'ordinamento
(0.5 = caso, 1.0 = perfetto). PR-AUC = area sotto precisione-richiamo. Brier = errore
quadratico medio di una probabilità. BSS (*Brier Skill Score*) = 1 − Brier/Brier(riferimento).

## 1. Il bersaglio osservato

Per una previsione fatta alla data D, **esito positivo = la CVE entra nel catalogo KEV entro i
successivi H giorni** (primo `date_added` in (D, D+H]). Questo è l'**ingresso nel catalogo
KEV**, non la data reale di inizio dello sfruttamento, che è precedente e non osservata.
L'assenza da KEV significa «non osservata in questa fonte», non «mai sfruttata». Ogni numero qui
misura la capacità di anticipare **quella fonte**. Probabilità di sfruttamento e gravità delle
conseguenze restano concetti distinti: qui si tratta solo di probabilità/tempistica di un
inserimento in KEV.

## 2. Copertura temporale utilizzabile (verificato)

- **370 snapshot EPSS**, dal 2021-04-14 al 2026-11-14. Cadenza settimanale fino ad agosto 2026,
  poi giornaliera (93 giorni). Lacune: 278 settimanali, 90 giornaliere, 1 di quattro giorni.
- **5 versioni del modello EPSS** nello storico (v1, v2022.01.01, v2023.03.01, v2025.03.14,
  v2026.06.15). La scala del punteggio cambia tra versioni: la ricalibrazione è appresa
  localmente nel tempo (walk-forward), quindi il cambio di versione non falsa il confronto.
- **Tutti gli snapshot storici sono `backfilled`**: ricostruiti ora dai file datati pubblicati
  da FIRST. È una **ricostruzione retrospettiva fedele** di «EPSS a quella data», non una
  cattura dal vivo fatta allora (quella è iniziata solo pochi giorni fa). Limite dichiarato.
- **KEV** `date_added`: data d'ingresso nel catalogo, ricostruibile point-in-time (fedele).
- **NVD** `published`: stabile, quindi point-in-time sicura. **CVSS, CWE e prodotti sono esclusi**
  perché NVD è archiviato solo come stato corrente: il loro valore a una data passata non è
  ricostruibile senza contaminazione dal futuro.

Distinzione chiave: EPSS-alla-data e ingresso-in-KEV-alla-data sono ricostruibili fedelmente;
lo stato tecnico NVD (CVSS/prodotti/categoria) **no**. Perciò il modello base usa solo feature
sicure (EPSS corrente, trend EPSS, età della CVE).

## 3. Domanda predittiva e popolazione

Alla data D la popolazione è ogni CVE che: (a) ha un punteggio EPSS nello snapshot vicino a D;
(b) è già pubblicata in NVD (`published ≤ D`); (c) **non è ancora in KEV** (`date_added` nullo o
> D). Le CVE già in KEV sono escluse: si prevede un **primo** ingresso. Orizzonte di partenza:
**30 giorni**, coerente con EPSS. Il punteggio EPSS a 30 giorni non va reinterpretato come
probabilità a 7 o 90 giorni.

## 4. Feature (tutte point-in-time sicure)

| Inclusa | Motivo |
| --- | --- |
| `logit(EPSS a D)` | la baseline da battere, usata grezza e ricalibrata |
| trend EPSS ~28 giorni | EPSS(D) − EPSS(snapshot ~28g prima); 0 se non ancora presente (flag `is_new`) |
| `log1p(età in giorni)` | D − data di pubblicazione; le CVE fresche entrano in KEV molto più spesso |

Escluse: CVSS, CWE, prodotti/categoria (non ricostruibili point-in-time → rischio di
contaminazione). Exploit pubblici, notizie e scansioni non entrano qui: andranno misurati in
esperimenti separati, come richiesto.

## 5. Protocollo di valutazione (senza contaminazioni)

- **Walk-forward, nessuna suddivisione casuale.** Date di test: uno snapshot EPSS al mese il cui
  intero esito a H giorni è già trascorso. All'addestramento di ogni data D si usano **solo** le
  date di test precedenti la cui finestra si era già chiusa entro D (`_train_dates`), così ogni
  etichetta d'addestramento era interamente osservabile allora.
- I negativi sono sottocampionati per l'addestramento e **ri-pesati** per preservare la
  calibrazione; le metriche sono sempre calcolate sulla **popolazione intera** a D.
- **CVE ripetute e finestre sovrapposte.** Le date di test sono scelte a **distanza ≥ orizzonte**
  (`_eval_dates`): qui 30–35 giorni l'una dall'altra per una finestra di 30, quindi le finestre
  d'esito `(D, D+30]` sono **disgiunte per costruzione** — un ingresso in KEV cade in al più una
  finestra e non è mai contato due volte. Una CVE ricorre come esempio (CVE, data) solo finché
  resta non elencata; appena entra in KEV è esclusa da ogni data successiva, quindi un positivo
  (primo ingresso) è contato a **esattamente una** data. Un ingresso che cade nel piccolo
  intervallo tra la fine di una finestra e lo snapshot successivo non è contato da nessuna parte
  (scelta conservativa), mai due volte. Il report espone `windows_disjoint: true`.
- **Anni 2023–2026 = valutazioni temporali separate**: ogni anno è un blocco disgiunto di date di
  test, valutato indipendentemente.
- Metriche: ROC-AUC entro-data (discriminazione, con ranghi medi sui pareggi) e pooled; PR-AUC
  (punti operativi solo ai confini dei gruppi di punteggio uguale, quindi robusta ai pareggi);
  Brier con BSS rispetto a una previsione costante pari alla frequenza base appresa solo
  sull'addestramento; calibrazione; precisione/richiamo a parità di numero di allerte (conteggio
  *atteso* dei positivi quando il budget cade dentro un gruppo di punteggi uguali); anticipo
  rispetto all'ingresso in KEV; stabilità per anno.

## 6. Confronto con EPSS (risultati verificati)

Walk-forward a 30 giorni: **50 date di test (distanza ≥ 30 giorni), 2022-02-09 → 2026-10-11,
12 517 734 esempi (CVE × data), 778 positivi, prevalenza 6,2·10⁻⁵.** Finestre disgiunte (distanza
min 30, mediana 35, max 35 giorni).

| Modello | ROC-AUC entro-data | ROC-AUC pooled | Brier | BSS vs base-rate |
| --- | --- | --- | --- | --- |
| frequenza costante (base-rate) | — | — | 0,000062 | 0,000 |
| EPSS grezzo | 0,644 | 0,738 | 0,014887 | **−238,5** |
| EPSS ricalibrato (Platt, train-only) | 0,644 | 0,752 | 0,000062 | −0,000 |
| EPSS + età | **0,874** | **0,888** | 0,000062 | −0,002 |
| EPSS + trend | 0,642 | 0,717 | 0,001158 | −17,6 |
| EPSS + età + trend + is_new | 0,864 | 0,846 | 0,001267 | −19,4 |

Contributo separato delle feature (ROC-AUC entro-data): EPSS 0,644 → **+età 0,874** →
+trend 0,642. **Tutto il guadagno viene dall'età della CVE; il trend EPSS non aggiunge nulla.**
Il solo-età (EPSS+età) è anche il **meglio calibrato** (Brier 0,000062): aggiungere trend e
is_new peggiora la calibrazione (Brier 0,00116–0,00127, BSS −17…−19) senza migliorare il ranking.
Quindi il modello da preferire è **EPSS+età**.

Stabilità per anno (ROC-AUC, EPSS+età vs EPSS grezzo), valutazioni temporali separate:

| Anno | positivi | EPSS grezzo | EPSS+età |
| --- | --- | --- | --- |
| 2022 | 358 | 0,838 | 0,865 |
| 2023 | 90 | 0,593 | **0,756** |
| 2024 | 91 | 0,631 | **0,902** |
| 2025 | 112 | 0,620 | **0,892** |
| 2026 | 127 | 0,628 | **0,893** |

Il 2022 è anomalo (espansione di copertura del modello EPSS v2022.01.01 e inserimento massivo di
arretrati in KEV): lì EPSS grezzo è già alto e l'età aggiunge poco. Dal 2023 in poi il guadagno
dell'età è netto e ripetuto ogni anno.

Precisione/richiamo a parità di allerte **per data di valutazione** (non al giorno; veri positivi
*attesi* per via dei pareggi), EPSS grezzo vs EPSS+età:

| Allerte/data | EPSS: veri positivi attesi (richiamo) | EPSS+età: veri positivi attesi (richiamo) |
| --- | --- | --- |
| 10 | 10 (1,3 %) | 16 (2,1 %) |
| 50 | 31 (4,0 %) | 38 (4,9 %) |
| 100 | 50 (6,4 %) | 56 (7,2 %) |

**PR-AUC** ≈ 0 per tutti (prevalenza 6·10⁻⁵): non è la metrica guida qui.

### Interpretazione onesta

- **La differenza ROC-AUC tra EPSS grezzo e ricalibrato è un artefatto, non discriminazione.**
  Entro la stessa data i due sono **identici** (0,644 = 0,644): Platt è monotòno in EPSS e non
  può cambiare l'ordine. La differenza *pooled* (0,738 vs 0,752) nasce solo perché la
  ricalibrazione usa coefficienti diversi per ogni data, alterando la comparabilità **fra** date.
- **Il Brier non migliora: nessun modello batte la frequenza costante.** EPSS grezzo come
  probabilità ha BSS −238 (la sua scala è per un evento più frequente). I modelli ricalibrati
  arrivano a BSS leggermente *negativo* (ricalibrato −0,000, EPSS+età −0,002): sono **un filo
  peggiori** di una previsione costante pari alla prevalenza, non migliori. Nessun modello aggiunge
  abilità probabilistica: il valore è solo nell'ordinamento, non nei valori di probabilità.
- **Il segnale reale è la discriminazione, e viene dall'età.** EPSS+età ordina meglio di EPSS da
  solo gli ingressi imminenti in KEV, in modo stabile dal 2023 al 2026.
- **La performance assoluta resta bassa.** Il 55 % degli ingressi KEV aveva EPSS < 0,05 alla data
  di previsione: gran parte degli inserimenti non è anticipabile da queste feature.

## 6-bis. Ablation: gli exploit pubblici aggiungono segnale? (verificato: no)

Esperimento **separato** (`epss-experiment --exploit-ablation`), come richiesto dal prompt:
«aggiungi exploit pubblici solo con esperimenti separati che ne misurino il contributo», tenendo
distinti **disponibilità di exploit**, attività di scansione e sfruttamento confermato. Feature:
«esiste un exploit pubblico (Exploit-DB o Metasploit) con data della fonte ≤ D».

**Limite temporale (importante): ricostruzione retrospettiva approssimata.** La `provider_date`
indica quando l'*exploit* è apparso secondo la fonte, ma **non** garantisce che il *collegamento*
exploit↔CVE fosse disponibile allora: il catalogo è stato raccolto ora (`first_seen` recente) e
abbiamo solo la mappatura **corrente**, senza snapshot storici del legame. Un riferimento CVE può
essere stato aggiunto a una voce Exploit-DB molto dopo la pubblicazione, quindi «ha un exploit
entro D» può essere **ottimista**. Non è quindi un fatto point-in-time come EPSS-alla-data o
l'ingresso in KEV, ma una ricostruzione approssimata. Poiché anche così non aggiunge nulla, il
risultato negativo vale *a maggior ragione*. Nuclei è escluso perché privo di data (copertura
parziale).

| Modello | ROC-AUC entro-data | ROC-AUC pooled |
| --- | --- | --- |
| solo-exploit | 0,61 | 0,71 |
| EPSS + età | 0,875 | 0,890 |
| EPSS + età + exploit | 0,882 | 0,890 |

L'exploit **da solo** ordina debolmente e il suo segnale **cala negli anni** (2022: 0,76 →
2026: 0,55). **Aggiunto a EPSS+età non cambia il ranking** (0,875 → 0,882 entro-data, pooled
identico, guadagno non consistente fra gli anni; a 100 allerte/data gli stessi 55 veri positivi).
Decisione: **non** aggiungere la feature exploit; EPSS+età resta il modello sperimentale. Restano
da misurare, con lo stesso protocollo e come feature separate, scansioni e notizie.

## 6-ter. Notizie: storico insufficiente oggi (documentato, valutazione futura preparata)

Le notizie sono modellate sulla **prima osservazione** (`first_seen_at`) e **non sono recuperabili
all'indietro**: i feed RSS restituiscono solo una finestra recente, quindi lo storico utile cresce
solo in avanti dal giorno in cui è iniziata la raccolta. Allo stato: **~4 giorni** di storico
(2026-11-12 → 2026-11-15, ~5 400 item), **zero** finestre di 30 giorni valutabili. Un confronto
walk-forward credibile con EPSS+età è impossibile ora.

Non viene eseguito alcun esperimento sulle notizie: sarebbe non credibile. È invece pronta una
**sonda di prontezza** (`GET /api/v1/analysis/epss-experiment/news-readiness`,
`epss_experiment.news_history_readiness`) che riporta quanto storico esiste e se è sufficiente
(soglia: ~365 giorni di raccolta). Protocollo previsto quando sarà pronto: feature «la CVE è stata
citata in una notizia raccolta entro D» (`first_seen_at ≤ D`), stesso walk-forward a finestre
disgiunte e stesse metriche dell'ablation exploit, con exploit/scansioni/notizie tenute distinte, e
un **periodo finale (gli ultimi mesi) tenuto fuori** da ogni scelta di feature o soglia, usato solo
per il confronto finale. Fino ad allora EPSS+età resta invariato.

## 7. Cosa è stato integrato

Seguendo il principio «integra soltanto risultati giustificati»:

- Nuovo modulo `backend/app/analysis/epss_experiment.py` (riproducibile), CLI
  `epss-experiment` (con `--exploit-ablation`), endpoint `GET /api/v1/analysis/epss-experiment`
  (report, in cache finché non cambiano gli input), `.../scores` (ordinamento sperimentale delle
  CVE odierne con **EPSS+età**, etichettato) e `.../exploit-ablation`.
- **EPSS resta il riferimento.** La previsione aggregata per categoria non è toccata; le
  scansioni non sono fuse. Lo scorer sperimentale non alimenta la previsione; la feature exploit
  non è stata aggiunta perché non migliora (§6-bis).
- La cache si invalida su una firma che traccia versione del codice e ultimi snapshot
  EPSS/KEV/NVD (e exploits per l'ablation): un nuovo ingresso KEV o un catalogo aggiornato forzano
  il ricalcolo.
- 12 test anti-contaminazione (`backend/tests/test_epss_experiment.py`): selezione delle date di
  addestramento, distanza ≥ orizzonte (finestre disgiunte), esclusione delle finestre non ancora
  chiuse, esclusione delle CVE già elencate e di quelle non ancora pubblicate, trend dal solo
  snapshot precedente, monotonicità della ricalibrazione, robustezza ai pareggi di PR-AUC e budget,
  feature exploit point-in-time, prove end-to-end.

## 8. Limiti

- Misura l'anticipo del **catalogo KEV**, non di tutto lo sfruttamento reale.
- `date_added` si addensa su eventi di manutenzione del catalogo (es. il backfill di marzo 2022),
  quindi la tempistica del bersaglio è in parte amministrativa.
- PR-AUC poco informativa a questa prevalenza.
- Performance assoluta bassa: la maggior parte degli ingressi non è anticipabile da EPSS+età.
- EPSS storico è ricostruito dai file datati FIRST (fedele), non catturato dal vivo allora.

## 9. Stato e prossimo passo

**Fatto (verificato):** definizione del bersaglio; copertura temporale; feature incluse/escluse
con motivazione; protocollo walk-forward senza contaminazioni; confronto con EPSS con sei
modelli; separazione dei contributi (età vs trend); test anti-contaminazione; integrazione
minima e separata.

**Ipotesi da verificare (non ancora dimostrate):** che gli exploit pubblici, le notizie o le
scansioni aggiungano capacità predittiva oltre EPSS+età — da misurare in esperimenti separati che
tengano distinti disponibilità di exploit, attività di scansione e sfruttamento confermato.

**Prossimo passo sostenuto dai risultati:** poiché il guadagno dipende solo dall'età, valutare
una codifica più ricca della recency (tempo dalla pubblicazione a fasce, interazione con EPSS) e
ripetere a 7 e 90 giorni con confronti appropriati. Non dichiarare il modello «migliore» di EPSS
oltre a quanto mostrato: batte EPSS **sull'ordinamento degli ingressi in KEV** (ROC-AUC entro-data
0,64 → 0,87), **non** sulla calibrazione (Brier) né come prova di sfruttamento reale.
