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
- **CVE ripetute e finestre sovrapposte.** Le date mensili distano 27–35 giorni contro una
  finestra di 30, quindi le finestre d'esito consecutive di una CVE quasi non si sovrappongono.
  Una CVE ricorre come esempio (CVE, data) finché resta non elencata: ogni occasione è una
  previsione distinta. Un positivo (primo ingresso in KEV) può accadere a **una sola** data,
  perché la CVE esce dalla popolazione una volta elencata: i positivi non vengono mai contati due
  volte.
- **Anni 2023–2026 = valutazioni temporali separate**: ogni anno è un blocco disgiunto di date di
  test, valutato indipendentemente.
- Metriche: ROC-AUC entro-data (discriminazione, robusta ai pareggi) e pooled; PR-AUC; Brier con
  BSS rispetto a una previsione costante pari alla frequenza base appresa solo sull'addestramento;
  calibrazione; precisione/richiamo a parità di numero di allerte; anticipo rispetto all'ingresso
  in KEV; stabilità per anno.

## 6. Confronto con EPSS (risultati verificati)

Walk-forward a 30 giorni: **56 date mensili, 2022-03-02 → 2026-10-01, 13 985 104 esempi
(CVE × data), 881 positivi, prevalenza 6,3·10⁻⁵.**

| Modello | ROC-AUC entro-data | ROC-AUC pooled | Brier | BSS vs base-rate |
| --- | --- | --- | --- | --- |
| frequenza costante (base-rate) | — | — | 0,000063 | 0,000 |
| EPSS grezzo | 0,620 | 0,744 | 0,014995 | **−237** |
| EPSS ricalibrato (Platt, train-only) | 0,620 | 0,762 | 0,000063 | −0,003 |
| EPSS + età | **0,848** | **0,879** | 0,000063 | −0,005 |
| EPSS + trend | 0,619 | 0,762 | 0,000063 | −0,005 |
| EPSS + età + trend + is_new | 0,832 | 0,866 | 0,000063 | −0,007 |

Contributo separato delle feature (ROC-AUC entro-data): EPSS 0,620 → **+età 0,848** →
+trend 0,619. **Tutto il guadagno viene dall'età della CVE; il trend EPSS non aggiunge
praticamente nulla.** Il modello completo (0,832) è perfino leggermente sotto il solo-età,
perché il trend inutile aggiunge rumore.

Stabilità per anno (ROC-AUC, EPSS+età vs EPSS grezzo), valutazioni temporali separate:

| Anno | positivi | EPSS grezzo | EPSS+età |
| --- | --- | --- | --- |
| 2022 | 427 | 0,823 | 0,813 |
| 2023 | 92 | 0,570 | **0,723** |
| 2024 | 91 | 0,667 | **0,877** |
| 2025 | 126 | 0,608 | **0,882** |
| 2026 | 145 | 0,629 | **0,892** |

Il 2022 è anomalo: coincide con l'espansione di copertura del modello EPSS v2022.01.01 (la
popolazione raddoppia) e con un inserimento massivo di arretrati in KEV (219 positivi a marzo).
Lì l'età non aiuta, perché gli arretrati riguardano CVE vecchie. Dal 2023 in poi il guadagno
dell'età è netto e ripetuto ogni anno.

Precisione/richiamo a parità di allerte (pooled), EPSS grezzo vs EPSS+età:

| Budget/giorno | EPSS: veri positivi (richiamo) | EPSS+età: veri positivi (richiamo) |
| --- | --- | --- |
| 10 | 9 (1,0 %) | 15 (1,7 %) |
| 50 | 30 (3,4 %) | 41 (4,6 %) |
| 100 | 42 (4,8 %) | 54 (6,1 %) |

Anticipo mediano rispetto all'ingresso in KEV: ~13–15 giorni per entrambi.
**PR-AUC** ≈ 0 per tutti (prevalenza 6·10⁻⁵, dominata dai pareggi): non è la metrica guida qui.

### Interpretazione onesta

- **La differenza ROC-AUC tra EPSS grezzo e ricalibrato è un artefatto, non discriminazione.**
  Entro la stessa data i due sono **identici** (0,620 = 0,620): Platt è monotòno in EPSS e non
  può cambiare l'ordine. La differenza *pooled* (0,744 vs 0,762) nasce solo perché la
  ricalibrazione usa coefficienti diversi per ogni data, alterando la comparabilità **fra** date.
- **Il Brier migliora solo per ri-ancoraggio alla frequenza base, non per abilità.** EPSS grezzo
  come probabilità ha BSS −237 (la sua scala è per un evento più frequente). I modelli
  ricalibrati arrivano a BSS ≈ 0, cioè **eguagliano** una previsione costante pari alla
  prevalenza, ma non la battono. Nessun modello aggiunge abilità probabilistica propria sul Brier.
- **Il segnale reale è la discriminazione, e viene dall'età.** EPSS+età ordina meglio di EPSS da
  solo gli ingressi imminenti in KEV, in modo stabile dal 2023 al 2026.
- **La performance assoluta resta bassa.** Il 55 % degli ingressi KEV aveva EPSS < 0,05 alla data
  di previsione: gran parte degli inserimenti non è anticipabile da queste feature.

## 7. Cosa è stato integrato

Seguendo il principio «integra soltanto risultati giustificati»:

- Nuovo modulo `backend/app/analysis/epss_experiment.py` (riproducibile), CLI
  `epss-experiment`, endpoint `GET /api/v1/analysis/epss-experiment` (report, in cache finché non
  arrivano nuovi dati) e `GET /api/v1/analysis/epss-experiment/scores` (ordinamento sperimentale
  delle CVE odierne con **EPSS+età**, chiaramente etichettato).
- **EPSS resta il riferimento.** La previsione aggregata per categoria non è toccata; le
  scansioni non sono fuse. Lo scorer sperimentale non alimenta la previsione.
- 9 test anti-contaminazione (`backend/tests/test_epss_experiment.py`): selezione delle date di
  addestramento, esclusione delle finestre non ancora chiuse, esclusione delle CVE già elencate e
  di quelle non ancora pubblicate, trend che usa solo lo snapshot precedente, monotonicità della
  ricalibrazione, prova end-to-end.

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
0,62 → 0,85, 2023–2026), **non** sulla calibrazione (Brier) né come prova di sfruttamento reale.
