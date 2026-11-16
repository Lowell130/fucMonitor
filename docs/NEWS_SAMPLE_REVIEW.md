# Revisione del campione di notizie

Prima revisione effettiva del campione prodotto da `GET /api/v1/news/quality`. Distingue due assi
che **non vanno confusi**: l'**accordo con le regole** (l'etichetta corrisponde al testo?) e la
**verifica dei fatti** (il contenuto è vero nel mondo?).

## Metodo

- Campione riproducibile: `seed=1`, 30 elementi, finestra 30 giorni, stato del 16 novembre 2026.
- Un solo revisore (Claude), lettura di titolo + sommario. Giudizio qualitativo, non uno standard
  d'oro condiviso. Numeri piccoli: indicativi, non una stima stabile.
- **Avvertenza di campionamento**: il campione è pesato sul **volume**, quindi dominato dal feed
  Microsoft MSRC (una voce per CVE, ~75% degli articoli). Misura perciò soprattutto i **casi
  facili**. Per i casi informativi si usa ora `sample_exclude_per_cve=true`.

## Asse A — accordo con le regole (misurato su questo campione)

**27/30 corretti (~90%), 3 scostamenti.** Tutti su testo libero; sulle ~18 voci MSRC strutturate
l'accordo è ~100%, quindi l'accordo sui soli elementi non-per-CVE è nettamente più basso
(3 errori su ~12 voci a testo libero).

Scostamenti:

1. **SecurityWeek, "Telegram Widgets Hit by RCE Demos"** — regola: `other`, exploitation=false. Il
   testo parla di exploitation sospetta e demo di RCE → **segnale di exploitation mancato**
   (sotto-etichettatura).
2. **BleepingComputer, "Google warns fully-automated AI attacks are coming soon"** — regola:
   `vulnerability_disclosure`. È un pezzo di tendenza, non una divulgazione → **event_type errato**
   (dovrebbe essere `other`); innescato dalle parole «vulnerability discovery and exploitation».
3. **Fortinet PSIRT, "...in fortisoc" (format string)** — regola: `other`, nessun CVE estratto. È un
   avviso di vulnerabilità → dovrebbe essere `vulnerability_disclosure`; il CVE non era nel sommario.

**Lettura**: le regole a parole chiave sono quasi perfette sugli **avvisi strutturati dei vendor** e
deboli sul **testo libero** (stampa e advisory senza CVE nel sommario), dove sia sovra-innescano
(#2 falso disclosure) sia sotto-innescano (#1 exploitation mancato, #3 disclosure mancato). Nessun
Paese o attore viene estratto, per scelta, quindi non è stato valutato.

### Secondo passaggio mirato (casi a testo libero, `sample_exclude_per_cve=true`)

Per misurare dove stanno davvero gli errori, revisione di 22 elementi **non-per-CVE** (seed=1).
**18/22 corretti (~82%), 4 scostamenti.** Difetto ricorrente e più rilevante: **segnale di
exploitation mancato** su testo libero.

1. SecurityWeek, "Telegram ... RCE Demos" — `other`/expl=false; testo = exploitation sospetta e demo
   RCE → **exploitation mancato**.
2. BleepingComputer, "AI attacks coming soon" — `vulnerability_disclosure`; è tendenza → `other`.
3. Fortinet PSIRT, "...in fortisoc" — `other`, CVE non estratto → dovrebbe essere `vulnerability_disclosure`.
4. CSIRT Italia, "N-Able: due catene di exploit ... zero-day in N-central" — `vulnerability_disclosure`/
   expl=false; descrive **catene di exploit per zero-day** → **exploitation mancato** (grave).

Funzionano bene, invece: ingressi KEV → `vulnerability_exploitation`+expl (CISA #5, #17), outage
Microsoft → `service_disruption` (#22), minaccia bomba alle scuole → `hoax_disruption` (#14), e tutti
gli advisory dei vendor con CVE nel sommario.

**Conclusione asse A**: l'accordo sui casi facili (MSRC) è ~100%, sui casi a testo libero ~82%; il
buco principale è l'**exploitation_signal** su stampa e CSIRT (parole come «catene di exploit»,
«suspected exploitation», «RCE demo» non innescano la regola). È il bersaglio di miglioramento
regole più utile, perché è l'etichetta di sicurezza più rilevante.

## Asse B — verifica dei fatti (distinta, in gran parte non stabilibile)

La verifica dei fatti **non coincide** con l'accordo con le regole e in gran parte **non è
stabilibile dalla sola notizia**:

- Le voci **ufficiali** (MSRC, CISA, Cisco, Fortinet, CSIRT) sono **divulgazioni** da fonte
  autorevole, verificabili come CVE reali, ma **non sono «incidenti»**: `claim_status=official`
  significa «da fonte primaria», non «incidente verificato».
- Le voci di **stampa** non sono verificabili dal solo articolo: #2 (Telegram) è anzi **contestato**
  dalla fonte stessa (Durov smentisce). `claim_status=reported` lo riflette correttamente.
- **Nessuno dei 30 elementi è un incidente verificato.** Confermano che il conteggio «incidenti
  verificati» non si ricava dalle notizie (serve una fonte di conferma incrociata, es. KEV).

Conclusione sull'asse B: una verifica dei fatti su larga scala **non è fattibile** dalle notizie; al
più si può confermare l'esistenza di un CVE o l'ingresso in KEV incrociando fonti autorevoli.

## Stato della misura

- **Accordo con le regole: misurato** su `seed=1`, n=30 (~90%), con l'avvertenza sul campionamento.
  Resta un solo revisore e un campione piccolo: non è ancora una stima stabile dell'accuratezza.
- **Verifica dei fatti: non misurata** per i fatti riportati dalla stampa (non stabilibile dal solo
  articolo); per le divulgazioni ufficiali è verificabile come esistenza del CVE, non come incidente.
- L'endpoint resta `label_quality_measured: false` per default: ogni campione estratto dall'API è
  *non revisionato* finché qualcuno non lo etichetta. Questa pagina documenta la revisione fatta.

## Definizione di `exploitation_signal` (fissata prima di correggere)

`exploitation_signal = true` **solo** quando la notizia riporta **sfruttamento reale osservato**:
attacchi in corso/nel mondo reale, attori nominati che sfruttano, vittime/compromissioni, o
inserimento in un catalogo di «known-exploited». È **false** per: **dimostrazioni tecniche / PoC /
demo RCE** (è *disponibilità di exploit*, tracciata a parte dalle fonti exploit-repo), **ipotesi**
(«could/may be exploited», «an attacker who successfully exploited»), **sospetti** («suspects»,
«reportedly») e **negazioni** («disputes», «no evidence»). I due significati — sfruttamento reale vs
dimostrazione tecnica — restano **separati**.

## Riesame dei quattro scostamenti contro la definizione

Nessuno dei quattro è un errore confermato di `exploitation_signal`:

- #1 Telegram: **sospetto + demo + negazione** → `false` corretto.
- #2 AI attacks: capacità generica futura, nessun evento osservato → `false` corretto (l'errore è
  solo di `event_type`, fuori ambito).
- #3 Fortinet fortisoc: **ipotetico** («may allow») → `false` corretto.
- #4 CSIRT N-Able: **divulgazione di catene di exploit** (CVD), nessun attacco osservato nel testo →
  `false` difendibile.

I miei «mancati» precedenti confondevano demo/sospetti/divulgazione con sfruttamento reale: è
proprio la distinzione richiesta.

## Errore confermato e correzione (regole `2026.11.16-1`)

In verifica è emerso un errore reale **fuori dai quattro**: TheHackerNews «Hackers Exploit N-central
Flaws to **Infect** 21 Servers» era `false` pur riportando compromissioni reali. Le regole
`exploitation` esistenti erano già ad alta precisione (frasi di sfruttamento reale), ma non
coprivano due fraseggi giornalistici. Aggiunti due pattern:

- `exploit… to (infect|deploy|hijack|ransom|backdoor|drop)` — sfruttamento che porta a un esito
  concreto d'attacco;
- `(hackers|threat actors?) (have|are|been|…)* exploit` — attore nominato che sfrutta (esclude
  «an attacker **could** exploit» degli advisory).

### Misura (corpus reale, 4000 item del 16 novembre)

- **Casi recuperati: 7**, tutti sfruttamento reale confermato (N-central ×2, PHP2Shell, Check Point
  zero-day, AhsayCBS, Railway, Qubole).
- **Nuovi falsi positivi: 0** sull'intero corpus.
- **Controllo negativo**: 4 fraseggi ipotetici/dimostrativi («an attacker could exploit…», «hackers
  could exploit…», «demo RCE; suspects exploitation…», «may allow…») → nessuno innescato.
- **Verifica su campione distinto**: la coppia di pattern è stata derivata dall'errore confermato e
  dalla definizione; sulla metà di **verifica** del corpus (split per hash dell'id, non usata per
  rifinire) i ribaltamenti sono 6, tutti veri positivi, 0 falsi positivi.
- I quattro scostamenti riesaminati restano correttamente `false`.
- **Conferma dal vivo dopo il relabel** (intero DB, 5520 item): esattamente **7** item sono
  attribuibili ai nuovi pattern (match nuovo e non vecchio) — i 7 veri positivi — e **0** item
  risultano `exploitation_signal=true` senza corrispondere ad alcun pattern (nessuna fuga).
- Coperto da test (`test_exploitation_signal_real_vs_hypothetical`).

## Falsi positivi di contesto (verifica indipendente, regole `2026.11.16-2`)

Una verifica indipendente ha riprodotto **quattro falsi positivi** che la mia misura precedente non
aveva colto (controllavo l'innesco del pattern, non il contesto): negazione di «active
exploitation», «zero-day exploit» **dimostrato in laboratorio**, «hackers exploit» limitato a una
**demo**, e «exploit in circolazione» (disponibilità) senza attacchi osservati. Correzione:

- `exploitation_signal` è valutato **per singolo match** con contesto **locale, limitato alla frase**,
  mai con un veto globale: un match è scartato solo se la negazione lo riguarda (adiacente «no active
  exploitation» o evidenziale «no evidence of exploitation»), se è seguito da un'osservazione negata
  («… not observed»), o se accanto ha un segnale di **dimostrazione/PoC/lab**. Una demo o una
  negazione in **un'altra frase** non nasconde un attacco reale (verificato: «actively exploited; a
  PoC was also released», «exploited … but did not deploy ransomware», «exploited … though the vendor
  disputed» restano `true`).
- Rimosso «exploit in circolazione» dai pattern (è **disponibilità** di exploit, segnale distinto).
- `sandbox` e il solo `poc` **non** sono segnali di demo: «sandbox-evading backdoor» è un attacco
  reale e «exploited hours after PoC released» è sfruttamento che **segue** un PoC.

**Verifica su dati reali** (relabel sull'intero DB, campione distinto dai test): il guard ha
disattivato **2** item prima `true` → uno era una **negazione reale** (MSRC «was not exploited in the
wild», soppressione corretta) e l'altro un **mio falso negativo** su «exploited hours after PoC
released», individuato e corretto rimuovendo il `poc` nudo. Dopo la correzione, nessun item `true`
risulta in contesto negato/demo/disponibilità e i 7 recuperati restano `true`. Coperto da test
(falsi positivi di contesto + casi anti-veto).

## Limiti dichiarati

- **Le dichiarazioni di accuratezza valgono solo per i casi effettivamente revisionati** elencati qui
  (seed=1, n=30 e n=22; più i casi di contesto e anti-veto nei test). **Non** è una stima di
  accuratezza generale del classificatore: la verifica indipendente ha mostrato che una misura
  «0 falsi positivi» basata solo sull'innesco del pattern era incompleta finché non si controllava il
  contesto. Nessun numero di accuratezza è dichiarato oltre gli item letti a mano.

- Questa è una **revisione delle etichette**, **non** una verifica dei fatti: conferma che la regola
  concorda col testo, non che il fatto riportato sia vero.
- **Non** è una modifica del modello predittivo: tocca solo le etichette derivate delle notizie, non
  il candidato CVE né il registro prospettico né la baseline per categoria.
- Resta un difetto noto non corretto qui (fuori ambito `exploitation_signal`): sovra-innesco di
  `event_type=vulnerability_disclosure` su pezzi di tendenza (#2) ed estrazione CVE quando il
  sommario non lo contiene (#3) — eventuale correzione futura, versionata e testata.
