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

## Prossimo passo suggerito (non ancora fatto)

- Revisione mirata con `sample_exclude_per_cve=true` per stimare l'accordo sui **casi a testo libero**
  (dove stanno gli errori), con più elementi e, idealmente, un secondo revisore.
- Correggere le regole più deboli emerse (sovra-innesco di `vulnerability_disclosure` su pezzi di
  tendenza; estrazione CVE quando il sommario non lo contiene) — da fare come modifica alle regole,
  versionata e testata, **senza** toccare il candidato né il registro prospettico.
