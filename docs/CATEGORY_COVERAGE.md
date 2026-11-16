# Copertura delle categorie: numeratori, denominatori e baseline

Aggiornato al 16 novembre 2026. Come le assegnazioni prodotto→categoria (regole in
`backend/app/taxonomy/rules.json` + decisioni manuali) entrano nei numeri dell'osservatorio, e
che cosa è cambiato con le regole `2026.11.16-1`.

## Le tre quantità e come si formano

Le categorie si assegnano ai **prodotti**, non alle CVE: una CVE eredita le categorie dei prodotti
che tocca, quindi può stare in più categorie e **i conteggi per categoria si sovrappongono per
costruzione** (non sono una partizione e non sommano ai totali).

- **Numeratore** = CVE della categoria **già nel catalogo KEV** (sfruttamento confermato: un fatto).
- **Denominatore** = tutte le CVE catalogate della categoria.
- **Quota KEV** (`kev_share`) = numeratore / denominatore. È la percentuale che l'osservatorio mostra
  come tasso di sfruttamento confermato per categoria; il denominatore è reso esplicito accanto.
- **Baseline aggregata per categoria** (`analysis/exploitation.py`, metodo `recent_rate`):
  conteggio atteso di ingressi KEV nell'orizzonte = **volume recente di pubblicazioni della
  categoria × tasso storico censurato per orizzonte**, con intervallo di Byar/Poisson. È
  descrittiva, non un modello.

## Effetto di una nuova assegnazione

Classificare un prodotto prima non mappato **aggancia le sue CVE** a una categoria. Di conseguenza,
per quella categoria:

- il **denominatore** cresce (tutte le sue CVE);
- il **numeratore** cresce **solo** se tra quelle CVE ce ne sono di già in KEV;
- la **quota KEV** si muove nella direzione del termine dominante: siccome di norma entrano più CVE
  totali che CVE-KEV, la quota può **scendere leggermente** anche mentre il numeratore cresce — è
  l'effetto atteso di una copertura più completa, non un peggioramento;
- la **baseline `recent_rate`** cambia perché salgono sia il *volume recente* sia il *conteggio
  storico di eventi KEV* della categoria: il conteggio atteso si **alza di poco** per le categorie
  interessate. È una **correzione di completezza**, non un cambio di modello.

Questo tocca **solo** le misure aggregate per categoria. Il **modello CVE sperimentale** (EPSS+età)
e il **registro prospettico** non sono toccati: non usano la mappatura delle categorie.

## Che cosa è cambiato con `2026.11.16-1` (misurato)

Delta aggregato di copertura, prima → dopo la ricostruzione della tabella derivata:

| quantità | prima | dopo | Δ |
|---|---|---|---|
| prodotti classificati | 31.822 | 32.065 | +243 |
| CVE classificate | 167.154 | 168.729 | +1.575 |
| **CVE KEV classificate** (numeratore globale) | 1.499 | 1.562 | **+63** |
| CVE recenti classificate | 41.347 | 41.730 | +383 |

Copertura KEV complessiva **84,3% → 87,8%**; CVE KEV ancora senza categoria **280 → 217**.

Famiglie aggiunte e categoria di destinazione (dietro CVE sfruttate):

- **firewall_security_appliance**: F5 BIG-IQ / Enterprise Manager / Traffix, Palo Alto Expedition, Cisco ASyncOS
- **identity_access**: Cisco Identity Services Engine (+ passive identity connector)
- **router_network_edge**: SD-WAN (Cisco vSmart, Arista VeloCloud, Citrix SD-WAN WANOP)
- **mail_collaboration**: Cisco Unified Communications Manager, Mitel MiCollab, SmarterMail
- **enterprise_application**: JetBrains TeamCity, LiteLLM, SysAid, Red Hat Fuse, Accellion FTA, CrushFTP, Gladinet CentreStack/Triofox
- **remote_management**: agent di gestione Microsoft (System Center, OMI, Log Analytics, Container Monitoring), SimpleHelp
- **database_storage**: Oracle ZFS / StorageTek, IBM Storwize
- **operating_system**: Red Hat CodeReady Linux Builder
- **web_cms**: DotNetNuke (bug di ancoraggio corretto), Telerik UI for ASP.NET AJAX
- **iot_ot_building**: 3DS Delmia Apriso
- **browser_client**: utility desktop Gigabyte (Aorus/OC Guru/Xtreme)

Scelta documentata: le **piattaforme software di comunicazione unificata** (CUCM, MiCollab) vanno in
`mail_collaboration`, accanto a Teams/Zoom/Mattermost; i **telefoni/edge** (Avaya, Polycom) restano
in `router_network_edge` come già classificati.

## Snapshot per categoria (dopo, 16 novembre 2026)

Numeratore, denominatore e quota KEV correnti (ordinati per numeratore). Riferimento per leggere i
cambiamenti futuri; i conteggi si sovrappongono tra categorie.

| categoria | CVE KEV (num.) | CVE (den.) | quota KEV |
|---|---:|---:|---:|
| operating_system | 549 | 53.417 | 1,03% |
| browser_client | 293 | 28.259 | 1,04% |
| router_network_edge | 178 | 13.651 | 1,30% |
| enterprise_application | 158 | 15.927 | 0,99% |
| mobile_device | 153 | 19.075 | 0,80% |
| firewall_security_appliance | 152 | 6.793 | 2,24% |
| web_cms | 106 | 19.192 | 0,55% |
| mail_collaboration | 100 | 3.856 | 2,59% |
| database_storage | 93 | 7.798 | 1,19% |
| remote_management | 85 | 4.656 | 1,83% |
| vpn_remote_access | 70 | 1.543 | 4,54% |
| virtualization_cloud | 63 | 4.627 | 1,36% |
| iot_ot_building | 55 | 6.166 | 0,89% |
| identity_access | 12 | 1.380 | 0,87% |

Le assegnazioni restano riproducibili dalle regole + eventuali decisioni manuali (storico
versionato nella tabella `product_category_history`) e sono coperte da test
(`backend/tests/test_categories.py`).
