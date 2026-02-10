# MemSqueezer – Memory & Browser Forensics Framework

MemSqueezer è un **framework web-based** per l’analisi forense della memoria (Memory Forensics) e del browser, progettato come supporto alle indagini digitali su sistemi Windows. Il progetto incapsula e orchestra diversi tool esistenti (Volatility e Bulk Extractor) esponendoli tramite REST API e fornendo una interfaccia web intuitiva per l’analisi di memory dump e file di paging (`pagefile.sys`).

## Caratteristiche principali

- Architettura **client–server** basata su REST API HTTP e formato JSON.
- Analisi di:
  - Memory dump (es. file `.mem`).
  - File di paging `pagefile.sys`.
- Integrazione con tool di Memory Forensics:
  - **Volatility** (plugin: `pslist`, `pstree`, `netscan`, `filescan`, `timeliner`).
  - **Bulk Extractor** (estrazione di URL, domini, e‑mail, header, indirizzi IP, ecc.).
- Motore di ricerca interno basato su **keyword** ed **espressioni regolari**, che simula il comportamento dei comandi `strings` e `grep` dei sistemi Unix-like.
- Analisi congiunta di dump e pagefile per massimizzare le evidenze disponibili.
- Presentazione dei risultati tramite:
  - Tabelle testuali (processi, file aperti, connessioni di rete, timeline).
  - Grafici riassuntivi (domini, URL, e‑mail, header, indirizzi IP, risultati di `grep`).
- Pensato per supportare un investigatore forense nella ricostruzione delle attività di un utente (ad esempio uso di Tor Browser e accesso al Deep Web).

## Architettura

MemSqueezer è composto da due macro-componenti: **server** (backend) e **client** (frontend).

### Server

Il backend è implementato in **Python** con **Flask** ed espone una serie di REST API che orchestrano i tool forensi.

Il server è suddiviso in due componenti principali:

- **Memdump Component**
  - Modulo `Dump Analysis`:
    - `Volatility_interface`: invoca Volatility e i plugin `pslist`, `pstree`, `timeliner`, `filescan`, `netscan`, restituendo un JSON per ciascun plugin.
    - `BulkExtractor_interface`: esegue Bulk Extractor da linea di comando, producendo file `PCAP` e file `TXT`.
    - `Grep_interface`: ricerca match sul dump tramite keyword/regex, restituendo un JSON con tutti i risultati.
  - Modulo `Tool Handler`:
    - `Pcap_file_handler`: elabora il file `.pcap` prodotto da Bulk Extractor e lo converte in JSON.
    - `Txt_file_handler`: elabora i vari `.txt` prodotti da Bulk Extractor e li converte in JSON.

- **Pagefile Component**
  - Modulo `Pagefile Analysis`:
    - `Grep_interface`: analisi keyword/regex sul file di paging, con output JSON dei match.

Tutti gli output vengono inviati al client che si occupa della visualizzazione nell’interfaccia web.

### Client

Il frontend è sviluppato in **Dart** utilizzando il framework **Flutter** in modalità web.

Struttura logica lato client:

- `models/`: classi che rappresentano le entità di dominio e i dati ricevuti dal server (processi, file, connessioni, match, ecc.).
- `screens/`: pagine principali dell’applicazione:
  - **HomePage** (`/home`): pagina iniziale del framework.
  - **FormSubmit** (`/form`): form per inserire sistema operativo, keyword e indirizzi IP per l’analisi.
  - **LoadingPage** (`/loadingPage`): pagina di caricamento che mostra lo stato delle analisi in corso.
  - **ResultPage** (`/resultPage`): pagina di visualizzazione dei risultati (tabelle + grafici).
- `widgets/`: componenti UI riutilizzabili (widget custom).
- `services/`: classi che implementano le chiamate HTTP verso il backend.
- `utils/`: helper e utility per la UI.
- `main.dart`: entry point dell’applicazione Flutter.

## Tecnologie utilizzate

### Backend

- **Python**:
  - Linguaggio principale del server.
  - Semplice nella manipolazione di JSON e con un ampio ecosistema di librerie.
- **Flask**:
  - Micro-framework web leggero e flessibile.
  - Basato su WSGI (Web Server Gateway Interface).
  - Ottimo per routing, REST API, testing e debug.

### Tool di Memory Forensics

- **Volatility** (v3):
  - Preinstallato in Kali Linux.
  - Utilizzabile sia da CLI che come libreria Python.
  - Plugin usati: `pslist`, `pstree`, `netscan`, `filescan`, `timeliner`.
- **Bulk Extractor**:
  - Analizza immagini di disco, file e directory indipendentemente dal file system.
  - Estrae numeri di carte di credito, e‑mail, URL, ricerche, header, IP, ecc.

### Frontend

- **Dart**:
  - Linguaggio object-oriented sviluppato da Google.
  - Sintassi vicina a C/Java/Swift, compilabile in JavaScript.
- **Flutter**:
  - Framework UI multipiattaforma open source.
  - Rendering ad alte prestazioni tramite Skia.
  - Widget personalizzati per costruire la UI web, con design minimal e user‑friendly.

## Funzionalità principali

- Analisi di memory dump e pagefile:
  - Estrazione di processi in esecuzione, gerarchie di processi, file aperti, connessioni di rete.
  - Generazione di timeline temporali combinate processi/connessioni.
- Ricerca per keyword:
  - Supporto a keyword semplici (es. `system`, `.dll`, `tcp`).
  - Utilizzo del simbolo `$` per forzare il match esatto evitando sottostringhe (es. `$system`).
  - Supporto per espressioni regolari configurate lato server.
- Analisi protocolli e rete:
  - Individuazione di connessioni `TCP` e `UDP` collegate a processi specifici (es. `tor.exe`).
- Analisi Deep Web / Tor:
  - Identificazione di attività riconducibili a Tor Browser (processi `firefox.exe` + `tor.exe`).
  - Rilevamento di domini `.onion`, URL contenenti keyword legate a Tor/Deep Web (`torproject`, `onion`, `duckduckgo`, ecc.).
  - Supporto alla correlazione con strumenti esterni (es. database di nodi Tor).

## Esempio di utilizzo (scenario d’indagine)

Un tipico scenario d’uso è il seguente:

1. Un sospettato utilizza Tor Browser per accedere a siti del Deep Web.
2. L’investigatore acquisisce un dump di memoria e il file di paging tramite strumenti come FTK Imager.
3. I file vengono messi a disposizione del server MemSqueezer.
4. Tramite l’interfaccia web, l’investigatore inserisce keyword come:

   ```text
   tor; torproject; @torproject; onion; firefox; mozilla; duckduckgo; ftk;
   ```
