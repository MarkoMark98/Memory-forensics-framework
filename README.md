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

5. MemSqueezer:
   - Mostra processi `firefox.exe` e `tor.exe`.
   - Evidenzia connessioni di rete TCP appartenenti a `tor.exe`.
   - Elenca file aperti relativi ai binari di Tor Browser e agli strumenti di acquisizione.
   - Mostra grafici con i match delle keyword in domini, URL, e‑mail, header, indirizzi IP e risultati di `grep`.

Questo consente di ricostruire in modo guidato la sequenza delle attività sul sistema analizzato.

## Limitazioni note

- Non è ancora previsto l’upload dei file (dump e pagefile) tramite interfaccia web:
  - I file devono essere gestiti e configurati lato server (percorsi locali).
  - Questa scelta è legata alla dimensione potenzialmente molto elevata dei dump.
- La lista completa dei match per ogni keyword è gestita internamente ma non è ancora esposta in una vista dedicata nella UI.
- I tempi di analisi dipendono dalla dimensione del dump e dalle risorse hardware:
  - Dump più grandi implicano tempi di esecuzione più lunghi, in particolare per la fase di `grep`.

## Setup e avvio

> Nota: i comandi seguenti sono indicativi e possono variare in base alla struttura effettiva del repository e ai nomi dei file/script.

### Requisiti

- Sistema operativo Linux o Windows.
- Python 3.x.
- Flutter SDK + Dart SDK.
- Volatility (v3) installato e raggiungibile da riga di comando.
- Bulk Extractor installato e raggiungibile da riga di comando.

### Backend (server)

```bash
# Clona il repository
git clone https://github.com/MarkoMark98/Memory-forensics-framework.git
cd Memory-forensics-framework/server

# (Opzionale) crea e attiva un virtualenv
python3 -m venv venv
source venv/bin/activate   # su Windows: venv\Scripts\activate

# Installa le dipendenze Python
pip install -r requirements.txt

# Avvia il server Flask
python app.py
```

### Frontend (client)

```bash
cd ../client

# Recupera le dipendenze Dart/Flutter
flutter pub get

# Avvia la versione web in modalità sviluppo
flutter run -d chrome
```

Una volta avviati backend e frontend, il framework sarà raggiungibile all’indirizzo locale indicato da Flutter (ad esempio `http://localhost:xxxx`).

## Struttura del repository (indicativa)

```text
Memory-forensics-framework/
├── server/
│   ├── app.py
│   ├── requirements.txt
│   ├── modules/
│   │   ├── dump_analysis/
│   │   ├── pagefile_analysis/
│   │   └── tool_handler/
│   └── ...
└── client/
    ├── lib/
    │   ├── models/
    │   ├── screens/
    │   ├── widgets/
    │   ├── services/
    │   └── utils/
    └── ...
```

## Stato del progetto

MemSqueezer nasce come progetto di **tesi di laurea triennale in Informatica** presso l’Università degli Studi di Salerno (a.a. 2020–2021). È da considerarsi un prototipo avanzato a scopo didattico e di ricerca, non un prodotto pronto per l’uso in produzione senza ulteriori verifiche, hardening e manutenzione.

## Licenza

Al momento questo repository **non ha una licenza esplicita**. Tutti i diritti sono riservati all’autore. Se desideri che altri possano utilizzare, modificare o distribuire il codice, valuta in futuro l’aggiunta di un file `LICENSE` con una licenza open source a tua scelta (ad esempio MIT, GPL, Apache, ecc.).
