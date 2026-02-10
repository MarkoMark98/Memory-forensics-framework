# MemSqueezer – Memory & Browser Forensics Framework

MemSqueezer è un **framework web-based** per l’analisi forense della memoria (Memory Forensics) e del browser, progettato come supporto alle indagini digitali su sistemi Windows. Il progetto incapsula e orchestra tool esistenti (Volatility e Bulk Extractor) esponendoli tramite REST API e fornendo una interfaccia web intuitiva per l’analisi di memory dump e file di paging (`pagefile.sys`).

## Obiettivi del progetto

- Semplificare i processi di **Memory Forensics** e **Browser Forensics**.
- Rendere più veloce e intuitiva l’analisi delle immagini di memoria e del file di paging.
- Fornire a un investigatore forense uno strumento unico che:
  - Colleghi più tool forensi.
  - Centralizzi l’esecuzione e la visualizzazione dei risultati.
  - Supporti la ricostruzione delle attività svolte su un computer.

Il progetto è stato sviluppato come **tesi di laurea triennale in Informatica** presso l’Università degli Studi di Salerno (a.a. 2020–2021).

## Caratteristiche principali

- Architettura **client–server** basata su:
  - REST API HTTP.
  - Formato di scambio dati JSON.
- Analisi di:
  - Memory dump (file `.mem`).
  - File di paging `pagefile.sys`.
- Integrazione con tool di Memory Forensics:
  - **Volatility** (plugin: `pslist`, `pstree`, `netscan`, `filescan`, `timeliner`).
  - **Bulk Extractor** (estrazione di URL, domini, e‑mail, header, indirizzi IP, ecc.).
- Motore di ricerca interno basato su:
  - **Keyword**.
  - **Espressioni regolari**.
- Presentazione dei risultati tramite:
  - Tabelle (processi, file aperti, connessioni di rete, timeline).
  - Grafici (domini, URL, e‑mail, header, indirizzi IP, risultati di ricerche sul dump/pagefile).

## Architettura

MemSqueezer è composto da due parti principali:

- **Server (backend)** in Python/Flask.
- **Client (frontend)** in Dart/Flutter presente in una repository separata al seguente link: https://github.com/MarkoMark98/MemSqueezer_Frontend

### Server

Il backend espone una serie di endpoint REST che orchestrano l’esecuzione dei tool di Memory Forensics e processano i risultati.

Componenti principali:

- **Memdump Component**
  - Modulo `Dump Analysis`:
    - `Volatility_interface`: invoca Volatility e i plugin `pslist`, `pstree`, `timeliner`, `filescan`, `netscan`, restituendo un JSON per ciascun plugin.
    - `BulkExtractor_interface`: esegue Bulk Extractor da linea di comando, producendo file `PCAP` e file `TXT`.
    - `Grep_interface`: ricerca match nel dump tramite keyword ed espressioni regolari, simulando `strings`/`grep`, con output JSON.
  - Modulo `Tool Handler`:
    - `Pcap_file_handler`: gestisce il file `.pcap` prodotto da Bulk Extractor e lo trasforma in JSON.
    - `Txt_file_handler`: gestisce i file `.txt` prodotti da Bulk Extractor e li trasforma in JSON.

- **Pagefile Component**
  - Modulo `Pagefile Analysis`:
    - `Grep_interface`: ricerca match nel `pagefile.sys` tramite keyword/regex, con output JSON.

I JSON generati vengono inviati al client, che si occupa della visualizzazione.

### Client

Il frontend è una web app sviluppata con Flutter, strutturata in moduli:

- `models/` – classi che rappresentano i dati forniti dal server (processi, file, connessioni, match, ecc.).
- `screens/` – schermate principali:
  - **HomePage** (`/home`): pagina iniziale del framework.
  - **FormSubmit** (`/form`): form per inserire sistema operativo, keyword e indirizzi IP.
  - **LoadingPage** (`/loadingPage`): pagina di caricamento che mostra lo stato delle analisi.
  - **ResultPage** (`/resultPage`): pagina che organizza e visualizza i risultati (tabelle + grafici).
- `widgets/` – widget UI riutilizzabili.
- `services/` – classi per le richieste HTTP verso il backend.
- `utils/` – helper e funzioni di supporto alla UI.
- `main.dart` – entry point dell’applicazione Flutter.

## Tecnologie utilizzate

### Backend

- **Python**
  - Linguaggio dinamico, orientato agli oggetti.
  - Semplifica la manipolazione di JSON e l’integrazione con librerie esterne.
- **Flask**
  - Micro-framework web open source.
  - Basato su WSGI (Web Server Gateway Interface).
  - Leggero, flessibile, adatto alla creazione di REST API.

### Tool di Memory Forensics

- **Volatility (v3)**
  - Framework multipiattaforma open source.
  - Plugin usati:
    - `pslist` – lista dei processi in esecuzione al momento del dump.
    - `pstree` – albero dei processi.
    - `netscan` – lista delle connessioni di rete.
    - `filescan` – lista dei file aperti.
    - `timeliner` – timeline combinata di processi e connessioni.
- **Bulk Extractor**
  - Strumento per analizzare immagini di disco, file o directory.
  - Indipendente dal file system.
  - Estrae numeri di carte di credito, indirizzi e‑mail, URL, ricerche online, header, indirizzi IP.

### Frontend

- **Dart**
  - Linguaggio object-oriented sviluppato da Google.
  - Sintassi simile a C/Java.
  - Supporto a costrutti dedicati (es. costruttori `ClassName.fromJson`).
- **Flutter**
  - Framework UI multipiattaforma open source.
  - Usa il motore grafico Skia.
  - Basato su widget altamente personalizzabili per la creazione di interfacce moderne e responsive.

## Funzionalità principali

- Analisi di memory dump e pagefile:
  - Processi in esecuzione.
  - Gerarchie di processi.
  - File aperti.
  - Connessioni di rete.
  - Timeline con eventi ordinati per data/ora.
- Ricerca per keyword:
  - Supporto a keyword semplici (es. `system`, `.dll`, `tcp`, `udp`).
  - Uso del simbolo `$` per forzare il match esatto della stringa (es. `$system` per evitare match parziali).
  - Ricerca tramite espressioni regolari configurate lato server.
- Integrazione con scenari reali:
  - Analisi di utilizzo di Tor Browser e Deep Web (processi `firefox.exe`/`tor.exe`, domini `.onion`, attività su `duckduckgo`, ecc.).
  - Individuazione di pattern sospetti nelle connessioni di rete e nei log.

## Esempio di scenario d’uso

Un esempio di impiego del framework:

1. Un sospettato utilizza **Tor Browser** per accedere a siti del Deep Web.
2. Un investigatore forense acquisisce:
   - Un memory dump del sistema.
   - Il file di paging (`pagefile.sys`), ad esempio tramite FTK Imager.
3. I file vengono messi a disposizione del server MemSqueezer.
4. Tramite la pagina **FormSubmit**, l’investigatore inserisce:
   - Sistema operativo target (es. Windows).
   - Keyword come:
     ```text
     tor; torproject; @torproject; onion; firefox; mozilla; duckduckgo; ftk;
     ```
   - Eventuali indirizzi IP di interesse.
5. Il framework:
   - Mostra i processi `firefox.exe` e `tor.exe`.
   - Evidenzia connessioni di rete attribuite a `tor.exe`.
   - Elenca file e directory legate all’installazione di Tor Browser.
   - Visualizza grafici con la distribuzione di domini, URL, e‑mail, header e indirizzi IP correlati alle keyword.
6. L’investigatore utilizza tabelle e grafici per:
   - Ricostruire la sequenza temporale delle azioni.
   - Collegare l’uso di Tor Browser a specifici eventi di rete e URL visitati.
   - Estrarre evidenze utilizzabili in sede giudiziaria.

## Limitazioni note

- Caricamento dei file:
  - Non è previsto l’upload diretto di memory dump e pagefile tramite interfaccia web.
  - La gestione dei file avviene tramite percorsi configurati lato server.
- Visualizzazione dei match:
  - Il framework mantiene la lista completa dei match per ogni keyword, ma nella versione attuale la UI non espone una vista dettagliata di tutti i singoli match.
- Tempi di esecuzione:
  - Crescono all’aumentare della dimensione del dump (ad esempio una differenza significativa tra 2 GB e 4 GB).
  - La fase più costosa è l’esecuzione delle ricerche sul dump (grep/regex).
  - Le performance dipendono anche dall’hardware della macchina che esegue il framework.

## Setup e avvio (linee guida generali)

### Requisiti

- Sistema operativo in grado di eseguire:
  - Python 3.x.
  - Dart/Flutter.
  - Volatility.
  - Bulk Extractor.
- Accesso ai file:
  - Memory dump (`.mem`).
  - File di paging (`pagefile.sys`).

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

Una volta avviati backend e frontend, il framework è raggiungibile all’indirizzo locale indicato da Flutter (esempio: `http://localhost:xxxx`).

## Struttura del repository (esempio)

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

## Stato del progetto e licenza

MemSqueezer nasce come progetto di **tesi di laurea triennale in Informatica** e rappresenta un prototipo avanzato a scopo didattico e di ricerca. Non è pensato come prodotto pronto per l’uso in ambienti di produzione senza ulteriori attività di hardening, test e manutenzione.

Al momento questo repository **non ha una licenza esplicita**: tutti i diritti sul codice e sulla documentazione sono riservati all’autore.

L’uso del software e delle tecniche descritte è inteso **esclusivamente per scopi leciti, di studio e di laboratorio**.  
L’analisi forense deve essere svolta solo su sistemi per i quali si dispone di autorizzazione.
