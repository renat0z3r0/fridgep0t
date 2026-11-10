# fridgep0t

[English](README.md) · **Italiano** · [Español](README.es.md)

> «Farò sicuramente dei danni, ma mi rivolgo a tutte queste casalinghe che
> vedono su Internet la borsa che gli piace e che costa solo 6 euro al mese, il
> frigorifero che costa solo 19 euro al mese, quel materasso che ne costa 22 al
> mese. Quando arriva la fine del mese, arrivano pure i Carabinieri […]»
>
> — Renato Zero, [intervista a Fanpage.it](https://www.fanpage.it/spettacolo/interviste/renato-zero-dopo-la-morte-di-mia-madre-ho-chiesto-a-dio-di-dialogare-con-lei-e-me-lo-ha-concesso/)

Lui lo sapeva già, prima di tutti noi: coi frigoriferi, prima o poi, arrivano i
Carabinieri.

Un honeypot per i controllori di refrigerazione dei supermercati.

Tra ottobre e novembre 2026 alcuni attaccanti sono entrati nei supervisori di
refrigerazione esposti su internet in tutta Europa, usando password di default e
firmware vecchio e non aggiornato, e hanno forzato cicli di sbrinamento.
fridgep0t finge di essere uno di quei controllori. Registra chi si collega,
quali password prova e quali exploit pubblici usa, e non gli dà mai niente di
reale.

È un singolo binario statico senza dipendenze a runtime, costruito attorno a tre
scelte: un'identità per deployment, così le istanze non si possono catalogare
insieme; una fedeltà delle persona ancorata a fonti pubbliche; l'hardening della
supply chain.

## Design

**Identità per deployment.** Un'esca che esce con un nome negozio, un MAC e un
subject della CA fissi nel codice è identica in ogni deployment per chiunque
faccia honeypot detection. Qui il nome del negozio, l'hostname, il MAC, la
stringa del firmware e il suo `Last-Modified` sono generati a ogni avvio, e lo
sono anche le chiavi e la finestra di validità del certificato (imposta
`TLS_DIR` per conservare il certificato tra un riavvio e l'altro, come fa
l'immagine container). I subject del certificato no: sono fissi per persona,
come il CN di modello che porta un'unità reale. Imposta `IDENTITY_SEED` per
mantenere un'identità stabile tra i riavvii senza condividerla con nessun altro
deployment; lascialo vuoto per un'identità nuova a ogni avvio. Il nome del
negozio generato segue la lingua di `DEVICE_TZ` (o `STORE_LANG`), e il MAC porta
l'OUI registrato all'IEEE dal produttore (vedi FINGERPRINTS.md).

HTTPS è disponibile per ogni persona (`HTTPS_PORT`). L'issuer del certificato è
compilato solo per `danfoss`, l'unica unità di cui i dettagli dell'issuer sono
documentati; le altre portano un CN nudo invece di un'organizzazione indovinata.

**Coerenza della persona.**
- La stringa del firmware è generata una volta e riusata ovunque compaia, così
  la pagina di login e la risposta XML `read_units` non si contraddicono mai:
  una pagina che nomina una build e un'API che ne nomina un'altra è un classico
  indizio di honeypot.
- `read_date_time` risponde nel fuso orario del dispositivo (`DEVICE_TZ`,
  default `Europe/Rome`), non nell'UTC del container. Un supervisore in un
  negozio europeo riporterebbe l'ora locale.

**Un CVE-2021-45420 credibile per la persona Dixell.** Rispondere ai percorsi
di upload di XWEB con un `200` vuoto è qualcosa che qualunque checker
automatico smaschera. fridgep0t simula lo scambio scrivi-poi-leggi che
l'exploit pubblico e il suo template Nuclei verificano davvero: una `POST` a un
CGI di upload "salva" il file in memoria, una successiva `GET /logo/<nome>` lo
restituisce, e `cal_dir.cgi` lo elenca. Niente tocca il disco; gli upload
salvati hanno un tetto e sono registrati come eventi `control`.

**Hardening della supply chain.**
- `cloud-init.yaml` clona il tuo repository (`FRIDGEP0T_REPO`) a un commit
  revisionato (`FRIDGEP0T_REF`) invece di seguire un branch che si muove, si
  rifiuta di compilare se uno dei due manca o se il checkout fallisce, e
  installa un ruleset nftables che blocca tutto il traffico in uscita tranne il
  DNS e le nuove connessioni TCP 80/443 (servono per scaricare pacchetti e
  immagini; i mirror non sono fissati per indirizzo). L'esca in sé non apre mai
  connessioni in uscita.
- Il `Containerfile` compila in statico e gira su distroless `nonroot`: niente
  shell, niente package manager, niente su cui fare pivot. Le immagini base
  sono fissate per digest, con il comando di aggiornamento documentato nel
  file.
- Generazione del certificato in-process (nessuna chiamata a `openssl`). Le
  chiavi sono nuove a ogni avvio, oppure una per deployment quando `TLS_DIR`
  conserva il certificato; la validità è retrodatata di una quantità casuale,
  così il certificato non rivela mai la data di build.

## Persona

| Persona   | Finge di essere                     | Serve                                                               |
|-----------|-------------------------------------|--------------------------------------------------------------------|
| `danfoss` | System manager Danfoss AK-SM 800A   | Login StoreView, API XML su `/html/xml.cgi` e `/xml.cgi`, HTTP+HTTPS |
| `dixell`  | Supervisore Copeland/Dixell XWEB EVO | Pagina di login, flusso `cgi-bin/login.lua`, percorsi CGI di XWEB 500 |
| `aksc355` | Danfoss AK-SC 355 (legacy)          | Pagina di login con il flusso documentato Forgot-Credentials / divulgazione del MAC |
| `carel`   | Carel pCOWeb                        | Server thttpd, HTTP Basic auth, pagine `/config/` inclusa la divulgazione delle credenziali in chiaro |
| `eliwell` | Eliwell TelevisGo                   | Pagina di login (default Administrator / 0), payload welcome/version |
| `rdm`     | RDM Data Manager                    | Pagina di login con il default documentato `1234`, login/status CGI |

Queste sei coprono ogni famiglia di produttori nominata nei rapporti di
esposizione successivi agli attacchi (Danfoss, Dixell/Copeland XWEB, Carel,
Eliwell, RDM).

Ogni persona può anche esporre un servizio Modbus TCP opzionale con temperature
dei banchi, setpoint e un registro di sbrinamento finti (vedi "Modbus TCP" più
sotto). È spento finché non si imposta `MODBUS_PORT`.

La persona `aksc355` è volutamente superficiale. Punta all'altro modello legacy
nominato nell'allerta del CERT-FR (titolo: "Danfoss série AK-SM et AK-SC"), ma
non abbiamo una copia della vera interfaccia web dell'AK-SC 355, quindi è
ancorata solo al comportamento documentato pubblicamente: la banda firmware
("3.091 or higher"), gli account di default, e la schermata "Forgot Credentials
-> Reset Password" che rivela il MAC dell'unità e un codice di reset. Basta per
catturare uno scanner che cerca proprio le AK-SC 355; non regge un'interazione
approfondita. Per un deployment che ti interessa, cattura le pagine di un'unità
reale e sostituisci il markup, e imposta `SERVER_HEADER` alla stringa del web
server che osservi: non ne forniamo una, perché un valore sbagliato tradisce
più di un valore assente.

## Exploit riconosciuti

Le richieste che corrispondono a un exploit pubblico ricevono un campo
`exploit` nel log:

- CVE-2023-25914 — path traversal dell'AK-SM 800A via `get_file`
- CVE-2023-25915 — command injection dell'AK-SM 800A via `load_cert`
- CVE-2025-41452 — sovrascrittura degli header nginx dell'AK-SM 800A via
  `load_nginx_headers`
- CVE-2025-41450 — bypass del login dell'AK-SM 800A con il "code of the day",
  annotando se l'attaccante ha calcolato il codice corretto
- CVE-2021-45420 — scrittura di file senza autenticazione su XWEB 500 sotto
  `/cgi-bin/`
- CVE-2026-25085 — bypass del login di XWEB Pro via un `auth_mode` inatteso

### Livelli di fedeltà

Le persona sono costruite solo da fonti pubbliche (manuali dei produttori,
advisory CVE e dei produttori, firme dei rapporti di esposizione) e da markup
originale, mai da firmware catturato. La fedeltà quindi varia con quanto è
documentato pubblicamente:

- `danfoss`, `dixell`, `carel`, `eliwell` — buona: header del server, flusso di
  autenticazione, credenziali di default e percorsi chiave sono tutti
  documentati pubblicamente.
- `rdm` — media: il default `1234` e il login CGI sono documentati, ma l'header
  Server esatto e i byte della pagina no, quindi il markup è semplice e
  l'header è lasciato a `SERVER_HEADER`.
- `aksc355` — superficiale: ancorata solo alla banda firmware e al flusso
  Forgot-Credentials.

Dove un dettaglio del dispositivo reale non si può citare, resta configurabile
e vuoto invece che indovinato, perché un'impronta sbagliata tradisce più di una
mancante. Per un deployment che ti interessa, cattura le pagine di un'unità
reale e imposta `SERVER_HEADER` al valore che osservi.

## Cosa risponde ogni persona

Comune a tutte e sei:

- La pagina iniziale è servita su `/` e `/index.html`, solo a `GET` e `HEAD`.
  Qualunque altro metodo riceve il rifiuto tipico del server: 405, oppure 501
  su `carel`.
- I percorsi sconosciuti ricevono la pagina 404 della persona; una richiesta
  malformata la sua pagina 400; un body oltre 8 KiB la sua pagina 413 (400 su
  `carel`).
- Un login via form o API che "riesce" consegna un token di sessione valido
  un'ora, e la risposta è ritardata di 0,6–1,4 secondi, perché un'unità reale
  ci mette un momento. `carel` usa invece HTTP Basic auth: niente token,
  niente ritardo.
- Ogni richiesta, login, comando e tentativo di exploit viene registrato (vedi
  "Leggere il log").

**`danfoss`** (header in stile nginx, keep-alive sulla pagina di login)
- `POST /html/xml.cgi` (anche `/xml.cgi`) accetta un `<cmd action="…"/>` XML;
  `OPTIONS` risponde 204 e ogni altro metodo 405.
- `getauth` fa il login e restituisce un token di sessione, da rimandare
  nell'header `AKSM-Auth`. Funzionano anche le credenziali passate direttamente
  su un altro comando.
- `read_date_time` risponde senza sessione, nel fuso orario del dispositivo.
- `read_units` restituisce nome del negozio, firmware e MAC; `read_devices` gli
  otto banchi con temperatura, setpoint e stato di sbrinamento.
- Qualunque altra azione da una sessione è registrata come `control`. Una il
  cui nome contiene `defrost`, con `node` da `"1"` a `"8"`, avvia lo
  sbrinamento simulato.
- In un browser, un login riuscito sostituisce il form con una tabella degli
  otto banchi e un pulsante Defrost su ogni riga. La pagina usa gli stessi
  comandi XML, quindi un clic è registrato esattamente come un comando da
  script.
- Login che riescono: `Supervisor`/`12345`, `superviseur`/`12345`,
  `admin`/`admin`, `admin`/`1234` (nome utente con qualsiasi
  maiuscola/minuscola), oppure il code of the day con `eds_only` o
  `quantum_only`.

**`dixell`**
- `POST /cgi-bin/login.lua` (anche `/login`) accetta i campi `username`,
  `password` e `auth_mode`. Cinque errori dalla stessa sorgente sullo stesso
  nome utente bloccano quella coppia per 300 secondi.
- `POST /cgi-bin/datachart.cgi` con `SSES=<token>` restituisce le temperature
  dei banchi; senza una sessione valida restituisce la pagina di login.
- `POST /cgi-bin/logo_extra_upload.cgi`, `cal_save.cgi` o `lo_utils.cgi`
  "salva" un upload: la prima riga è il nome del file, il resto il contenuto,
  fino a 8 KiB, solo in memoria. `GET /logo/<nome>` lo restituisce; `GET
  /cgi-bin/cal_dir.cgi` o `/logo/` elenca ciò che è stato salvato.
- Gli script e i fogli di stile referenziati dalla pagina rispondono con un
  200 vuoto.
- Login che riescono: `admin`/`Admin`, `Admin`/`Admin`, `admin`/`admin`.

**`aksc355`**
- `POST /cgi-bin/login.cgi` (anche `/login`) accetta `user` o `username`, e
  `password` o `pass`.
- `POST /cgi-bin/reset.cgi` (anche `/reset`) è il flusso Forgot-Credentials:
  restituisce il MAC dell'unità e un codice di reset casuale.
- Login che riescono: `admin`, `administrator`, `user` o `guest` con
  `danfoss`; `Supervisor`/`12345` (nome utente con qualsiasi
  maiuscola/minuscola).

**`carel`** (header di risposta e pagine d'errore di thttpd 2.25b; risponde nella versione HTTP della richiesta)
- La pagina iniziale è servita anche su `/http/index.html`, e i nomi dei
  metodi sono confrontati senza distinguere maiuscole e minuscole.
- Tutto ciò che sta sotto `/config/` chiede HTTP Basic auth, realm `pCOWeb`.
  `/config/pw_changeusers.html` elenca in chiaro gli account di fabbrica e le
  loro password; ogni altro percorso di configurazione restituisce una pagina
  minima con MAC e versione.
- Login che riescono: `httpadmin`/`fhttpadmin`, `admin`/`fadmin`,
  `carel`/`fcarel`, `guest`/`fguest`, `root`/`froot`.

**`eliwell`**
- `POST /login` (anche `/j_security_check`) accetta `user`, `username` o
  `j_username`, e `password` o `j_password`.
- `GET /welcome` (anche `/version`) restituisce prodotto, produttore, versione
  del software e nome dell'impianto, senza sessione.
- Login che riescono: `Administrator` con `0` o con password vuota.

**`rdm`**
- `POST /cgi-bin/login.cgi` (anche `/login`) accetta `user` o `username`, e
  `password`, `pass` o `pin`.
- `/cgi-bin/status.cgi` (anche `/status`) restituisce gli otto banchi con
  temperatura, setpoint e stato di sbrinamento, senza sessione, come su
  un'unità con "Force CGI login" disattivato.
- Login che riescono: password `1234` con utente vuoto, `admin` o `user`.

### HTTPS

`HTTPS_PORT` aggiunge un listener TLS per qualunque persona. Parla solo TLS
1.2, come le unità reali, e presenta un certificato leaf firmato da una CA
self-signed, entrambi generati in-process e retrodatati. Un handshake fallito
o scaduto è registrato come `tls_error`.

### Modbus TCP

`MODBUS_PORT` aggiunge un listener Modbus TCP per qualunque persona, che
risponde a qualsiasi unit id.

| Registri | Contenuto |
|----------|-----------|
| 0–7      | Temperature dei banchi, decimi di °C, con segno, con rumore del sensore |
| 100–107  | Setpoint dei banchi, decimi di °C |
| 200–207  | Comando di sbrinamento: un valore diverso da zero lo avvia, zero lo ferma |

- I function code 3 e 4 leggono, 6 e 16 scrivono, e 43/14 restituisce
  l'identificazione del dispositivo (produttore, prodotto, firmware). Ogni
  altra funzione riceve l'eccezione 1, un indirizzo non mappato l'eccezione 2,
  un conteggio non valido l'eccezione 3.
- Uno sbrinamento alza la temperatura del banco di circa 1,5 °C al minuto per
  venti minuti (al massimo +25 °C), poi azzera il suo registro e il banco torna
  alla sua base in quarantacinque minuti, come farebbe uno vero; chi fa polling
  non la vede mai tornare di colpo. Fermarlo prima fa ripartire la discesa da
  dove era arrivato, e riavviarlo a metà discesa riprende a salire dalla
  temperatura corrente.
- Lo stesso stato dei banchi è quello che `read_devices`, `datachart.cgi` e
  `status.cgi` riportano via HTTP.

## Avvio rapido

```
cargo build --release --locked
PERSONA=danfoss HTTP_PORT=8080 ./target/release/fridgep0t
```

Un binario compilato sulla tua workstation incorpora la tua home directory
nelle posizioni dei panic. Fai il deploy della build container, che non ha
quei percorsi, oppure compila con `RUSTFLAGS="--remap-path-prefix=$HOME=~"`
(una voce `[build] rustflags` nel tuo `~/.cargo/config.toml` lo rende
permanente).

Apri http://localhost:8080 e ogni richiesta compare come riga JSON su stdout e
in `events.jsonl`. Lancia i test: unit test per i parser e lo stato, e una
suite di integrazione che avvia il binario per ogni persona e lo attacca via
HTTP, HTTPS e Modbus, compresi i percorsi di timeout, tetto di connessioni e
spegnimento:

```
cargo test --release --locked
```

La CI esegue build, test, clippy e fmt su stable, build e test sulla versione
minima di Rust supportata (1.75), e `cargo audit` sulle dipendenze bloccate. Gira
anche ogni settimana, e le sue action sono fissate per SHA di commit.

`SIGTERM` o Ctrl-C fermano l'esca; prima scrive gli eventi di log ancora in
coda, per al massimo due secondi.

## Deploy

**Container.** Il `Containerfile` compila il binario e lo mette su distroless
`nonroot`, in ascolto su 8080 (HTTP) e 8443 (HTTPS), con il log in
`/logs/events.jsonl` e il certificato conservato in `/logs/tls`:

```
podman build -t fridgep0t .
podman run -d --name fridgep0t --restart=always \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 80:8080 -p 443:8443 -v fridgep0t-logs:/logs:U \
  -e PERSONA=danfoss -e IDENTITY_SEED=<una-tua-stringa-casuale> \
  fridgep0t
```

**Server nuovo.** Incolla `cloud-init.yaml` nel campo "User data" di un nuovo
server Ubuntu 24.04, dopo aver impostato al suo interno `PERSONA`,
`FRIDGEP0T_REPO` e `FRIDGEP0T_REF`. Installa il firewall, compila l'immagine
dal commit che hai fissato, genera un `IDENTITY_SEED` casuale per quell'host e
avvia il container con le opzioni qui sopra. Lì solo `danfoss` riceve la porta
HTTPS. Per esporre Modbus, segui il commento nel file.

## Configurazione

| Variabile       | Default           | Significato                                          |
|-----------------|-------------------|------------------------------------------------------|
| `PERSONA`       | `danfoss`         | `danfoss`, `dixell`, `aksc355` (o `aksc`), `carel` (`pcoweb`), `eliwell` (`televisgo`), `rdm` (`datamanager`) |
| `BIND`          | `0.0.0.0`         | Indirizzo su cui ascoltare                           |
| `HTTP_PORT`     | `8080`            | Listener HTTP                                        |
| `HTTPS_PORT`    | `0` (spento)      | Listener HTTPS (certificato generato in-process)     |
| `MODBUS_PORT`   | `0` (spento)      | Listener Modbus TCP                                  |
| `LOG_PATH`      | `events.jsonl`    | Dove vengono accodati gli eventi                     |
| `DEVICE_TZ`     | `Europe/Rome`     | Fuso orario riportato dall'orologio dell'esca        |
| `IDENTITY_SEED` | nessuno (casuale) | Seed fisso per un'identità stabile per deployment    |
| `TLS_DIR`       | nessuno (nuovo a ogni avvio) | Directory che conserva il certificato generato tra i riavvii (`/logs/tls` nell'immagine container) |
| `STORE_NAME`    | generato          | Sostituisce il nome del negozio generato             |
| `STORE_LANG`    | da `DEVICE_TZ`    | Lingua dell'insegna generata: `it`, `de`, `fr`, `es`, `nl`, `en` |
| `FIRMWARE`      | generato          | Sostituisce la stringa del firmware generata         |
| `MAC_OUI`       | per persona (IEEE) | Sostituisce l'OUI del produttore (`xx:xx:xx`) nel MAC generato |
| `SERVER_HEADER` | default della persona | Sostituisce l'header Server per qualunque persona (vedi Livelli di fedeltà) |

## Leggere il log

Il log ruota a 256 MB, conservando da `events.jsonl.1` a `events.jsonl.4`.
`summary.py` trasforma un log in un breve rapporto:

```
python3 -I summary.py --hours 24 --ignore <il-tuo-ip> < events.jsonl
```

Stampa i totali (eventi, sorgenti, login tentati e accettati, tentativi di
exploit, sorgenti Modbus, scritture di controllo, tentativi di sbrinamento),
gli eventuali buchi nel log, i principali exploit, IP, credenziali e percorsi,
e una riga per ogni tentativo di sbrinamento.

Ogni evento è un oggetto JSON con `ts` (UTC), `persona`, `proto` (`http`,
`https`, `modbus`, `tcp` o `system`), `src_ip`, `src_port` ed `event`, più i
campi propri di quell'evento. I campi forniti dall'attaccante sono tagliati a
512 caratteri e la riga a 8 KiB (`"truncated": true` segna una riga tagliata
più a fondo).

| Evento | Registrato quando | Campi principali |
|--------|-------------------|------------------|
| `start` | L'esca parte | porte, nome negozio, hostname, MAC, firmware, fuso orario |
| `request` | Qualunque richiesta HTTP ben formata | `method`, `path`, `host`, `user_agent`, `authorization`, `body`, `exploit` |
| `bad_request` | Una richiesta viene rifiutata (malformata, troppo grande, interrotta) | `raw`, `exploit` |
| `login_attempt` | Qualunque login, su qualunque persona | `username`, `password`, `granted`; `locked`, `auth_mode`, `exploit` su `dixell` |
| `xml_cmd` | Un comando XML di `danfoss` | `action`, `attrs`, `auth_header`, `session`, `exploit` |
| `control` | L'attaccante agisce: un comando, un upload, una divulgazione di credenziali o del MAC | `action`; `node`, `defrost`, `path`, `stored_as`, `exploit` |
| `datachart` | Una richiesta dati di `dixell` | `session`, `request` |
| `connect`, `read`, `write`, `device_id` | Traffico Modbus | `unit`, `fc`, `start`, `count` o `values`, `defrost` |
| `unsupported`, `malformed` | Una funzione Modbus a cui non rispondiamo, o un frame non valido | `pdu_hex` o `header_hex` |
| `tls_error` | Un handshake TLS fallisce o scade | `error` |
| `conn_refused` | Una sorgente supera il suo tetto di connessioni (al massimo una volta al minuto per sorgente) | |
| `log_suppressed` | Una sorgente raggiunge il tetto di eventi al minuto | `class`, `per_minute` |
| `log_dropped` | La coda del log era piena | `count` |

## Sicurezza

- Non esegue mai comandi, non legge file e non inoltra traffico. I payload
  degli exploit sono registrati e scartati; i file "caricati" vivono in una
  mappa in memoria con un tetto.
- I body delle richieste, i campi registrati e le connessioni hanno un tetto,
  compreso un limite per sorgente, così un attaccante non può togliere spazio
  agli altri. I socket inattivi vanno in timeout; ogni connessione viene chiusa
  dopo 30 secondi, per quanto lentamente arrivi.
- L'HTTP è analizzato in modo rigoroso: solo HTTP/1.0 e 1.1, righe di header
  ben formate, esattamente un `Host` su HTTP/1.1, un `Content-Length` numerico
  che coincide tra le ripetizioni e rientra nel tetto del body, nessun
  `Transfer-Encoding`. Tutto ciò che è ambiguo viene registrato come
  `bad_request`, riceve la pagina d'errore 400 (o 413) della persona e la
  connessione viene chiusa, così un body non può mai essere letto come la
  richiesta successiva.
- Le righe di log troppo lunghe vengono troncate; `summary.py` neutralizza i
  codici di escape del terminale presenti nell'input dell'attaccante.
- Il log non blocca mai una connessione: un thread di scrittura svuota una
  coda limitata; se la coda si riempie, gli eventi più recenti vengono
  scartati e un evento `log_dropped` riporta quanti. Lo spegnimento aspetta al
  massimo due secondi che il thread finisca di scrivere.
- Una sorgente non può far uscire gli eventi degli altri dal log, che è
  limitato in dimensione: ogni IP sorgente può registrare 600 eventi al minuto,
  contati separatamente per gli eventi di routine e per login e comandi, così
  una raffica di richieste non può seppellire il comando che la segue. Oltre il
  tetto viene scritto un solo evento `log_suppressed`, poi niente fino allo
  scadere del minuto. `summary.py` riporta entrambi i tipi di buco.
- I campi del log sono controllati dall'attaccante. Trattali come non fidati
  quando li elabori.

I limiti sono fissi nel codice, non configurabili, perché sono la rete di
sicurezza:

| Limite | Valore |
|--------|--------|
| Body della richiesta | 8 KiB |
| Header della richiesta | 16 KiB |
| Campo registrato / riga di log | 512 caratteri / 8 KiB |
| Connessioni, totali / per IP sorgente | 256 / 16 |
| Timeout del socket inattivo / connessione intera | 15 s / 30 s |
| Token di sessione | 1 ora ciascuno, al massimo 1000 (si scarta il più vecchio) |
| Upload `dixell` salvati | 8 KiB ciascuno, in memoria, azzerati oltre 256 file |
| File di log | 256 MB, più 4 file ruotati |
| Coda del log | 4096 eventi |
| Eventi per IP sorgente al minuto | 600 di routine + 600 tra login e comandi |

## Limiti

- Interazione superficiale: un attaccante autenticato ha a disposizione una
  manciata di comandi via API, non l'applicazione completa. Solo `danfoss`
  mostra qualcosa nel browser dopo il login: una tabella degli otto banchi.
- Il codice pubblico si può riconoscere. L'identità generata aiuta, ma cambia
  il markup della persona per un deployment che ti interessa.
- Gli IP cloud sono sospetti. Alcuni scanner segnalano i dispositivi
  industriali su hosting cloud come probabili honeypot; un indirizzo non cloud
  è più convincente.

## Da fare

Lavoro aperto, più o meno in ordine di priorità. Vedi FINGERPRINTS.md per lo
stato attuale, con le fonti, di ogni persona.

Impronte di prima mano (serve un account Shodan/Censys):
- Esegui `http.title:"TelevisGo"` e `http.title:"Data Manager"` e cattura, per
  ciascuno, l'header `Server`, l'`http.favicon.hash` e un banner grezzo.
  Imposta l'header via `SERVER_HEADER`, fai coincidere il favicon (vedi sotto)
  e registrali in FINGERPRINTS.md come di prima mano. Questo porta `eliwell` e
  `rdm` al livello buono.
- Verifica l'header Server di `aksc355` su un'unità reale; imposta
  `SERVER_HEADER` se ne invia uno.
- Cattura una seconda unità `dixell`: il blocco di header, la banda firmware e
  il contenuto della pagina poggiano su una sola XWEB 500 EVO osservata.
- Favicon: servire un favicon il cui hash sia uguale all'`http.favicon.hash`
  dell'unità reale. È una delle impronte Shodan più forti e oggi non ne
  impostiamo uno.

Copertura degli exploit:
- Generalizzare lo strato di risposta agli exploit invertendo i template Nuclei
  pubblici (l'approccio funnypot), così l'esca restituisce risposte esatte al
  byte per molti CVE ICS, non solo per quelli scritti a mano. È autonomo; non
  serve Shodan.

Debito di fedeltà e onestà:
- Catturare pagine di riferimento reali per le persona superficiali e medie
  (`aksc355`, `rdm`) e sostituire il markup segnaposto; impostare le lunghezze
  esatte in byte delle pagine.
- Verificare in modo indipendente i due CVE Danfoss senza fonte
  (CVE-2023-25914, CVE-2023-25915) oppure rietichettarli nella persona
  `danfoss` e in FINGERPRINTS.md.

Hardening del deployment:
- Fissare `FRIDGEP0T_REF` a un commit revisionato in cloud-init.yaml;
  aggiornare i digest delle immagini base nel Containerfile quando le cambi.
- Fare il deploy su un IP non cloud; i range cloud sono segnalati come
  probabili honeypot.

Opzionale, valore più basso:
- Aggiungere `aksm800` (AK-SM 800 legacy, pagina Flash-loader) e `aksc255` come
  varianti sottili, se serve coprire proprio quei modelli. Entrambe sarebbero
  superficiali senza pagine di riferimento reali.
- Aggiungere un controllo in CI che faccia rispettare FINGERPRINTS.md rispetto
  al codice (oggi `tests/attack.rs` fa rispettare il comportamento, non il
  documento).

## Ringraziamenti

Grazie a [Nik0l4](https://github.com/nic0ladibari) per l'aiuto sul fingerprint
di Danfoss (pagina di login, banda firmware e algoritmo del code of the day).

## Licenza

BSD-4-Clause. L'uso e la modifica sono liberi, ma qualunque pubblicazione,
rapporto, presentazione o altro materiale che menzioni le funzionalità o l'uso
di questo software deve riconoscere il titolare del copyright (clausola 3 di
`LICENSE`), e gli avvisi devono accompagnare le copie. `CITATION.cff` fornisce
una citazione già pronta.
