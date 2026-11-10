# fridgep0t

**English** · [Italiano](README.it.md) · [Español](README.es.md)

> «Farò sicuramente dei danni, ma mi rivolgo a tutte queste casalinghe che
> vedono su Internet la borsa che gli piace e che costa solo 6 euro al mese, il
> frigorifero che costa solo 19 euro al mese, quel materasso che ne costa 22 al
> mese. Quando arriva la fine del mese, arrivano pure i Carabinieri […]»
>
> *"I will surely do some damage, but I'm talking to all those housewives who
> see online the bag they like for only 6 euros a month, the fridge for only 19
> euros a month, that mattress for 22 a month. When the end of the month comes,
> the Carabinieri come too […]"*
>
> — Renato Zero, [interview with Fanpage.it](https://www.fanpage.it/spettacolo/interviste/renato-zero-dopo-la-morte-di-mia-madre-ho-chiesto-a-dio-di-dialogare-con-lei-e-me-lo-ha-concesso/) (our translation)

He knew it before any of us: where there are fridges, sooner or later the
Carabinieri show up.

A honeypot for supermarket refrigeration controllers.

In October and November 2026, attackers broke into internet-facing refrigeration
supervisors across Europe using default passwords and old, unpatched firmware,
then forced defrost cycles. fridgep0t pretends to be one of those controllers.
It records who connects, what passwords they try and which public exploits they
use, and it never gives them anything real.

It is a single static binary with no runtime dependencies, built around three
choices: a per-deployment identity so instances cannot be catalogued together,
persona fidelity anchored to public sources, and supply-chain hardening.

## Design

**Per-deployment identity.** A decoy that ships one hard-coded store name, MAC
address and CA subject looks identical in every deployment to anyone doing
honeypot detection. Here the store name, hostname, MAC, firmware string and its
`Last-Modified` time are generated per start, and so are the certificate's keys
and validity window (set `TLS_DIR` to keep the certificate across restarts, as
the container image does). The certificate subjects are not: they are fixed per
persona, like the model-wide CN a real unit carries. Set
`IDENTITY_SEED` to keep a stable identity across restarts without sharing it
with any other deployment; leave it unset for a fresh identity each start. The
generated store name follows the language of `DEVICE_TZ` (or `STORE_LANG`), and
the MAC carries the vendor's IEEE-registered OUI (see FINGERPRINTS.md).

HTTPS is available for every persona (`HTTPS_PORT`). The certificate issuer is
filled in only for `danfoss`, the one unit whose issuer details are documented;
the others carry a bare CN rather than a guessed organisation.

**Persona consistency.**
- The firmware string is generated once and reused everywhere it appears, so the
  login page and the XML `read_units` response never disagree: a page naming
  one build and an API naming another is a classic honeypot tell.
- `read_date_time` answers in the device's own time zone (`DEVICE_TZ`, default
  `Europe/Rome`), not the container's UTC. A supervisor in a European store
  would report local time.

**A believable CVE-2021-45420 for the Dixell persona.** Answering the XWEB upload
paths with an empty `200` is something any automated checker sees through.
fridgep0t simulates the write-then-read handshake the public exploit and its
Nuclei template actually verify: a `POST` to an upload CGI "stores" the file in
memory, a following `GET /logo/<name>` returns it, and `cal_dir.cgi` lists it.
Nothing touches disk; stored uploads are capped and logged as `control` events.

**Supply-chain hardening.**
- `cloud-init.yaml` clones your own repository (`FRIDGEP0T_REPO`) at a reviewed
  commit (`FRIDGEP0T_REF`) instead of tracking a moving branch, refuses to build
  if either is missing or the checkout fails,
  and installs an nftables ruleset that drops all egress except DNS and new TCP
  80/443 (needed for package and image pulls; mirrors are not pinned by
  address) — the decoy itself never connects out.
- The `Containerfile` builds static and ships on distroless `nonroot`: no shell,
  no package manager, nothing to pivot to. Base images are pinned by digest,
  with the refresh command documented inline.
- In-process certificate generation (no `openssl` shell-out). Keys are fresh per
  start, or per deployment when `TLS_DIR` keeps the certificate; validity is
  backdated by a random amount so the certificate never reveals the build date.

## Personas

| Persona   | Pretends to be                      | Serves                                                              |
|-----------|-------------------------------------|--------------------------------------------------------------------|
| `danfoss` | Danfoss AK-SM 800A system manager   | StoreView login, the XML API at `/html/xml.cgi` and `/xml.cgi`, HTTP+HTTPS |
| `dixell`  | Copeland/Dixell XWEB EVO supervisor | Login page, `cgi-bin/login.lua` flow, the XWEB 500 CGI paths        |
| `aksc355` | Danfoss AK-SC 355 (legacy)          | Login page with the documented Forgot-Credentials / MAC-disclosure flow |
| `carel`   | Carel pCOWeb                        | thttpd server, HTTP Basic auth, `/config/` pages incl. the cleartext credential disclosure |
| `eliwell` | Eliwell TelevisGo                   | Login page (Administrator / 0 default), welcome/version payload |
| `rdm`     | RDM Data Manager                    | Login page with the documented `1234` default, CGI login/status |

These six cover every vendor family named in the post-attack exposure reports
(Danfoss, Dixell/Copeland XWEB, Carel, Eliwell, RDM).

Any persona can also run an optional Modbus TCP service with fake case
temperatures, setpoints and a defrost register (see "Modbus TCP" below). Off
unless `MODBUS_PORT` is set.

The `aksc355` persona is deliberately shallow. It targets the other legacy model
named in the CERT-FR alert (title: "Danfoss série AK-SM et AK-SC"), but we do not
have a copy of the real AK-SC 355 web interface, so it is anchored only to
publicly documented behaviour: the firmware band ("3.091 or higher"), the default
accounts, and the "Forgot Credentials -> Reset Password" screen that discloses the
unit's MAC and a reset code. It is enough to catch a scanner hunting specifically
for AK-SC 355 units; it will not survive deep interaction. For a deployment you
care about, capture a real unit's pages and replace the markup, and set
`SERVER_HEADER` to the web server string you observe — we do not ship one,
because a wrong value is a worse tell than none.

## Exploits it recognises

Requests that match a public exploit get an `exploit` field in the log:

- CVE-2023-25914 — AK-SM 800A path traversal via `get_file`
- CVE-2023-25915 — AK-SM 800A command injection via `load_cert`
- CVE-2025-41452 — AK-SM 800A nginx header overwrite via `load_nginx_headers`
- CVE-2025-41450 — AK-SM 800A "code of the day" login bypass, noting whether the
  attacker computed the correct code
- CVE-2021-45420 — XWEB 500 unauthenticated file write under `/cgi-bin/`
- CVE-2026-25085 — XWEB Pro login bypass via an unexpected `auth_mode`

### Fidelity tiers

Personas are built only from public sources (vendor manuals, CVE and vendor
advisories, exposure-report signatures) and original markup — never captured
firmware. Fidelity therefore varies with how much is publicly documented:

- `danfoss`, `dixell`, `carel`, `eliwell` — good: server header, auth flow,
  default credentials and key paths are all publicly documented.
- `rdm` — medium: the `1234` default and CGI login are documented, but the exact
  Server header and page bytes are not, so the markup is plain and the header is
  left to `SERVER_HEADER`.
- `aksc355` — shallow: anchored to the firmware band and the Forgot-Credentials
  flow only.

Where a real device detail cannot be cited it is left configurable and empty
rather than guessed, because a wrong fingerprint is a worse tell than a missing
one. For a deployment you care about, capture a real unit's pages and set
`SERVER_HEADER` to the value you observe.

## What each persona answers

Common to all six:

- The landing page is served on `/` and `/index.html`, to `GET` and `HEAD`
  only. Any other method gets the server's own refusal: 405, or 501 on `carel`.
- Unknown paths get the persona's 404 page; a malformed request its 400 page; a
  body over 8 KiB its 413 page (400 on `carel`).
- A form or API login that "succeeds" hands out a session token valid for one
  hour, and its answer is delayed by 0.6 to 1.4 seconds, as a real unit takes a
  moment. `carel` uses HTTP Basic auth instead: no token, no delay.
- Every request, login, command and exploit attempt is logged (see "Reading the
  log").

**`danfoss`** (nginx-style headers, keep-alive on the login page)
- `POST /html/xml.cgi` (also `/xml.cgi`) takes an XML `<cmd action="…"/>`;
  `OPTIONS` answers 204 and any other method 405.
- `getauth` logs in and returns a session token, sent back in the `AKSM-Auth`
  header. Credentials given inline on another command work too.
- `read_date_time` answers without a session, in the device's time zone.
- `read_units` returns the store name, firmware and MAC; `read_devices` the
  eight cases with temperature, setpoint and defrost state.
- Any other action from a session is logged as `control`. One whose name
  contains `defrost`, with `node="1"` to `"8"`, starts the simulated defrost.
- In a browser, a successful login replaces the form with a table of the eight
  cases and a Defrost button on each row. The page drives the same XML
  commands, so a click is logged exactly like a scripted command.
- Logins that succeed: `Supervisor`/`12345`, `superviseur`/`12345`,
  `admin`/`admin`, `admin`/`1234` (user name in any case), or the code of the
  day with `eds_only` or `quantum_only`.

**`dixell`**
- `POST /cgi-bin/login.lua` (also `/login`) takes the form fields `username`,
  `password` and `auth_mode`. Five failures from one source on one user name
  lock that pair for 300 seconds.
- `POST /cgi-bin/datachart.cgi` with `SSES=<token>` returns the case
  temperatures; without a valid session it returns the login page.
- `POST /cgi-bin/logo_extra_upload.cgi`, `cal_save.cgi` or `lo_utils.cgi`
  "stores" an upload: the first line is the file name, the rest the content, up
  to 8 KiB, in memory only. `GET /logo/<name>` returns it; `GET
  /cgi-bin/cal_dir.cgi` or `/logo/` lists what was stored.
- The scripts and stylesheets the page references answer an empty 200.
- Logins that succeed: `admin`/`Admin`, `Admin`/`Admin`, `admin`/`admin`.

**`aksc355`**
- `POST /cgi-bin/login.cgi` (also `/login`) takes `user` or `username`, and
  `password` or `pass`.
- `POST /cgi-bin/reset.cgi` (also `/reset`) is the Forgot-Credentials flow: it
  returns the unit's MAC and a random reset code.
- Logins that succeed: `admin`, `administrator`, `user` or `guest` with
  `danfoss`; `Supervisor`/`12345` (user name in any case).

**`carel`** (thttpd 2.25b's response headers and error pages; answers in the request's HTTP version)
- The landing page is also served on `/http/index.html`, and method names are
  matched in any case.
- Everything under `/config/` asks for HTTP Basic auth, realm `pCOWeb`.
  `/config/pw_changeusers.html` lists the factory accounts and passwords in
  clear; any other config path returns a stub with the MAC and version.
- Logins that succeed: `httpadmin`/`fhttpadmin`, `admin`/`fadmin`,
  `carel`/`fcarel`, `guest`/`fguest`, `root`/`froot`.

**`eliwell`**
- `POST /login` (also `/j_security_check`) takes `user`, `username` or
  `j_username`, and `password` or `j_password`.
- `GET /welcome` (also `/version`) returns product, vendor, software version
  and plant name, without a session.
- Logins that succeed: `Administrator` with `0` or with an empty password.

**`rdm`**
- `POST /cgi-bin/login.cgi` (also `/login`) takes `user` or `username`, and
  `password`, `pass` or `pin`.
- `/cgi-bin/status.cgi` (also `/status`) returns the eight cases with
  temperature, setpoint and defrost state, without a session, as on a unit
  where "Force CGI login" is off.
- Logins that succeed: password `1234` with the user empty, `admin` or `user`.

### HTTPS

`HTTPS_PORT` adds a TLS listener for any persona. It speaks TLS 1.2 only, as
the real units do, and presents a leaf certificate signed by a self-signed CA,
both generated in-process and backdated. A failed or timed-out handshake is
logged as `tls_error`.

### Modbus TCP

`MODBUS_PORT` adds a Modbus TCP listener for any persona, answering any unit
id.

| Registers | Content |
|-----------|---------|
| 0–7       | Case temperatures, tenths of °C, signed, with sensor jitter |
| 100–107   | Case setpoints, tenths of °C |
| 200–207   | Defrost command: non-zero starts a defrost, zero stops it |

- Function codes 3 and 4 read, 6 and 16 write, and 43/14 returns the device
  identification (vendor, product, firmware). Any other function gets
  exception 1, an unmapped address exception 2, a bad count exception 3.
- A defrost raises the case temperature about 1.5 °C per minute for twenty
  minutes (at most +25 °C), then clears its register and the case pulls back
  down to its base over forty-five minutes, as a real one would; a poller never
  sees it snap back. Stopping it early recovers from where it got to, and
  restarting mid-recovery climbs on from the current temperature.
- The same case state is what `read_devices`, `datachart.cgi` and `status.cgi`
  report over HTTP.

## Quick start

```
cargo build --release --locked
PERSONA=danfoss HTTP_PORT=8080 ./target/release/fridgep0t
```

A binary built on your workstation embeds your home directory in panic
locations. Deploy the container build, which has no such paths, or build with
`RUSTFLAGS="--remap-path-prefix=$HOME=~"` (a `[build] rustflags` entry in your
user-level `~/.cargo/config.toml` makes that permanent).

Open http://localhost:8080 and every request shows up as a JSON line on stdout
and in `events.jsonl`. Run the tests: unit tests for the parsers and state, and an
integration suite that starts the binary per persona and attacks it over HTTP,
HTTPS and Modbus, including the timeout, connection-cap and shutdown paths:

```
cargo test --release --locked
```

CI runs build, test, clippy and fmt on stable, build and test on the minimum
supported Rust (1.75), and `cargo audit` on the locked dependencies. It also runs
every week, and its actions are pinned by commit SHA.

`SIGTERM` or Ctrl-C stops the decoy; it writes out the queued log events first,
for at most two seconds.

## Deploy

**Container.** The `Containerfile` builds the binary and ships it on distroless
`nonroot`, listening on 8080 (HTTP) and 8443 (HTTPS), logging to
`/logs/events.jsonl` and keeping its certificate in `/logs/tls`:

```
podman build -t fridgep0t .
podman run -d --name fridgep0t --restart=always \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 80:8080 -p 443:8443 -v fridgep0t-logs:/logs:U \
  -e PERSONA=danfoss -e IDENTITY_SEED=<your-own-random-string> \
  fridgep0t
```

**Fresh server.** Paste `cloud-init.yaml` into the "User data" box of a new
Ubuntu 24.04 server after setting `PERSONA`, `FRIDGEP0T_REPO` and
`FRIDGEP0T_REF` in it. It installs the firewall, builds the image from your
pinned commit, generates a random `IDENTITY_SEED` for that host and starts the
container with the flags above. Only `danfoss` gets the HTTPS port there. To
expose Modbus, follow the comment in the file.

## Configuration

| Variable        | Default           | Meaning                                              |
|-----------------|-------------------|------------------------------------------------------|
| `PERSONA`       | `danfoss`         | `danfoss`, `dixell`, `aksc355` (or `aksc`), `carel` (`pcoweb`), `eliwell` (`televisgo`), `rdm` (`datamanager`) |
| `BIND`          | `0.0.0.0`         | Address to listen on                                 |
| `HTTP_PORT`     | `8080`            | HTTP listener                                        |
| `HTTPS_PORT`    | `0` (off)         | HTTPS listener (certificate generated in-process)    |
| `MODBUS_PORT`   | `0` (off)         | Modbus TCP listener                                  |
| `LOG_PATH`      | `events.jsonl`    | Where events are appended                            |
| `DEVICE_TZ`     | `Europe/Rome`     | Time zone the decoy's clock reports                  |
| `IDENTITY_SEED` | none (random)     | Fixed seed for a stable per-deployment identity      |
| `TLS_DIR`       | none (fresh each start) | Directory that keeps the generated certificate across restarts (`/logs/tls` in the container image) |
| `STORE_NAME`    | generated         | Override the generated store name                    |
| `STORE_LANG`    | from `DEVICE_TZ`  | Language of the generated store banner: `it`, `de`, `fr`, `es`, `nl`, `en` |
| `FIRMWARE`      | generated         | Override the generated firmware string               |
| `MAC_OUI`       | per persona (IEEE) | Override the vendor OUI (`xx:xx:xx`) of the generated MAC |
| `SERVER_HEADER` | persona default   | Override the Server header for any persona (see Fidelity tiers) |

## Reading the log

The log rotates at 256 MB, keeping `events.jsonl.1` to `events.jsonl.4`.
`summary.py` turns a log into a short report:

```
python3 -I summary.py --hours 24 --ignore <your-own-ip> < events.jsonl
```

It prints totals (events, sources, logins tried and accepted, exploit attempts,
Modbus sources, control writes, defrost attempts), any gaps in the log, the top
exploits, IPs, credentials and paths, and one line per defrost attempt.

Every event is one JSON object with `ts` (UTC), `persona`, `proto` (`http`,
`https`, `modbus`, `tcp` or `system`), `src_ip`, `src_port` and `event`, plus
the fields of that event. Attacker-supplied fields are cut to 512 characters
and a line to 8 KiB (`"truncated": true` marks a line cut harder).

| Event | Logged when | Main fields |
|-------|-------------|-------------|
| `start` | The decoy starts | ports, store name, hostname, MAC, firmware, time zone |
| `request` | Any well-formed HTTP request | `method`, `path`, `host`, `user_agent`, `authorization`, `body`, `exploit` |
| `bad_request` | A request is refused (malformed, oversized, cut short) | `raw`, `exploit` |
| `login_attempt` | Any login, on any persona | `username`, `password`, `granted`; `locked`, `auth_mode`, `exploit` on `dixell` |
| `xml_cmd` | A `danfoss` XML command | `action`, `attrs`, `auth_header`, `session`, `exploit` |
| `control` | An attacker acts: a command, an upload, a credential or MAC disclosure | `action`; `node`, `defrost`, `path`, `stored_as`, `exploit` |
| `datachart` | A `dixell` data request | `session`, `request` |
| `connect`, `read`, `write`, `device_id` | Modbus traffic | `unit`, `fc`, `start`, `count` or `values`, `defrost` |
| `unsupported`, `malformed` | A Modbus function we do not answer, or a bad frame | `pdu_hex` or `header_hex` |
| `tls_error` | A TLS handshake fails or times out | `error` |
| `conn_refused` | A source is over its connection cap (at most once a minute per source) | |
| `log_suppressed` | A source reaches its events-per-minute cap | `class`, `per_minute` |
| `log_dropped` | The log queue was full | `count` |

## Safety

- Never runs commands, reads files, or forwards traffic. Exploit payloads are
  logged and dropped; "uploaded" files live in a capped in-memory map.
- Request bodies, logged fields and connections are capped, including a per-source
  limit so one attacker cannot crowd out others. Idle sockets time out; any
  connection is cut after 30 seconds however it trickles.
- HTTP is parsed strictly: only HTTP/1.0 and 1.1, well-formed header lines,
  exactly one `Host` on HTTP/1.1, a numeric `Content-Length` that agrees across
  repeats and fits the body cap, no `Transfer-Encoding`. Anything ambiguous is logged as `bad_request`,
  answered with the persona's 400 (or 413) error page and the connection closed,
  so a body can never be read as the next request.
- Over-long log lines are truncated; `summary.py` neutralises terminal escape
  codes from attacker input.
- Logging never stalls a connection: one writer thread drains a bounded queue;
  if the queue fills, the newest events are dropped and a `log_dropped` event
  reports how many. Shutdown waits at most two seconds for the writer to drain.
- One source cannot roll everyone else's events out of the size-bounded log:
  each source IP may log 600 events a minute, counted separately for routine
  events and for logins and commands, so a flood of requests cannot bury the
  command that follows it. Past the cap one `log_suppressed` event is written,
  then nothing until the minute is up. `summary.py` reports both kinds of gap.
- Log fields are attacker-controlled. Treat them as untrusted when you process them.

The limits are fixed in the code, not configurable, because they are the safety
net:

| Limit | Value |
|-------|-------|
| Request body | 8 KiB |
| Request headers | 16 KiB |
| Logged field / log line | 512 characters / 8 KiB |
| Connections, total / per source IP | 256 / 16 |
| Idle socket timeout / whole connection | 15 s / 30 s |
| Session tokens | 1 hour each, at most 1000 (the oldest is dropped) |
| Stored `dixell` uploads | 8 KiB each, in memory, cleared past 256 files |
| Log file | 256 MB, plus 4 rotated files |
| Log queue | 4096 events |
| Events per source IP per minute | 600 routine + 600 logins and commands |

## Limitations

- Shallow interaction: a logged-in attacker gets a handful of API commands, not
  the full app. Only `danfoss` shows anything in the browser after login: a
  table of the eight cases.
- Public code can be fingerprinted. The generated identity helps, but change the
  persona markup for a deployment you care about.
- Cloud IPs look suspicious. Some scanners flag industrial devices on cloud
  hosting as likely honeypots; a non-cloud address is more convincing.

## To do

Open work, roughly in priority order. See FINGERPRINTS.md for the current
sourced state of each persona.

First-party fingerprints (needs a Shodan/Censys account):
- Run `http.title:"TelevisGo"` and `http.title:"Data Manager"` and capture, for
  each, the `Server` header, the `http.favicon.hash` and one raw banner. Set the
  header via `SERVER_HEADER`, match the favicon (see below), and record them in
  FINGERPRINTS.md as first-party. This promotes `eliwell` and `rdm` to the good
  tier.
- Verify the `aksc355` Server header against a real unit; set `SERVER_HEADER`
  if it sends one.
- Capture a second `dixell` unit: the header block, firmware band and page
  content rest on a single observed XWEB 500 EVO.
- Favicon matching: serve a favicon whose hash equals the real unit's
  `http.favicon.hash`. It is one of the strongest Shodan fingerprints and we
  currently don't set one.

Exploit coverage:
- Generalise the exploit-response layer by inverting public Nuclei templates
  (the funnypot approach) so the decoy returns byte-exact responses for many ICS
  CVEs, not just the hand-written ones. Self-contained; needs no Shodan.

Fidelity and honesty debt:
- Capture real reference pages for the shallow/medium personas (`aksc355`,
  `rdm`) and replace the placeholder markup; set exact page byte lengths.
- Independently verify the two unsourced Danfoss CVEs (CVE-2023-25914,
  CVE-2023-25915) or relabel them in the `danfoss` persona and FINGERPRINTS.md.

Deployment hardening:
- Pin `FRIDGEP0T_REF` to a reviewed commit in cloud-init.yaml; refresh the base
  image digests in the Containerfile when you bump them.
- Deploy on a non-cloud IP; cloud ranges are flagged as likely honeypots.

Optional, lower value:
- Add `aksm800` (legacy AK-SM 800, Flash-loader page) and `aksc255` as thin
  variants if coverage of those exact models is needed. Both would be shallow
  without real reference pages.
- Add a CI check that enforces FINGERPRINTS.md against the code (today
  `tests/attack.rs` enforces the behaviour, not the document).

## Acknowledgements

Thanks to [Nik0l4](https://github.com/nic0ladibari) for help with the Danfoss
fingerprint (login page, firmware band and the code-of-the-day algorithm).

## License

BSD-4-Clause. Use and modification are free, but any publication, report,
presentation or other material that mentions features or use of this software
must acknowledge the copyright holder (clause 3 of `LICENSE`), and the notices
must travel with copies. `CITATION.cff` gives a ready-made citation.
