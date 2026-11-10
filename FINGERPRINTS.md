# Fingerprint provenance

Every persona in fridgep0t is built from public sources and original markup —
never from captured firmware. This file records, per persona, what each
observable fingerprint is and where it comes from, so the decoy is auditable and
so a reviewer can check an edit against a documented contract.

Two principles govern what is here:

- The primary internet-scan fingerprint for these devices is the HTTP title
  (`http.title` on Shodan, `services.http.response.html_title` on Censys), plus
  body content and, secondarily, the `Server` header. The titles below are all
  documented and correct.
- Where a real device detail cannot be cited from a public source, it is left
  configurable and empty (set via `SERVER_HEADER`) rather than guessed. A wrong
  fingerprint is a worse tell than a missing one.

Fidelity tiers: **good** = title, auth flow, default credentials and key paths
all publicly documented; **medium** = defaults and behaviour documented but
`Server` header / exact page bytes are not; **shallow** = anchored to a firmware
band and one documented behaviour only.

The behavioural assertions below are enforced by `tests/attack.rs`.

---

## danfoss — Danfoss AK-SM 800A — tier: good

| Fingerprint | Value | Source |
|---|---|---|
| http.title | `Danfoss StoreView` | distinctive StoreView page title noted in exposure reporting [FE] |
| Server | `nginx` | CVE-2025-41452 concerns the unit's externally accessible nginx server [CLA] |
| Default login | `Supervisor` / `12345` | factory default; factory-default use reported in the campaign [CISA] |
| Key path | `/html/xml.cgi` (XML API) | AK-SM XML interface path; not captured from a unit here |
| Login page content | heading `System Manager 800A`, `Version SVB501.000.139`, Username/Password fields, dark `Sign In` button | first-party [IHX]: the article's login screenshot. Our markup reproduces this; it was not copied. |
| Post-login chrome | red header `Danfoss ENGINEERING TOMORROW`, label `AK-SM800A Series` | first-party [IHX]: the article's menu/circuits screenshots |
| Firmware band | `SVB501.000.xxx` | first-party [IHX]: the login screenshot shows SVB501.000.139. One sample. |
| MAC OUI | `00:07:68` | IEEE MA-L: Danfoss A/S [IEEE] |
| Exploits tagged | CVE-2025-41450 (code-of-the-day auth bypass) | Claroty Team82 Aug-2026; Ironhackers write-up. The `check_code_of_day` algorithm is reconstructed there and reproduced by `code_of_the_day` (known-answer tested), so the log's `correct code` is accurate. |
| | CVE-2025-41452 (nginx headers.conf overwrite) | Claroty Team82 [CLA] |
| | CVE-2023-25914 (path traversal), CVE-2023-25915 (command injection) | no independent public source; not re-verified here |

## dixell — Copeland/Dixell XWEB EVO — tier: good

| Fingerprint | Value | Source |
|---|---|---|
| http.title | `XWEB EVO` | first-party [OBS]: title Shodan records for the unit |
| Server | none | first-party [OBS]: the banner carries no Server header. Override with `SERVER_HEADER`. |
| Response headers | `Content-Type: text/html`, then the block in `DIXELL_HEADERS` (`Cache-Control`, `X-Content-Type-Options`, `X-Robots-Tag`, `X-Permitted-Cross-Domain-Policies`, `Content-Security-Policy`, `Feature-Policy`, `Permissions-Policy`, `Referrer-Policy`, `Vary`, `X-Frame-Options`, `X-XSS-Protection`, `X-UA-Compatible`), `Content-Length`, `Date` last | first-party [OBS]: names, values and order match the banner line for line |
| Login page content | software version, plant name, product name `XWEB 500 EVO`, user name / password / language fields, clock, MAC as 12 upper-case hex digits without separators | first-party [OBS]: what the unit's login page shows. The markup is ours; element ids were not captured. |
| Firmware band | `5.8.x` | first-party [OBS]: the one unit observed ran 5.8.8. A single sample. |
| Page length | not matched (ours is ~3 KiB) | the observed unit's login page was 8258 bytes, but we have no capture of the content that fills it; padding to length with blank lines would be a worse tell than a shorter page. Capture the real page to close this. |
| Default login | `Admin` / `Admin` | factory default |
| Lockout | 5 failures per source IP and username, 300 s | our choice, unverified: the scope and timing of a real unit's lockout are not publicly documented. Per source so one scanner cannot lock the default for the next visitor. |
| Key paths | `cgi-bin/login.lua`, `cgi-bin/datachart.cgi`, `/cgi-bin/{logo_extra_upload,cal_save,lo_utils,cal_dir}.cgi` | XWEB CGI set |
| MAC OUI | `00:0a:f6` | first-party [OBS]: prefix of the MAC on the unit's login page; IEEE MA-L: Copeland LP [IEEE]. Override with `MAC_OUI`. |
| Exploits tagged | CVE-2021-45420 (unauth file write) | Swascan advisory; Exploit-DB 50639; Nuclei template `CVE-2021-45420` |
| | CVE-2026-25085 (auth-routine bypass, XWEB Pro line) | ICS-CERT ICSA-26-057-10; NVD, published 2026-02-27 |

Note: CVE-2026-25085 is scoped to the XWEB **Pro** firmware (300D/500B/500D ≤ 1.12.1).
The persona imitates XWEB EVO; the tag names the Pro line so the attribution is
not misread as applying to EVO itself.

## aksc355 — Danfoss AK-SC 355 — tier: shallow

| Fingerprint | Value | Source |
|---|---|---|
| http.title | `AK-SC 355` | model name; CERT-FR ALE-012 names the AK-SC series |
| Server | none | not publicly documented. Override with `SERVER_HEADER`. |
| Default login | `admin`/`danfoss` family defaults, `Supervisor`/`12345` | Danfoss web front-end defaults |
| Behaviour | Forgot-Credentials -> reset screen discloses MAC + reset code | Danfoss "supporting supermarkets" support material |
| Firmware band | `3.091` or higher | Danfoss AK-EM 800 guide (front-end versions supported) |
| MAC OUI | `00:07:68` | IEEE MA-L: Danfoss A/S [IEEE] |
| Certificate CN | `AKSC355` (CA and leaf) | not publicly documented; a bare model name rather than the AK-SM scheme |

Shallow on purpose: no public copy of the real AK-SC 355 web interface. Enough to
catch a scanner hunting specifically for AK-SC 355; it will not survive deep
interaction.

## carel — Carel pCOWeb — tier: good

| Fingerprint | Value | Source |
|---|---|---|
| http.title | `pCOWeb` | pCOWeb web interface; Shodan query `pCOWeb` |
| Server | `thttpd/2.25b 29dec2003` | pCOWeb manual: "the web server included in the pCOWeb is thttpd". Exact build string corroborated as a real, commonly-observed value by a public Shodan dork. Override with `SERVER_HEADER`. |
| Response headers | `Server`, `Content-Type` (charset `iso-8859-1`), `Date`, `Last-Modified`, `Accept-Ranges: bytes`, `Connection: close`, then `Content-Length`; on an error `Cache-Control: no-cache,no-store` instead of a length; status line in the request's HTTP version | thttpd 2.25b source, `send_mime()` in `libhttpd.c` (acme.com/software/thttpd). True of that release as shipped; a pCOWeb build may differ. |
| Error pages | thttpd's built-in 400 / 401 / 404 / 501 pages; methods matched case-blind, anything but GET/HEAD/POST refused with 501 | thttpd 2.25b source, `send_response()` and the `err…form` strings in `libhttpd.c`. A unit with its own `errors/errNNN.html` files would differ; none is documented. |
| Auth | HTTP Basic (`.htpasswd`), realm `pCOWeb` | pCOWeb manual; RT-SA-2019-013 |
| Default logins | `httpadmin`/`fhttpadmin`, `admin`/`fadmin`, `carel`/`fcarel`, `guest`/`fguest`, `root`/`froot` | pCOWeb manual §9.2.1/§9.7.2; RT-SA-2019-013 |
| Key path | `/config/pw_changeusers.html` (cleartext credential disclosure) | RT-SA-2019-013 |
| Firmware format | `A 1.4.x - B 1.4.y` | RT-SA-2019-013 (observed "A 1.4.11 - B 1.4.2") |
| Exploit tagged | CVE-2019-13553 (cleartext credential storage/disclosure) | RT-SA-2019-013 |
| MAC OUI | `00:0a:5c` | IEEE MA-L: Carel s.p.a. [IEEE] |

## eliwell — Eliwell TelevisGo — tier: good (title/login); header unknown

| Fingerprint | Value | Source |
|---|---|---|
| http.title | `TelevisGo` | TelevisGo web UI |
| Server | none | not publicly documented (runs on MS Windows 10 IoT, server not cited). Override with `SERVER_HEADER`. |
| Default login | `Administrator` / `0` | TelevisGo user manual |
| Login fields | plant name, language selector, "Save this information" checkbox | TelevisGo user manual |
| Version format | `5.x.0.0` (current line: v10) | TelevisGo user manual; Eliwell product page |
| Platform | MS Windows 10 IoT | Eliwell product page |
| MAC OUI | `00:18:bb` | IEEE MA-L: Eliwell Controls srl [IEEE]; a PC-based unit may carry its NIC maker's OUI instead. Not exposed by this persona. |

## rdm — Resource Data Management Data Manager — tier: medium

| Fingerprint | Value | Source |
|---|---|---|
| http.title | `Data Manager` | RDM Data Manager web app |
| Server | none | not publicly documented. Override with `SERVER_HEADER`. |
| Default password | `1234` | Safety Detectives; Cooling Post |
| Access model | interface often reachable without auth until "Force CGI login" is set | Cooling Post (RDM statement) |
| Related CVEs | CVE-2015-6468 (CSRF), plaintext passwords in page source; CVE-2016-4505 (Intuitive 650 TDB) | SecurityWeek; NVD |
| MAC OUI | `00:05:bc` | IEEE MA-L: Resource Data Management Ltd [IEEE] |

Medium on purpose: the `1234` default and CGI login are documented, but the
Server header and exact page bytes are not, so the markup is deliberately plain.

---

## References

- [FE] Field Effect, "Not just refrigerators: the security challenges of connected OT" (Nov 2026) — AK-SM 800A StoreView title, vendor list.
- [CLA] Claroty Team82 via TechRadar, "hidden daily passwords and command injection flaws" (Aug 2026) — CVE-2025-41450, CVE-2025-41452, nginx.
- [CISA] "Cold Chain Cyberattack" advisory coverage — factory-default use, CVE-2025-41450.
- CERT-FR CERTFR-2026-ALE-012 — "Danfoss série AK-SM et AK-SC".
- Swascan, "Security Advisory: Emerson – Dixell XWEB-500 Multiple Vulnerabilities (CVE-2021-45420)"; Exploit-DB 50639; projectdiscovery nuclei-templates `CVE-2021-45420`.
- NVD / ICS-CERT ICSA-26-057-10 — CVE-2026-25085 (Copeland XWEB Pro auth bypass).
- RedTeam Pentesting RT-SA-2019-013 — Carel pCOWeb credential storage/defaults; Carel pCOWeb user manual (+030220471).
- Eliwell TelevisGo user manual; Eliwell product pages.
- Safety Detectives / Cooling Post — RDM default password "1234"; SecurityWeek — RDM Data Manager CVEs; NVD CVE-2015-6468, CVE-2016-4505.
- [IEEE] IEEE Registration Authority, MA-L (OUI) public listing, standards-oui.ieee.org, retrieved 2026-11-09.
- [OBS] First-party observation, 2026-11-10: the Shodan host page (port 80 banner) and the public login page of one internet-exposed XWEB 500 EVO. The unit's address, plant name and full MAC are deliberately not recorded here.
- Danfoss AK-EM 800 installation guide — AK-SC 355 front-end "3.091 or higher"; Danfoss support material — AK-SC reset/MAC disclosure.

Dates and details here are from public sources at time of writing and may have
moved on; re-check before relying on any single value for a real deployment.
