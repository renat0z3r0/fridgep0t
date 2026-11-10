# fridgep0t

[English](README.md) · [Italiano](README.it.md) · **Español**

> «Farò sicuramente dei danni, ma mi rivolgo a tutte queste casalinghe che
> vedono su Internet la borsa che gli piace e che costa solo 6 euro al mese, il
> frigorifero che costa solo 19 euro al mese, quel materasso che ne costa 22 al
> mese. Quando arriva la fine del mese, arrivano pure i Carabinieri […]»
>
> *«Seguro que haré algún daño, pero me dirijo a todas esas amas de casa que
> ven en internet el bolso que les gusta y que cuesta solo 6 euros al mes, el
> frigorífico que cuesta solo 19 euros al mes, ese colchón que cuesta 22 al
> mes. Cuando llega el fin de mes, llegan también los Carabinieri […]»*
>
> — Renato Zero, [entrevista en Fanpage.it](https://www.fanpage.it/spettacolo/interviste/renato-zero-dopo-la-morte-di-mia-madre-ho-chiesto-a-dio-di-dialogare-con-lei-e-me-lo-ha-concesso/) (traducción nuestra)

Él ya lo sabía, antes que todos nosotros: con los frigoríficos, tarde o
temprano, llegan los Carabinieri.

Un honeypot para controladores de refrigeración de supermercados.

En octubre y noviembre de 2026, unos atacantes entraron en supervisores de
refrigeración expuestos a internet en toda Europa usando contraseñas por
defecto y firmware antiguo sin parchear, y forzaron ciclos de desescarche.
fridgep0t finge ser uno de esos controladores. Registra quién se conecta, qué
contraseñas prueba y qué exploits públicos usa, y nunca le entrega nada real.

Es un único binario estático sin dependencias en tiempo de ejecución,
construido en torno a tres decisiones: una identidad por despliegue, para que
las instancias no se puedan catalogar juntas; una fidelidad de las personas
anclada a fuentes públicas; y el endurecimiento de la cadena de suministro.

## Diseño

**Identidad por despliegue.** Un señuelo que sale con un nombre de tienda, una
MAC y un subject de CA fijos en el código es idéntico en cada despliegue para
cualquiera que haga detección de honeypots. Aquí el nombre de la tienda, el
hostname, la MAC, la cadena de firmware y su `Last-Modified` se generan en cada
arranque, igual que las claves y la ventana de validez del certificado (define
`TLS_DIR` para conservar el certificado entre reinicios, como hace la imagen de
contenedor). Los subjects del certificado no: son fijos por persona, como el CN
de modelo que lleva una unidad real. Define `IDENTITY_SEED` para mantener una
identidad estable entre reinicios sin compartirla con ningún otro despliegue;
déjalo vacío para tener una identidad nueva en cada arranque. El nombre de
tienda generado sigue el idioma de `DEVICE_TZ` (o `STORE_LANG`), y la MAC lleva
el OUI registrado en el IEEE por el fabricante (ver FINGERPRINTS.md).

HTTPS está disponible para todas las personas (`HTTPS_PORT`). El emisor del
certificado solo se rellena para `danfoss`, la única unidad cuyos datos de
emisor están documentados; las demás llevan un CN a secas en lugar de una
organización adivinada.

**Coherencia de la persona.**
- La cadena de firmware se genera una vez y se reutiliza en todos los sitios
  donde aparece, de modo que la página de login y la respuesta XML `read_units`
  nunca se contradicen: una página que nombra una build y una API que nombra
  otra es un indicio clásico de honeypot.
- `read_date_time` responde en la zona horaria del dispositivo (`DEVICE_TZ`,
  por defecto `Europe/Rome`), no en el UTC del contenedor. Un supervisor en una
  tienda europea informaría la hora local.

**Un CVE-2021-45420 creíble para la persona Dixell.** Responder a las rutas de
subida de XWEB con un `200` vacío es algo que cualquier comprobador automático
descubre. fridgep0t simula el intercambio de escribir y luego leer que el
exploit público y su plantilla de Nuclei verifican de verdad: un `POST` a un
CGI de subida "guarda" el fichero en memoria, un `GET /logo/<nombre>` posterior
lo devuelve, y `cal_dir.cgi` lo lista. Nada toca el disco; las subidas
guardadas tienen un tope y se registran como eventos `control`.

**Endurecimiento de la cadena de suministro.**
- `cloud-init.yaml` clona tu propio repositorio (`FRIDGEP0T_REPO`) en un commit
  revisado (`FRIDGEP0T_REF`) en lugar de seguir una rama que se mueve, se niega
  a compilar si falta alguno de los dos o si el checkout falla, e instala un
  conjunto de reglas nftables que descarta todo el tráfico saliente salvo el
  DNS y las conexiones TCP nuevas a 80/443 (necesarias para descargar paquetes
  e imágenes; los mirrors no están fijados por dirección). El señuelo en sí
  nunca abre conexiones salientes.
- El `Containerfile` compila en estático y se distribuye sobre distroless
  `nonroot`: sin shell, sin gestor de paquetes, nada sobre lo que pivotar. Las
  imágenes base están fijadas por digest, con el comando de actualización
  documentado en el propio fichero.
- Generación del certificado en el propio proceso (sin llamar a `openssl`). Las
  claves son nuevas en cada arranque, o una por despliegue cuando `TLS_DIR`
  conserva el certificado; la validez se retrasa una cantidad aleatoria, de
  modo que el certificado nunca revela la fecha de compilación.

## Personas

| Persona   | Finge ser                           | Sirve                                                               |
|-----------|-------------------------------------|--------------------------------------------------------------------|
| `danfoss` | System manager Danfoss AK-SM 800A   | Login StoreView, la API XML en `/html/xml.cgi` y `/xml.cgi`, HTTP+HTTPS |
| `dixell`  | Supervisor Copeland/Dixell XWEB EVO | Página de login, flujo `cgi-bin/login.lua`, las rutas CGI de XWEB 500 |
| `aksc355` | Danfoss AK-SC 355 (legacy)          | Página de login con el flujo documentado Forgot-Credentials / divulgación de la MAC |
| `carel`   | Carel pCOWeb                        | Servidor thttpd, HTTP Basic auth, páginas `/config/` incluida la divulgación de credenciales en claro |
| `eliwell` | Eliwell TelevisGo                   | Página de login (por defecto Administrator / 0), payload welcome/version |
| `rdm`     | RDM Data Manager                    | Página de login con el valor por defecto documentado `1234`, login/status CGI |

Estas seis cubren todas las familias de fabricantes nombradas en los informes
de exposición posteriores a los ataques (Danfoss, Dixell/Copeland XWEB, Carel,
Eliwell, RDM).

Cualquier persona puede además ofrecer un servicio Modbus TCP opcional con
temperaturas de los muebles, consignas y un registro de desescarche falsos (ver
"Modbus TCP" más abajo). Está apagado mientras no se defina `MODBUS_PORT`.

La persona `aksc355` es deliberadamente superficial. Apunta al otro modelo
legacy nombrado en la alerta del CERT-FR (título: "Danfoss série AK-SM et
AK-SC"), pero no tenemos una copia de la interfaz web real del AK-SC 355, así
que se ancla solo al comportamiento documentado públicamente: la banda de
firmware ("3.091 or higher"), las cuentas por defecto y la pantalla "Forgot
Credentials -> Reset Password" que revela la MAC de la unidad y un código de
reset. Basta para atrapar a un escáner que busque específicamente unidades
AK-SC 355; no aguanta una interacción profunda. Para un despliegue que te
importe, captura las páginas de una unidad real y sustituye el marcado, y
define `SERVER_HEADER` con la cadena del servidor web que observes: no
incluimos ninguna, porque un valor equivocado delata más que uno ausente.

## Exploits que reconoce

Las peticiones que coinciden con un exploit público reciben un campo `exploit`
en el log:

- CVE-2023-25914 — path traversal del AK-SM 800A mediante `get_file`
- CVE-2023-25915 — inyección de comandos del AK-SM 800A mediante `load_cert`
- CVE-2025-41452 — sobrescritura de cabeceras nginx del AK-SM 800A mediante
  `load_nginx_headers`
- CVE-2025-41450 — bypass del login del AK-SM 800A con el "code of the day",
  anotando si el atacante calculó el código correcto
- CVE-2021-45420 — escritura de ficheros sin autenticación en XWEB 500 bajo
  `/cgi-bin/`
- CVE-2026-25085 — bypass del login de XWEB Pro mediante un `auth_mode`
  inesperado

### Niveles de fidelidad

Las personas se construyen solo a partir de fuentes públicas (manuales de los
fabricantes, avisos de CVE y de fabricantes, firmas de los informes de
exposición) y de marcado original, nunca de firmware capturado. Por eso la
fidelidad varía según cuánto está documentado públicamente:

- `danfoss`, `dixell`, `carel`, `eliwell` — buena: la cabecera del servidor, el
  flujo de autenticación, las credenciales por defecto y las rutas clave están
  todos documentados públicamente.
- `rdm` — media: el valor por defecto `1234` y el login CGI están documentados,
  pero la cabecera Server exacta y los bytes de la página no, así que el
  marcado es sencillo y la cabecera se deja a `SERVER_HEADER`.
- `aksc355` — superficial: anclada solo a la banda de firmware y al flujo
  Forgot-Credentials.

Cuando un detalle del dispositivo real no se puede citar, queda configurable y
vacío en lugar de adivinado, porque una huella equivocada delata más que una
ausente. Para un despliegue que te importe, captura las páginas de una unidad
real y define `SERVER_HEADER` con el valor que observes.

## Qué responde cada persona

Común a las seis:

- La página inicial se sirve en `/` y `/index.html`, solo a `GET` y `HEAD`.
  Cualquier otro método recibe el rechazo propio del servidor: 405, o 501 en
  `carel`.
- Las rutas desconocidas reciben la página 404 de la persona; una petición mal
  formada su página 400; un cuerpo de más de 8 KiB su página 413 (400 en
  `carel`).
- Un login por formulario o API que "tiene éxito" entrega un token de sesión
  válido durante una hora, y su respuesta se retrasa entre 0,6 y 1,4 segundos,
  porque una unidad real tarda un momento. `carel` usa en cambio HTTP Basic
  auth: sin token y sin retraso.
- Cada petición, login, comando e intento de exploit se registra (ver "Leer el
  log").

**`danfoss`** (cabeceras al estilo nginx, keep-alive en la página de login)
- `POST /html/xml.cgi` (también `/xml.cgi`) acepta un `<cmd action="…"/>` XML;
  `OPTIONS` responde 204 y cualquier otro método 405.
- `getauth` inicia sesión y devuelve un token de sesión, que se reenvía en la
  cabecera `AKSM-Auth`. También funcionan las credenciales pasadas directamente
  en otro comando.
- `read_date_time` responde sin sesión, en la zona horaria del dispositivo.
- `read_units` devuelve el nombre de la tienda, el firmware y la MAC;
  `read_devices` los ocho muebles con temperatura, consigna y estado de
  desescarche.
- Cualquier otra acción desde una sesión se registra como `control`. Una cuyo
  nombre contenga `defrost`, con `node` de `"1"` a `"8"`, inicia el desescarche
  simulado.
- En un navegador, un login con éxito sustituye el formulario por una tabla de
  los ocho muebles con un botón Defrost en cada fila. La página usa los mismos
  comandos XML, así que un clic se registra exactamente igual que un comando
  de un script.
- Logins que tienen éxito: `Supervisor`/`12345`, `superviseur`/`12345`,
  `admin`/`admin`, `admin`/`1234` (nombre de usuario en cualquier combinación
  de mayúsculas y minúsculas), o el code of the day con `eds_only` o
  `quantum_only`.

**`dixell`**
- `POST /cgi-bin/login.lua` (también `/login`) acepta los campos `username`,
  `password` y `auth_mode`. Cinco fallos desde un mismo origen sobre un mismo
  nombre de usuario bloquean ese par durante 300 segundos.
- `POST /cgi-bin/datachart.cgi` con `SSES=<token>` devuelve las temperaturas de
  los muebles; sin una sesión válida devuelve la página de login.
- `POST /cgi-bin/logo_extra_upload.cgi`, `cal_save.cgi` o `lo_utils.cgi`
  "guarda" una subida: la primera línea es el nombre del fichero y el resto el
  contenido, hasta 8 KiB, solo en memoria. `GET /logo/<nombre>` lo devuelve;
  `GET /cgi-bin/cal_dir.cgi` o `/logo/` lista lo guardado.
- Los scripts y las hojas de estilo que referencia la página responden con un
  200 vacío.
- Logins que tienen éxito: `admin`/`Admin`, `Admin`/`Admin`, `admin`/`admin`.

**`aksc355`**
- `POST /cgi-bin/login.cgi` (también `/login`) acepta `user` o `username`, y
  `password` o `pass`.
- `POST /cgi-bin/reset.cgi` (también `/reset`) es el flujo Forgot-Credentials:
  devuelve la MAC de la unidad y un código de reset aleatorio.
- Logins que tienen éxito: `admin`, `administrator`, `user` o `guest` con
  `danfoss`; `Supervisor`/`12345` (nombre de usuario en cualquier combinación
  de mayúsculas y minúsculas).

**`carel`** (cabeceras de respuesta y páginas de error de thttpd 2.25b; responde en la versión HTTP de la petición)
- La página inicial también se sirve en `/http/index.html`, y los nombres de
  los métodos se comparan sin distinguir mayúsculas de minúsculas.
- Todo lo que cuelga de `/config/` pide HTTP Basic auth, realm `pCOWeb`.
  `/config/pw_changeusers.html` lista en claro las cuentas de fábrica y sus
  contraseñas; cualquier otra ruta de configuración devuelve una página mínima
  con la MAC y la versión.
- Logins que tienen éxito: `httpadmin`/`fhttpadmin`, `admin`/`fadmin`,
  `carel`/`fcarel`, `guest`/`fguest`, `root`/`froot`.

**`eliwell`**
- `POST /login` (también `/j_security_check`) acepta `user`, `username` o
  `j_username`, y `password` o `j_password`.
- `GET /welcome` (también `/version`) devuelve producto, fabricante, versión
  del software y nombre de la planta, sin sesión.
- Logins que tienen éxito: `Administrator` con `0` o con la contraseña vacía.

**`rdm`**
- `POST /cgi-bin/login.cgi` (también `/login`) acepta `user` o `username`, y
  `password`, `pass` o `pin`.
- `/cgi-bin/status.cgi` (también `/status`) devuelve los ocho muebles con
  temperatura, consigna y estado de desescarche, sin sesión, como en una unidad
  con "Force CGI login" desactivado.
- Logins que tienen éxito: contraseña `1234` con el usuario vacío, `admin` o
  `user`.

### HTTPS

`HTTPS_PORT` añade un listener TLS para cualquier persona. Habla solo TLS 1.2,
como las unidades reales, y presenta un certificado hoja firmado por una CA
autofirmada, ambos generados en el propio proceso y con fecha retrasada. Un
handshake fallido o que expira se registra como `tls_error`.

### Modbus TCP

`MODBUS_PORT` añade un listener Modbus TCP para cualquier persona, que responde
a cualquier unit id.

| Registros | Contenido |
|-----------|-----------|
| 0–7       | Temperaturas de los muebles, décimas de °C, con signo, con ruido de sensor |
| 100–107   | Consignas de los muebles, décimas de °C |
| 200–207   | Orden de desescarche: un valor distinto de cero lo inicia, cero lo detiene |

- Los códigos de función 3 y 4 leen, 6 y 16 escriben, y 43/14 devuelve la
  identificación del dispositivo (fabricante, producto, firmware). Cualquier
  otra función recibe la excepción 1, una dirección no mapeada la excepción 2,
  una cantidad no válida la excepción 3.
- Un desescarche sube la temperatura del mueble unos 1,5 °C por minuto durante
  veinte minutos (como máximo +25 °C), luego pone a cero su registro y el
  mueble vuelve a su base en cuarenta y cinco minutos, como haría uno real;
  quien hace polling nunca la ve volver de golpe. Detenerlo antes hace que la
  bajada parta de donde había llegado, y reiniciarlo a mitad de la bajada sigue
  subiendo desde la temperatura actual.
- Ese mismo estado de los muebles es el que `read_devices`, `datachart.cgi` y
  `status.cgi` informan por HTTP.

## Inicio rápido

```
cargo build --release --locked
PERSONA=danfoss HTTP_PORT=8080 ./target/release/fridgep0t
```

Un binario compilado en tu estación de trabajo incrusta tu directorio personal
en las ubicaciones de los panic. Despliega la build de contenedor, que no tiene
esas rutas, o compila con `RUSTFLAGS="--remap-path-prefix=$HOME=~"` (una
entrada `[build] rustflags` en tu `~/.cargo/config.toml` lo hace permanente).

Abre http://localhost:8080 y cada petición aparece como una línea JSON en
stdout y en `events.jsonl`. Ejecuta los tests: tests unitarios para los parsers
y el estado, y una suite de integración que arranca el binario por cada persona
y lo ataca por HTTP, HTTPS y Modbus, incluidos los caminos de timeout, tope de
conexiones y apagado:

```
cargo test --release --locked
```

La CI ejecuta build, test, clippy y fmt en stable, build y test en la versión
mínima de Rust soportada (1.75), y `cargo audit` sobre las dependencias fijadas.
Se ejecuta además cada semana, y sus actions están fijadas por SHA de commit.

`SIGTERM` o Ctrl-C detienen el señuelo; antes escribe los eventos de log que
quedan en cola, durante dos segundos como máximo.

## Despliegue

**Contenedor.** El `Containerfile` compila el binario y lo distribuye sobre
distroless `nonroot`, escuchando en 8080 (HTTP) y 8443 (HTTPS), con el log en
`/logs/events.jsonl` y el certificado conservado en `/logs/tls`:

```
podman build -t fridgep0t .
podman run -d --name fridgep0t --restart=always \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 80:8080 -p 443:8443 -v fridgep0t-logs:/logs:U \
  -e PERSONA=danfoss -e IDENTITY_SEED=<tu-propia-cadena-aleatoria> \
  fridgep0t
```

**Servidor nuevo.** Pega `cloud-init.yaml` en el campo "User data" de un
servidor Ubuntu 24.04 nuevo, después de definir en él `PERSONA`,
`FRIDGEP0T_REPO` y `FRIDGEP0T_REF`. Instala el cortafuegos, compila la imagen
desde el commit que has fijado, genera un `IDENTITY_SEED` aleatorio para ese
host y arranca el contenedor con las opciones de arriba. Ahí solo `danfoss`
recibe el puerto HTTPS. Para exponer Modbus, sigue el comentario del fichero.

## Configuración

| Variable        | Por defecto       | Significado                                          |
|-----------------|-------------------|------------------------------------------------------|
| `PERSONA`       | `danfoss`         | `danfoss`, `dixell`, `aksc355` (o `aksc`), `carel` (`pcoweb`), `eliwell` (`televisgo`), `rdm` (`datamanager`) |
| `BIND`          | `0.0.0.0`         | Dirección en la que escuchar                         |
| `HTTP_PORT`     | `8080`            | Listener HTTP                                        |
| `HTTPS_PORT`    | `0` (apagado)     | Listener HTTPS (certificado generado en el proceso)  |
| `MODBUS_PORT`   | `0` (apagado)     | Listener Modbus TCP                                  |
| `LOG_PATH`      | `events.jsonl`    | Dónde se añaden los eventos                          |
| `DEVICE_TZ`     | `Europe/Rome`     | Zona horaria que informa el reloj del señuelo        |
| `IDENTITY_SEED` | ninguno (aleatorio) | Semilla fija para una identidad estable por despliegue |
| `TLS_DIR`       | ninguno (nuevo en cada arranque) | Directorio que conserva el certificado generado entre reinicios (`/logs/tls` en la imagen de contenedor) |
| `STORE_NAME`    | generado          | Sustituye el nombre de tienda generado               |
| `STORE_LANG`    | según `DEVICE_TZ` | Idioma del rótulo generado: `it`, `de`, `fr`, `es`, `nl`, `en` |
| `FIRMWARE`      | generado          | Sustituye la cadena de firmware generada             |
| `MAC_OUI`       | por persona (IEEE) | Sustituye el OUI del fabricante (`xx:xx:xx`) en la MAC generada |
| `SERVER_HEADER` | valor de la persona | Sustituye la cabecera Server de cualquier persona (ver Niveles de fidelidad) |

## Leer el log

El log rota a los 256 MB, conservando de `events.jsonl.1` a `events.jsonl.4`.
`summary.py` convierte un log en un informe breve:

```
python3 -I summary.py --hours 24 --ignore <tu-propia-ip> < events.jsonl
```

Imprime los totales (eventos, orígenes, logins intentados y aceptados, intentos
de exploit, orígenes Modbus, escrituras de control, intentos de desescarche),
los huecos que haya en el log, los principales exploits, IP, credenciales y
rutas, y una línea por cada intento de desescarche.

Cada evento es un objeto JSON con `ts` (UTC), `persona`, `proto` (`http`,
`https`, `modbus`, `tcp` o `system`), `src_ip`, `src_port` y `event`, más los
campos propios de ese evento. Los campos aportados por el atacante se cortan a
512 caracteres y la línea a 8 KiB (`"truncated": true` marca una línea cortada
más a fondo).

| Evento | Se registra cuando | Campos principales |
|--------|--------------------|--------------------|
| `start` | El señuelo arranca | puertos, nombre de tienda, hostname, MAC, firmware, zona horaria |
| `request` | Cualquier petición HTTP bien formada | `method`, `path`, `host`, `user_agent`, `authorization`, `body`, `exploit` |
| `bad_request` | Se rechaza una petición (mal formada, demasiado grande, cortada) | `raw`, `exploit` |
| `login_attempt` | Cualquier login, en cualquier persona | `username`, `password`, `granted`; `locked`, `auth_mode`, `exploit` en `dixell` |
| `xml_cmd` | Un comando XML de `danfoss` | `action`, `attrs`, `auth_header`, `session`, `exploit` |
| `control` | El atacante actúa: un comando, una subida, una divulgación de credenciales o de la MAC | `action`; `node`, `defrost`, `path`, `stored_as`, `exploit` |
| `datachart` | Una petición de datos de `dixell` | `session`, `request` |
| `connect`, `read`, `write`, `device_id` | Tráfico Modbus | `unit`, `fc`, `start`, `count` o `values`, `defrost` |
| `unsupported`, `malformed` | Una función Modbus a la que no respondemos, o una trama no válida | `pdu_hex` o `header_hex` |
| `tls_error` | Un handshake TLS falla o expira | `error` |
| `conn_refused` | Un origen supera su tope de conexiones (como máximo una vez por minuto y origen) | |
| `log_suppressed` | Un origen alcanza su tope de eventos por minuto | `class`, `per_minute` |
| `log_dropped` | La cola del log estaba llena | `count` |

## Seguridad

- Nunca ejecuta comandos, lee ficheros ni reenvía tráfico. Los payloads de los
  exploits se registran y se descartan; los ficheros "subidos" viven en un mapa
  en memoria con tope.
- Los cuerpos de las peticiones, los campos registrados y las conexiones tienen
  tope, incluido un límite por origen para que un atacante no desplace a los
  demás. Los sockets inactivos expiran; cualquier conexión se corta a los 30
  segundos, por muy despacio que llegue.
- El HTTP se analiza de forma estricta: solo HTTP/1.0 y 1.1, líneas de cabecera
  bien formadas, exactamente un `Host` en HTTP/1.1, un `Content-Length`
  numérico que coincide entre repeticiones y cabe en el tope del cuerpo, sin
  `Transfer-Encoding`. Todo lo ambiguo se registra como `bad_request`, recibe
  la página de error 400 (o 413) de la persona y se cierra la conexión, de modo
  que un cuerpo nunca puede leerse como la petición siguiente.
- Las líneas de log demasiado largas se truncan; `summary.py` neutraliza los
  códigos de escape de terminal presentes en la entrada del atacante.
- El log nunca bloquea una conexión: un hilo de escritura vacía una cola
  limitada; si la cola se llena, los eventos más recientes se descartan y un
  evento `log_dropped` informa de cuántos. El apagado espera como máximo dos
  segundos a que el hilo termine de escribir.
- Un origen no puede expulsar los eventos de los demás del log, que está
  limitado en tamaño: cada IP de origen puede registrar 600 eventos por minuto,
  contados por separado para los eventos rutinarios y para logins y comandos,
  de modo que una ráfaga de peticiones no puede enterrar el comando que la
  sigue. Pasado el tope se escribe un único evento `log_suppressed`, y luego
  nada hasta que termina el minuto. `summary.py` informa de ambos tipos de
  hueco.
- Los campos del log están controlados por el atacante. Trátalos como no
  fiables cuando los proceses.

Los límites están fijados en el código, no son configurables, porque son la red
de seguridad:

| Límite | Valor |
|--------|-------|
| Cuerpo de la petición | 8 KiB |
| Cabeceras de la petición | 16 KiB |
| Campo registrado / línea de log | 512 caracteres / 8 KiB |
| Conexiones, totales / por IP de origen | 256 / 16 |
| Timeout del socket inactivo / conexión completa | 15 s / 30 s |
| Tokens de sesión | 1 hora cada uno, como máximo 1000 (se descarta el más antiguo) |
| Subidas `dixell` guardadas | 8 KiB cada una, en memoria, vaciadas al pasar de 256 ficheros |
| Fichero de log | 256 MB, más 4 ficheros rotados |
| Cola del log | 4096 eventos |
| Eventos por IP de origen y minuto | 600 rutinarios + 600 entre logins y comandos |

## Limitaciones

- Interacción superficial: un atacante autenticado dispone de un puñado de
  comandos por API, no de la aplicación completa. Solo `danfoss` muestra algo
  en el navegador después del login: una tabla de los ocho muebles.
- El código público se puede reconocer. La identidad generada ayuda, pero
  cambia el marcado de la persona para un despliegue que te importe.
- Las IP de nube resultan sospechosas. Algunos escáneres marcan los
  dispositivos industriales alojados en la nube como probables honeypots; una
  dirección que no sea de nube es más convincente.

## Pendiente

Trabajo abierto, más o menos por orden de prioridad. Consulta FINGERPRINTS.md
para ver el estado actual, con sus fuentes, de cada persona.

Huellas de primera mano (hace falta una cuenta de Shodan/Censys):
- Ejecuta `http.title:"TelevisGo"` y `http.title:"Data Manager"` y captura,
  para cada uno, la cabecera `Server`, el `http.favicon.hash` y un banner en
  bruto. Define la cabecera con `SERVER_HEADER`, haz coincidir el favicon (ver
  abajo) y regístralos en FINGERPRINTS.md como de primera mano. Esto sube
  `eliwell` y `rdm` al nivel bueno.
- Verifica la cabecera Server de `aksc355` en una unidad real; define
  `SERVER_HEADER` si envía alguna.
- Captura una segunda unidad `dixell`: el bloque de cabeceras, la banda de
  firmware y el contenido de la página se apoyan en una sola XWEB 500 EVO
  observada.
- Favicon: servir un favicon cuyo hash sea igual al `http.favicon.hash` de la
  unidad real. Es una de las huellas más fuertes de Shodan y hoy no definimos
  ninguno.

Cobertura de exploits:
- Generalizar la capa de respuesta a exploits invirtiendo las plantillas
  públicas de Nuclei (el enfoque funnypot), para que el señuelo devuelva
  respuestas exactas al byte para muchos CVE de ICS, no solo para los escritos
  a mano. Es autónomo; no necesita Shodan.

Deuda de fidelidad y honestidad:
- Capturar páginas de referencia reales para las personas superficiales y
  medias (`aksc355`, `rdm`) y sustituir el marcado provisional; fijar las
  longitudes exactas en bytes de las páginas.
- Verificar de forma independiente los dos CVE de Danfoss sin fuente
  (CVE-2023-25914, CVE-2023-25915) o reetiquetarlos en la persona `danfoss` y
  en FINGERPRINTS.md.

Endurecimiento del despliegue:
- Fijar `FRIDGEP0T_REF` a un commit revisado en cloud-init.yaml; actualizar los
  digests de las imágenes base en el Containerfile cuando las cambies.
- Desplegar en una IP que no sea de nube; los rangos de nube se marcan como
  probables honeypots.

Opcional, de menor valor:
- Añadir `aksm800` (AK-SM 800 legacy, página Flash-loader) y `aksc255` como
  variantes ligeras, si hace falta cubrir exactamente esos modelos. Ambas
  serían superficiales sin páginas de referencia reales.
- Añadir una comprobación en CI que haga cumplir FINGERPRINTS.md frente al
  código (hoy `tests/attack.rs` hace cumplir el comportamiento, no el
  documento).

## Agradecimientos

Gracias a [Nik0l4](https://github.com/nic0ladibari) por la ayuda con el
fingerprint de Danfoss (página de login, banda de firmware y el algoritmo del
code of the day).

## Licencia

BSD-4-Clause. El uso y la modificación son libres, pero cualquier publicación,
informe, presentación u otro material que mencione las funciones o el uso de
este software debe reconocer al titular del copyright (cláusula 3 de
`LICENSE`), y los avisos deben acompañar a las copias. `CITATION.cff` ofrece
una cita ya preparada.
