# snmpapply

Aplica una comunidad de lectura SNMPv2c a una lista de switches **de varios
fabricantes** en una sola corrida. Las credenciales salen de `.env`, los
dispositivos de `inventory.json`, y el fabricante se toma del JSON o se
**autodetecta por SSH**.

Reemplaza los scripts shell/pexpect por fabricante con un único binario Go
multiplataforma (sin Python, sin `sshpass`, sin runtime de `pexpect`).

## Fabricantes soportados

| Fabricante            | Alias                        |
|-----------------------|------------------------------|
| Huawei VRP            | `huawei`, `vrp`              |
| ArubaOS-CX            | `aruba-cx`, `cx`, `aoscx`    |
| ArubaOS WC/ProCurve   | `aruba-wc`, `procurve`, `wc` |
| Ruckus ICX / IronWare | `ruckus`, `icx`, `ironware`  |
| Zyxel ZyNOS           | `zyxel`, `zynos`             |

## Cómo funciona la detección de fabricante

SNMP no sirve para identificar el equipo — todavía no está configurado (ese es
justamente el objetivo). La detección corre sobre la misma sesión SSH que se usa
para configurar:

1. **Banner** — Huawei (prompt `<...>`) y ProCurve ("Press any key") quedan
   resueltos de inmediato.
2. **Sondeo** — para un prompt ambiguo `#`/`>`, se envía `show version` y la
   salida distingue Ruckus de ArubaOS-CX. Zyxel se anuncia en el banner de
   login ("Zyxel Communications"), así que se resuelve sin sondeo.

Define `"vendor"` explícitamente en `inventory.json` para omitir la detección
en un dispositivo.

## Inventario

El binario corre en la propia sonda del sitio, así que el usuario, la contraseña
y la comunidad salen todos de `.env` — el inventario es solo **una lista de IPs**:

```json
[
  "192.0.2.9",
  "192.0.2.10",
  "192.0.2.16"
]
```

Un elemento puede ser un objeto si necesitas una excepción puntual por
dispositivo (fabricante explícito, otra comunidad, un puerto no estándar o un
`password_env`):

```json
[
  "192.0.2.9",
  { "host": "192.0.2.30", "vendor": "ruckus" }
]
```

## Uso

```sh
cp .env.example .env                 # completa SSH_USER, SSH_PASSWORD, SNMP_COMMUNITY
cp inventory.example.json inventory.json   # después lista las IPs del sitio

go run ./cmd/snmpapply -dry-run      # solo escanea, no cambia nada
go run ./cmd/snmpapply               # escanea, confirma y luego configura
```

### Parámetros

| Parámetro          | Por defecto      | Descripción                          |
|--------------------|------------------|--------------------------------------|
| `-inventory`       | `inventory.json` | lista de dispositivos                |
| `-env`             | `.env`           | archivo de credenciales              |
| `-concurrency`     | `10`             | dispositivos en paralelo             |
| `-timeout`         | `90s`            | timeout total por dispositivo        |
| `-connect-timeout` | `8s`             | timeout de conexión SSH (los equipos muertos fallan así de rápido) |
| `-io-timeout`      | `30s`            | timeout de lectura por paso          |
| `-dry-run`         | `false`          | solo detecta el fabricante, sin cambios |
| `-vendor`          | _(vacío)_        | fuerza un fabricante para todos      |
| `-only`            | _(vacío)_        | filtro de hosts separados por coma   |
| `-v`               | `false`          | muestra la sesión SSH en vivo        |
| `-force-zyxel`     | `false`          | aplica también a Zyxel (SOBREESCRIBE su única comunidad) |
| `-no-precheck`     | `false`          | saltea el escaneo SNMP (fase 1); configura todos |
| `-snmp-timeout`    | `2s`             | timeout del escaneo SNMP por dispositivo |
| `-yes`             | `false`          | no preguntar antes de la fase 2      |

## Corrida en dos fases

1. **Fase 1 · Escaneo SNMP** — sondea todo el inventario con un GET SNMPv2c y
   muestra una tabla de qué dispositivos ya tienen la comunidad (`✅ configurado`)
   y cuáles todavía la necesitan (`❌ pendiente`) — ~100 ms cada uno, sin SSH.
2. Un mensaje de confirmación pregunta si configurar los dispositivos pendientes
   (se omite con `-yes`).
3. **Fase 2 · Configurar** — se conecta solo a los dispositivos que la necesitan.
   La salida es mínima: `✅` por cada uno configurado, `⊘` + motivo para un
   omitido, `❌` + motivo para una falla.

```
Fase 1 · Escaneo SNMP — 11 dispositivo(s)
HOST         VENDOR  SNMP
192.0.2.9   -       ✅ configurado
192.0.2.11  -       ❌ pendiente
...
7 configurados · 4 pendientes

¿Configurar los 4 dispositivos pendientes? [s/N]: s

Fase 2 · Configurando 4 dispositivo(s)
  ✅ 192.0.2.16   huawei
  ⊘ 192.0.2.11   omitido: vendor de comunidad única (usa -force-zyxel)
  ❌ 192.0.2.17   handshake ssh ... i/o timeout

7 presentes · 1 configurados · 2 omitidos · 1 con error  (13s)
```

Así una re-corrida solo toca lo que todavía hace falta — ideal después de una
pasada parcial donde algunos dieron timeout o quedaron limitados por tasa.
Re-aplicar es seguro igual: las comunidades se identifican por nombre, así que
la misma nunca se duplica (verificado en Huawei/Aruba reales). Usa
`-no-precheck` para omitir la fase 1 y configurar todo.

## Fabricantes de comunidad única (Zyxel)

Huawei, Aruba (CX/WC) y Ruckus guardan **varias** comunidades de lectura —
aplicar es aditivo, la comunidad existente se mantiene. **Zyxel ZyNOS guarda solo
una**, así que aplicar la *reemplaza* (destructivo). Por eso los dispositivos
Zyxel se **omiten por defecto** (en la fase 2 se muestran como `⊘ omitido`);
usa `-force-zyxel` para sobreescribir la única comunidad a propósito. Verificado
en vivo: una comunidad nueva convive con la vieja en los fabricantes de varias
comunidades (ambas responden SNMP). Nota: aplicar a ArubaOS-CX provoca un corte
breve (~segundos) de SNMP mientras su agente reinicia el `vrf default`.

## Instalación (en la sonda de un sitio)

El binario busca `inventory.json` y `.env` **junto a sí mismo** (y como respaldo
en el directorio actual), así que el armado portable es: una carpeta con el
binario + sus dos archivos de configuración. Sin parámetros — solo `./snmpapply`.

Una línea: descarga a la carpeta actual el binario para tu SO/arquitectura desde
GitHub Releases, verifica su checksum y deja también las plantillas
`.env.example` e `inventory.example.json` como referencia:

```sh
curl -fsSL https://raw.githubusercontent.com/Marioloez/snmpapply/main/install.sh | sh
# copia .env.example a .env e inventory.example.json a inventory.json,
# complétalos y ejecuta:
./snmpapply
```

O descarga el binario correspondiente a mano desde la página de Releases. Windows:
descarga `snmpapply-windows-amd64.exe`.

## Compilación / release (mantenedores)

`./build.sh [versión]` compila los cinco objetivos en `dist/` (stripped,
estático, `-trimpath`) más un `SHA256SUMS`, estampando `-version`:

```sh
./build.sh v1.0.0      # -> dist/snmpapply-<so>-<arch> + SHA256SUMS
./snmpapply -version   # snmpapply v1.0.0
```

Sube los archivos de `dist/` (binarios + `SHA256SUMS`) como assets de un GitHub
Release; `install.sh` los descarga desde ahí.

## Nota sobre SSH heredado

Estos switches hablan SSH de la era 2005. El dialer reactiva
`diffie-hellman-group1-sha1`, `aes128-cbc`, `3des-cbc`, `hmac-sha1` y `ssh-rsa`,
que Go deshabilita por defecto. Algunas de las primitivas más viejas
(`aes256-cbc`, `hmac-md5`) no existen en el stack SSH de Go; la negociación cae a
las soportadas. **Valida contra un equipo real por familia** antes de confiar en
una corrida masiva.

## Arquitectura

```
cmd/snmpapply        entrypoint de la CLI y tabla resumen
internal/config      carga y resolución de .env + inventory.json
internal/transport   transporte SSH PTY + motor expect ("pexpect en Go")
internal/driver      interfaz Driver + estrategias por fabricante
internal/detect      identificación híbrida de fabricante
internal/runner      pool acotado de workers, rutea cada dispositivo a su driver
```

Agregar un fabricante = implementar la interfaz `driver.Driver` y registrarla en
`registry.go`. El orquestador no cambia.
