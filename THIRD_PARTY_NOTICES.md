# Avisos de software de terceros

Portero VPN (Copyright 2026 Portero VPN) se distribuye bajo la Licencia Apache
2.0 — ver `LICENSE`. Este documento recoge el software de terceros que el
producto utiliza, con la distincion que de verdad importa a efectos de
licencia: **qué se redistribuye dentro del instalador** y **qué solo se invoca
como programa externo ya instalado en la maquina**.

Generado el 2026-08-27 a partir de `cargo metadata` sobre el arbol de
dependencias real (objetivo `x86_64-pc-windows-msvc`). Conviene regenerarlo al
subir versiones de dependencias.

---

## 1. OpenVPN Community — invocado, NO redistribuido

`openvpn.exe` esta bajo **GPLv2**. Portero VPN **no lo enlaza, no lo incluye en
su instalador y no distribuye copia alguna de el**: lo ejecuta como proceso
independiente mediante `CreateProcess` y se comunica con el por dos canales
externos y documentados — sus argumentos de linea de comandos y su *management
interface* sobre un socket TCP local (ver `svc/src/main.rs::start_openvpn` y
`src/mgmt/`).

Esa separacion en procesos distintos es la base para que las obligaciones de la
GPLv2 no alcancen al codigo de Portero VPN. Es una decision de diseño
deliberada, no una consecuencia accidental de la implementacion, y **no debe
revertirse sin revisar antes sus implicaciones legales**: enlazar contra
codigo de OpenVPN, o empaquetar `openvpn.exe` dentro del instalador, cambiaria
el analisis por completo.

El usuario instala OpenVPN Community por su cuenta. La app puede ayudarle
(`src/openvpn_install.rs`) descargando el instalador MSI oficial desde
`build.openvpn.net`, verificando su firma GPG y lanzandolo — pero lo que se
descarga viene de los servidores de OpenVPN, no de este proyecto.

- Proyecto: https://openvpn.net/community/
- Licencia: GPL-2.0-only

## 2. Mesa 3D / Lavapipe — redistribuido en el instalador

`assets/lavapipe/vulkan_lvp.dll` (56 MB) y su manifiesto ICD
`lvp_icd.x86_64.json` **si se incluyen en el instalador** (ver
`installer/portero-vpn.iss`), como ultimo recurso para equipos sin ningun
backend grafico utilizable (ver `src/gpu_fallback.rs`). Es el driver Vulkan por
software de Mesa 3D.

Mesa 3D se distribuye bajo licencia **MIT**, con componentes adicionales bajo
otras licencias permisivas.

> **Pendiente:** el texto de licencia de Mesa no viaja junto al binario en
> `assets/lavapipe/`. Antes de una distribucion publica hay que añadir ahi el
> `LICENSE` correspondiente a la build concreta de Lavapipe que se empaqueta, y
> dejar constancia de su version y procedencia.

- Proyecto: https://www.mesa3d.org/
- Licencia: MIT (y otras permisivas para componentes concretos)

## 3. Dependencias Rust — enlazadas estaticamente

391 crates externos entran en los binarios de Portero VPN. **Todos tienen
licencia permisiva**; no hay ninguna dependencia bajo GPL, LGPL, AGPL ni MPL en
el arbol.

Reparto por licencia declarada:

| Crates | Licencia |
| ---: | --- |
| 212 | MIT OR Apache-2.0 |
| 49 | MIT |
| 43 | Apache-2.0 OR MIT |
| 18 | Unicode-3.0 |
| 14 | MIT/Apache-2.0 |
| 12 | Apache-2.0 |
| 6 | Unlicense OR MIT |
| 5 | BSD-3-Clause |
| 4 | MIT OR Apache-2.0 OR Zlib |
| 3 | ISC |
| 3 | Apache-2.0/MIT |
| 2 | Zlib |
| 2 | Zlib OR Apache-2.0 OR MIT |
| 2 | BSL-1.0 |
| 2 | BSD-3-Clause OR Apache-2.0 |
| 2 | BSD-3-Clause OR MIT OR Apache-2.0 |
| 1 | 0BSD OR MIT OR Apache-2.0 |
| 1 | Apache-2.0 AND MIT |
| 1 | Apache-2.0 AND ISC |
| 1 | Apache-2.0 OR ISC OR MIT |
| 1 | Apache-2.0 / MIT |
| 1 | BSD-2-Clause OR Apache-2.0 OR MIT |
| 1 | (MIT OR Apache-2.0) AND OFL-1.1 AND LicenseRef-UFL-1.0 |
| 1 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| 1 | MIT OR Zlib OR Apache-2.0 |
| 1 | CC0-1.0 |
| 1 | CDLA-Permissive-2.0 |
| 1 | bzip2-1.0.6 |

### Dependencias directas

| Crate | Version | Licencia |
| --- | --- | --- |
| `anyhow` | 1.0.104 | MIT OR Apache-2.0 |
| `argon2` | 0.5.3 | MIT OR Apache-2.0 |
| `async-trait` | 0.1.92 | MIT OR Apache-2.0 |
| `chrono` | 0.4.45 | MIT OR Apache-2.0 |
| `eframe` | 0.29.1 | MIT OR Apache-2.0 |
| `egui` | 0.29.1 | MIT OR Apache-2.0 |
| `ico` | 0.5.0 | MIT |
| `password-hash` | 0.5.0 | MIT OR Apache-2.0 |
| `pgp` | 0.20.0 | MIT OR Apache-2.0 |
| `pollster` | 1.0.1 | Apache-2.0/MIT |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 |
| `raw-window-handle` | 0.6.2 | MIT OR Apache-2.0 OR Zlib |
| `rfd` | 0.15.4 | MIT |
| `serde` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 |
| `tokio` | 1.53.1 | MIT |
| `toml` | 0.8.2 | MIT OR Apache-2.0 |
| `tracing` | 0.1.44 | MIT |
| `tracing-appender` | 0.2.5 | MIT |
| `tracing-subscriber` | 0.3.23 | MIT |
| `tray-icon` | 0.24.2 | MIT OR Apache-2.0 |
| `ureq` | 3.4.0 | MIT OR Apache-2.0 |
| `uuid` | 1.25.0 | Apache-2.0 OR MIT |
| `windows` | 0.58.0 | MIT OR Apache-2.0 |
| `windows-service` | 0.7.0 | MIT OR Apache-2.0 |
| `winresource` | 0.1.31 | MIT |
| `wmi` | 0.14.5 | MIT OR Apache-2.0 |

### Copia local parcheada

`vendor/egui-wgpu-0.29.1/` es una copia de `egui-wgpu` 0.29.1 (MIT OR
Apache-2.0) modificada para reintentar la peticion de adaptador wgpu con
`force_fallback_adapter: true`. Conserva su licencia original; el fichero
`vendor/egui-wgpu-0.29.1/README.md` y su `Cargo.toml` mantienen la autoria
upstream. Ver el comentario de `[patch.crates-io]` en `Cargo.toml` raiz.

---

## Como regenerar el reparto de licencias

```powershell
cargo metadata --format-version 1 --filter-platform x86_64-pc-windows-msvc
```

El campo `license` de cada paquete es lo que se ha agregado en las tablas de
arriba. Para un informe mas formal (con textos de licencia completos por crate)
existen herramientas como `cargo-about` o `cargo-deny`, no usadas todavia en
este proyecto.
