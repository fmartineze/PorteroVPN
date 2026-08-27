# Portero VPN

Cliente OpenVPN para Windows que exige comprobaciones de seguridad locales
*antes* de dejar establecer la conexion. Interfaz en espanol, ventana compacta
(380x540, tamano fijo) que se minimiza al icono de bandeja.

La razon de ser del proyecto: las comprobaciones que interesan (antivirus activo
segun el Centro de seguridad de Windows) solo son fiables consultadas desde la
sesion del usuario, no desde sesion 0 -- por eso no basta con un script
`--up` de OpenVPN GUI y existe esta aplicacion.

> **Nota sobre la documentacion de diseno.** Los comentarios del codigo citan
> un *plan de arquitectura* por secciones ("plan, seccion 3", "plan, seccion
> 11", "plan, Contexto") en 29 sitios repartidos por 14 ficheros. Ese documento
> **no forma parte de este repositorio**: se quedo fuera al copiar el proyecto
> entre ordenadores el 2026-08-27. Si aparece, este es su sitio.

## Arquitectura

Tres crates en un workspace, con separacion de privilegios como decision
central:

| Crate | Privilegios | Responsabilidad |
| --- | --- | --- |
| `portero-vpn` (raiz) | Usuario normal | GUI (egui/eframe sobre wgpu), motor de comprobaciones, credenciales, dialogo con la management interface de OpenVPN |
| `svc/` -> `portero-vpn-svc` | LocalSystem | Solo lanza y mata `openvpn.exe`, y responde una consulta WMI de BitLocker |
| `svc-ipc/` | -- | Tipos de mensaje compartidos entre los dos anteriores |

El servicio elevado es deliberadamente minimo: no interpreta perfiles `.ovpn`,
no ve credenciales y no decide politica de seguridad. Recibe por un named pipe
(`\\.\pipe\PorteroVPN\ctrl`, JSON por lineas) la ruta y el puerto que la GUI ya
ha elegido, y ejecuta `CreateProcess`. La unica excepcion es `QueryBitLocker`,
que vive ahi porque su namespace WMI esta restringido a Administradores.

### Flujo de una conexion

1. La GUI ejecuta las comprobaciones activas en `policy.toml`. Si alguna
   obligatoria falla (o queda indeterminada), no se arranca nada.
2. Elige un puerto de management libre (25340-25400) y genera un *passfile* de
   un solo uso.
3. Pide a `PorteroVPNSvc` que lance `openvpn.exe --config ... --management ...
   --management-hold --management-query-passwords --management-signal`.
4. Se conecta a `127.0.0.1:<puerto>`, se autentica con el passfile y controla el
   resto (credenciales, estado, log, bytecount) hablando con la management
   interface directamente.
5. Al desconectar: `signal SIGTERM` y, si no responde a tiempo, `StopProfile`
   por el pipe como ultimo recurso. El passfile se borra siempre.

### Modulos que conviene conocer antes de tocar nada

- `src/connection.rs` -- orquestador del flujo completo, reintentos incluidos.
- `src/mgmt/protocol.rs` -- parser de la management interface y maquina de
  estados. Logica pura, cubierta por tests.
- `src/checks/` -- motor de comprobaciones. Anadir una es: implementar `Check`,
  registrarla en `CheckRegistry::new()`, y aparece sola en Configuracion.
- `src/openvpn_install.rs` -- descarga OpenVPN Community, **verifica su firma
  GPG** (resolviendo la subclave que firmo de verdad) y lo instala via MSI.
- `src/gpu_fallback.rs` -- si no hay ningun backend grafico utilizable, relanza
  el proceso con Vulkan por software (Lavapipe).

Los comentarios del codigo documentan el incidente real que motivo cada
constante y cada espera rara. Merece la pena leerlos antes de "simplificar"
algo que parezca arbitrario.

## Requisitos

- Windows 10 o superior, x64.
- Rust estable (probado con 1.96.0) con el toolchain MSVC.
- Para empaquetar: [Inno Setup 6](https://jrsoftware.org/isdl.php).
- En tiempo de ejecucion: OpenVPN Community. No hace falta instalarlo a mano --
  la propia app lo detecta y ofrece descargarlo e instalarlo desde la pantalla
  de Conexiones.

## Compilar y probar

```powershell
cargo build --release --workspace   # OJO: --workspace es obligatorio, ver abajo
cargo test  --workspace
cargo clippy --workspace --all-targets
```

**`cargo build --release` a secas NO sirve.** El paquete raiz es el unico
`default-member` del workspace, asi que sin `--workspace` no se genera
`target\release\portero-vpn-svc.exe` y el instalador fallara al no encontrarlo.

Algunos tests estan marcados `#[ignore]` porque dependen de red real
(build.openvpn.net, keys.openpgp.org), del antivirus real de la maquina o de
que `PorteroVPNSvc` este corriendo. Para ejecutarlos a mano:

```powershell
cargo test -- --ignored --nocapture
```

## Empaquetado

1. Genera los dos ejecutables de release:

   ```powershell
   cargo build --release --workspace
   ```

2. Compila el instalador desde la carpeta `installer\`:

   ```powershell
   & "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" portero-vpn.iss
   ```

El resultado queda en `installer\output\PorteroVPN-Setup.exe` (fuera del control
de versiones). El instalador pide administrador una sola vez, copia los dos
`.exe` mas el Lavapipe empaquetado, y registra y arranca `PorteroVPNSvc`.

La firma de codigo esta pendiente: SmartScreen avisara hasta que se firme.

### Sobre `assets/lavapipe/`

`vulkan_lvp.dll` (56 MB) es el ICD de Vulkan por software que el instalador
copia junto al ejecutable. Esta versionado a proposito, porque cargo no lo puede
recuperar y sin el se pierde la red de seguridad para equipos sin ningun backend
grafico (visto en una VM Win11 sobre Proxmox). Si algun dia se sube a un remoto
tipo GitHub, conviene pasarlo a Git LFS.

## Datos en tiempo de ejecucion

Todo vive en `C:\ProgramData\PorteroVPN\`, fuera del repositorio:

| Ruta | Contenido |
| --- | --- |
| `profiles\<uuid>.ovpn` | Copia propia del perfil importado (el original no se toca) |
| `profiles\<uuid>.meta.toml` | Metadatos + credenciales cifradas con DPAPI, si el usuario las guardo |
| `policy.toml` | Que comprobaciones estan activas y son obligatorias |
| `preferences.toml` | Preferencias generales de la app |
| `config-password.hash` | Hash Argon2id (formato PHC) de la contrasena de Configuracion |
| `logs\` | Log tecnico de la app y del servicio, rotacion diaria, 10 ficheros |
| `logs\connections\` | Un log por intento de conexion, se conservan los 10 ultimos |
| `run\` | Passfiles temporales de la management interface |

La app repara en cada arranque los permisos de `BUILTIN\Users` sobre ese arbol
(`icacls`), porque un unico arranque como Administrador bastaba para dejarla
inutilizable en el siguiente arranque normal.

## Seguridad

- La GUI **nunca** corre elevada. Solo se pide UAC para acciones puntuales y
  explicitas: instalar/reinstalar/quitar el servicio, y ejecutar el MSI de
  OpenVPN.
- Credenciales VPN: DPAPI ligado al usuario de Windows (sin
  `CRYPTPROTECT_LOCAL_MACHINE`), con entropia adicional propia de la app. Nunca
  en claro en disco, y el guardado es opt-in por perfil.
- Contrasena de Configuracion: Argon2id con sal por hash.
- La management interface se protege con un passfile de un solo uso, para que
  ningun otro proceso local pueda tomar el control de la conexion.
- El pipe de control concede acceso a usuarios autenticados (SDDL
  `D:(A;;GA;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)`), aceptable porque las unicas
  operaciones que ofrece son arrancar y parar `openvpn.exe`.

## Licencia

Portero VPN se distribuye bajo la **Licencia Apache 2.0** (ver `LICENSE` y
`NOTICE`).

`openvpn.exe` esta bajo GPLv2, pero **no se enlaza ni se redistribuye**: se
ejecuta como proceso independiente y se habla con el por linea de comandos y
por su management interface. Esa separacion es deliberada y es la base para que
las obligaciones de la GPLv2 no alcancen a este codigo — no la revierta nadie
sin revisar antes las implicaciones. El detalle completo, junto con el reparto
de licencias de las 391 dependencias (todas permisivas) y el Lavapipe que si se
empaqueta, esta en `THIRD_PARTY_NOTICES.md`.

## Limitaciones conocidas

- Una sola conexion activa a la vez.
- El volumen de arranque se asume `C:` en la consulta de BitLocker.
- `BitLockerVolumeStatus::Unavailable` (tipico en Windows Home, donde BitLocker
  no existe) se trata como fallo, asi que activar esa comprobacion en un equipo
  Home bloquea la conexion sin salida posible para el usuario.
- `vendor/egui-wgpu-0.29.1` es una copia local parcheada de egui-wgpu 0.29.1
  (reintenta con `force_fallback_adapter: true`). Al subir de version de
  eframe/egui hay que revisar si el parche sigue haciendo falta.
