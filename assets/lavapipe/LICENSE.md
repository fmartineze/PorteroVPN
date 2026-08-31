# Mesa 3D — Lavapipe

Este directorio contiene software de terceros que **Portero VPN redistribuye**
dentro de su instalador, a diferencia de OpenVPN y WireGuard, que solo se
invocan. Por eso su aviso de licencia viaja aquí, junto al binario.

## Qué se redistribuye

| | |
| --- | --- |
| Fichero | `vulkan_lvp.dll` (53,6 MB) y su manifiesto ICD `lvp_icd.x86_64.json` |
| Qué es | Lavapipe, el driver Vulkan por software de Mesa 3D |
| Versión | **26.2.0** |
| Identificado en | El recurso de versión del propio DLL: `ProductName: Mesa3D`, `ProductVersion: 26.2.0.0`, `CompanyName: Mesa/X.org` |
| Para qué | Último recurso en equipos sin ningún backend gráfico utilizable, ni GPU ni WARP (ver `src/gpu_fallback.rs`) |

## Licencia

Según la documentación oficial de Mesa
(<https://docs.mesa3d.org/license.html>):

> The core Mesa library is licensed according to the terms of the MIT license.
> Most of the Mesa code is licensed under MIT license, but individual files may
> have their own licenses. You may find all the licenses used within this
> project in the `licenses/` directory.

Texto de la licencia MIT, que es la del núcleo de Mesa:

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

Mesa es obra de muchos autores y cada fichero lleva su propio aviso de copyright
y su identificador SPDX. Los avisos por componente son los del directorio
`licenses/` de la distribución de Mesa de la que salió este binario.

## Pendiente

**No consta de dónde se obtuvo este `vulkan_lvp.dll`.** El binario se
incorporó al repositorio sin registrar su procedencia, y ni el fichero ni el
historial de git lo dicen.

Para cerrar esto del todo hacen falta dos cosas, y las dos dependen de saber esa
procedencia:

1. Anotar aquí el origen exacto (proyecto, URL y build) del que se descargó o
   con el que se compiló.
2. Copiar junto a este fichero el directorio `licenses/` que acompaña a esa
   distribución, que es donde estan los avisos de copyright concretos de cada
   componente. Este documento reproduce los terminos MIT del nucleo, pero los
   avisos por componente solo pueden salir de la distribucion original.

Mientras tanto, este aviso acompaña al binario y recoge lo que se ha podido
verificar del propio fichero y de la documentación oficial de Mesa.
