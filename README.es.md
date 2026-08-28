# ByteTrawl 1.1.1

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [Português (Brasil)](README.pt-BR.md) · **Español** · [Deutsch](README.de.md)

[![Versión](https://img.shields.io/badge/version-1.1.1-9acf68?style=flat-square)](https://github.com/everettjf/homebrew-tap/releases/tag/bytetrawl-v1.1.1)
[![macOS](https://img.shields.io/badge/macOS-13%2B-d69b51?style=flat-square)](#requisitos)
[![Licencia](https://img.shields.io/badge/license-Apache--2.0-d7d3c6?style=flat-square)](LICENSE)

ByteTrawl es un banco de trabajo multiplataforma, escrito en Rust, para el triaje estático seguro, la comparación y la auditoría de publicación de artefactos de software. Modela aplicaciones, directorios, paquetes y archivos como Artifacts para inspeccionar su estructura, metadatos, firmas, dependencias y binarios PE, Mach-O y ELF sin ejecutar el contenido analizado.

**Versión actual:** [ByteTrawl 1.1.1](https://github.com/everettjf/homebrew-tap/releases/tag/bytetrawl-v1.1.1) para Mac con Apple silicon. El [README en inglés](README.md#detailed-support-matrix) es la fuente canónica y contiene la matriz de soporte más detallada y actual.

## Capturas

[![ByteTrawl inspeccionando GrapeCompare.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/bytetrawl/#gallery)

La [galería interactiva](https://xnu.app/bytetrawl/#gallery) alterna entre estructura, Mach-O, dependencias, strings y la inspección Hex acotada.

## Instalación con Homebrew

```sh
brew tap everettjf/tap
brew install --cask bytetrawl
brew install bytetrawl-cli
```

La aplicación para macOS está firmada con Developer ID, notarizada por Apple y lleva adjunto el ticket de notarización. Cada release supera la verificación estricta de firma, la validación del ticket y la evaluación de Gatekeeper.

## Capacidades principales

| Área | Soporte actual |
|---|---|
| macOS e iOS | `.app`, bundles, frameworks, plug-ins, Mach-O universal, DMG y PKG/XAR; auditoría IPA de identidad, tamaño, targets, arquitecturas, localizaciones, privacidad, provisioning, entitlements y findings |
| Android | Manifest de APK, paquete/versión/SDK, permisos, componentes exportados, deep links, estadísticas DEX, ABI, bibliotecas nativas, indicadores de firma y findings |
| Windows | Headers, secciones, imports/exports, símbolos, dependencias y Authenticode de PE/COFF; identidad, capabilities, entry points, block map y firma de APPX/MSIX |
| Linux | Headers, arquitectura, interpreter, secciones, segmentos, relocations, símbolos, dependencias y findings de ELF; control, payload, tamaño instalado, scripts y archivos privilegiados de DEB |
| Contenedores y datos | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, imágenes y texto; 7z, RAR y streams comprimidos tienen identificación básica |
| Análisis común | Artifact Tree, metadata, headers, slices, sections, segments, imports, exports, symbols, relocations, grafo de dependencias, strings, Hex bajo demanda, hashes, entropía, firma y findings |
| Comparación y CI | Identidad SHA-256; altas, bajas, cambios, movimientos, crecimiento y duplicados; JSON, Markdown, HTML, SARIF, políticas, severity gates y códigos de salida estables |

Consulta la [matriz completa en inglés](README.md#detailed-support-matrix), el [schema de informes](docs/report-schema.md) y la [matriz de pruebas automatizadas](docs/testing.md).

## Flujo de escritorio

- Menús nativos de macOS para abrir archivo, carpeta, workspace y una ventana nueva.
- Arrastra un archivo, aplicación, paquete, workspace o directorio al centro de la ventana.
- Artifact Tree, contenido y Details son redimensionables; las tablas grandes usan renderizado virtual.
- **External Tools…** prioriza integraciones compatibles ya instaladas.
- Los workspaces conservan ruta, vista, marcadores, notas y resultados en caché.

Atajos: `⌘N` ventana nueva, `⌘O` archivo, `⇧⌘O` carpeta, `⌥⌘O` workspace, `⌘S` guardar y `⌘F` buscar.

## CLI

```sh
bytetrawl-cli inspect ./SomeApp.app --pretty
bytetrawl-cli inspect ./MyApp.ipa --depth deep --format sarif --output bytetrawl.sarif
bytetrawl-cli inspect ./package --hash sha256 --strings --entropy
```

Las profundidades son `lightweight`, `standard` y `deep`. Los códigos distinguen error fatal (`1`), fallo de policy/finding (`2`), cancelación (`4`) e informe parcial utilizable (`5`).

## Requisitos

- Mac con Apple silicon (`arm64`)
- macOS 13 Ventura o posterior
- Homebrew para los comandos anteriores

El núcleo no depende de GPUI y puede inspeccionar Windows PE y Linux ELF estáticamente desde macOS. El empaquetado y la UI nativos para Windows y Linux llegarán después.

## Límites de seguridad

ByteTrawl es estático y de solo lectura. No ejecuta programas importados, monta imágenes, instala paquetes, extrae archivos automáticamente, descompila, depura ni modifica bytes. No sigue enlaces simbólicos y limita explícitamente entradas, recursión, archivos, strings, miembros de archivos y salida de comandos. Los findings heurísticos son indicios, no veredictos de malware.

## Documentación

[Estrategia](docs/product-strategy.md) · [Análisis del producto y competidores](docs/product-analysis-roadmap.md) · [Plan IPAView](docs/ipa-convergence-plan.md) · [Pruebas](docs/testing.md) · [Sitio web](https://xnu.app/bytetrawl/)

El README en inglés es canónico; las traducciones se sincronizan al cambiar la versión, instalación o capacidades principales.
