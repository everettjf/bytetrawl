# ByteTrawl

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · **Português (Brasil)** · [Español](README.es.md) · [Deutsch](README.de.md)

[![macOS](https://img.shields.io/badge/macOS-13%2B-d69b51?style=flat-square)](#requisitos)
[![Licença](https://img.shields.io/badge/license-Apache--2.0-d7d3c6?style=flat-square)](LICENSE)

ByteTrawl é uma bancada multiplataforma, escrita em Rust, para triagem estática segura, comparação e auditoria de lançamento de artefatos de software. Aplicativos, diretórios, pacotes e arquivos são tratados como Artifacts, permitindo inspecionar estrutura, metadados, assinaturas, dependências e binários PE, Mach-O e ELF sem executar o conteúdo analisado.

O [README em inglês](README.md#detailed-support-matrix) é a fonte canônica e contém a matriz de suporte mais detalhada e atual. Instale a versão mais recente com os comandos Homebrew abaixo ou obtenha os arquivos no [GitHub Releases](https://github.com/everettjf/homebrew-tap/releases).

## Capturas de tela

[![ByteTrawl inspecionando GrapeCompare.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/bytetrawl/#gallery)

A [galeria interativa](https://xnu.app/bytetrawl/#gallery) alterna entre estrutura do aplicativo, Mach-O, dependências, strings e inspeção Hex limitada.

## Instalação com Homebrew

```sh
brew tap everettjf/tap
brew install --cask bytetrawl
brew install bytetrawl-cli
```

O aplicativo macOS é assinado com Developer ID, notarizado pela Apple e distribuído com o ticket anexado. Cada release passa por verificação estrita da assinatura, validação do ticket e avaliação do Gatekeeper.

## Principais recursos

| Área | Suporte atual |
|---|---|
| macOS e iOS | `.app`, bundles, frameworks, plug-ins, Mach-O universal, DMG e PKG/XAR; auditoria IPA de identidade, tamanho, targets, arquiteturas, localizações, privacidade, provisioning, entitlements e findings |
| Android | Manifest de APK, pacote/versão/SDK, permissões, componentes exportados, deep links, estatísticas DEX, ABIs, bibliotecas nativas, indicadores de assinatura e findings |
| Windows | Headers, seções, imports/exports, símbolos, dependências e Authenticode de PE/COFF; identidade, capabilities, entradas, block map e assinatura de APPX/MSIX |
| Linux | Headers, arquitetura, interpreter, seções, segmentos, relocations, símbolos, dependências e findings de ELF; control, payload, tamanho instalado, scripts e arquivos privilegiados de DEB |
| Contêineres e dados | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, imagens e texto; 7z, RAR e streams compactados possuem identificação básica |
| Análise comum | Artifact Tree, metadata, headers, slices, sections, segments, imports, exports, symbols, relocations, grafo de dependências, strings, Hex sob demanda, hashes, entropia, assinatura e findings |
| Comparação e CI | Identidade SHA-256; arquivos adicionados, removidos, alterados e movidos, crescimento e duplicatas; JSON, Markdown, HTML, SARIF, políticas, severity gates e códigos de saída estáveis |

Consulte a [matriz completa em inglês](README.md#detailed-support-matrix), o [schema de relatórios](docs/report-schema.md) e a [matriz de testes automatizados](docs/testing.md).

## Fluxo no desktop

- Menus nativos do macOS para abrir arquivo, pasta, workspace e nova janela.
- Arraste arquivo, aplicativo, pacote, workspace ou pasta para o centro da janela.
- Artifact Tree, conteúdo e Details são redimensionáveis; tabelas grandes usam renderização virtual.
- **External Tools…** prioriza integrações compatíveis já instaladas.
- Workspaces preservam caminho, visão atual, favoritos, notas e resultados em cache.

Atalhos: `⌘N` nova janela, `⌘O` arquivo, `⇧⌘O` pasta, `⌥⌘O` workspace, `⌘S` salvar e `⌘F` buscar.

## CLI

```sh
bytetrawl-cli inspect ./SomeApp.app --pretty
bytetrawl-cli inspect ./MyApp.ipa --depth deep --format sarif --output bytetrawl.sarif
bytetrawl-cli inspect ./package --hash sha256 --strings --entropy
```

As profundidades são `lightweight`, `standard` e `deep`. Os códigos distinguem erro fatal (`1`), falha de policy/finding (`2`), cancelamento (`4`) e relatório parcial utilizável (`5`).

## Requisitos

- Mac com Apple silicon (`arm64`)
- macOS 13 Ventura ou posterior
- Homebrew para os comandos acima

O núcleo é independente do GPUI e inspeciona Windows PE e Linux ELF estaticamente no macOS. Empacotamento e UI nativos para Windows e Linux virão depois.

## Limites de segurança

ByteTrawl é estático e somente leitura. Não executa programas importados, monta imagens, instala pacotes, extrai arquivos automaticamente, descompila, depura ou modifica bytes. A descoberta não segue links simbólicos e há limites explícitos para entradas, recursão, arquivos, strings, membros de arquivos e saída de comandos. Findings heurísticos são pistas, não veredictos de malware.

## Documentação

[Estratégia](docs/product-strategy.md) · [Análise do produto e concorrentes](docs/product-analysis-roadmap.md) · [Plano IPAView](docs/ipa-convergence-plan.md) · [Testes](docs/testing.md) · [Site](https://xnu.app/bytetrawl/)

O README em inglês é canônico; as traduções são sincronizadas quando mudam versão, instalação ou capacidades principais.
