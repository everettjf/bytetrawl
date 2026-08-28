# Real-world artifact corpus

This opt-in corpus complements ByteTrawl's deterministic synthetic and hostile-input fixtures with
real, publicly distributed software artifacts. It is intentionally not checked into Git and is not
part of the ordinary pull-request quality gate.

Each manifest entry is pinned to an immutable release or source commit and records its exact byte
length, SHA-256 digest, upstream project, declared license, and stable report assertions. The fetch
script rejects a payload before analysis if either its size or digest differs. ByteTrawl only reads
these artifacts; the workflow never executes, installs, mounts, or launches them.

Run the corpus locally:

```sh
scripts/fetch-real-world-corpus.sh
scripts/test-real-world-corpus.sh
```

Downloaded artifacts and generated reports live under `target/real-world-corpus/`. GitHub Actions
runs the same scripts on a weekly schedule and through manual dispatch, with the downloads cached by
the manifest hash. A download failure is reported separately from a ByteTrawl assertion failure.

## Coverage model

One real package can exercise several layers. The APK covers ZIP, binary AndroidManifest, DEX and
Android semantics; the IPA covers ZIP members, plists, Mach-O targets, privacy and signing metadata;
the DEB covers ar, tar, control metadata, payload modes and Linux package semantics. Dedicated PE,
ELF, DMG, MSIX and identification-only RPM samples preserve the public support-level boundaries.

Synthetic fixtures remain authoritative for malformed offsets, traversal, symlinks, CRC damage,
decompression limits, cancellation and deterministic edge cases. Real artifacts are regression and
compatibility evidence, not a replacement for adversarial unit tests.

When adding or updating a sample:

1. Use an open-source project and a permanent version/tag or commit URL.
2. Record the repository license without copying the artifact into this repository.
3. Download it to a temporary directory and independently calculate byte length and SHA-256.
4. Add semantic assertions that describe stable product behavior, not incidental UUIDs or timestamps.
5. Run the complete corpus locally before committing the manifest.
