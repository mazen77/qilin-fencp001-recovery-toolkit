# Changelog

## 1.1.0 — Researcher-branded public release

- Publicly credits **Mazen Bassiso** as creator and maintainer.
- Adds bilingual researcher profile and public research focus.
- Adds `CITATION.cff` for academic/research attribution.
- Adds `MEDIA_KIT.md` with GitHub description, topics, launch copy, social copy, and talk abstract.
- Adds author website `fa7ma.com` and public technology/security handle `@maz_tech`.
- Adds CLI `--version` credit while preserving privacy-safe behavior.
- Keeps all victim/incident identifiers removed from the public package.

## 1.0.1 — Public-safe release

- Removed all incident-specific names, dates, extensions, hashes and product/company references.
- Removed the case-derived bundled RAR4 profile and incident research summary.
- Renamed case-specific commands to generic `profile-rar4`, `rar4-header-map`, and `auto-rar4`.
- Made RAR4 file-header offset parsing dynamic from the main header.
- Redacted filenames, hashes, opaque footer bytes and inner filenames from reports by default.
- Added explicit opt-in flags for private identifier-rich IR reports.
- Replaced case studies with bilingual generic technical notes.
- Kept exact-pair keystream derivation, same-stream decryption, sparse-map recovery and reuse analysis.

## 1.0.0 — Internal research prototype

- Initial defensive research implementation.
