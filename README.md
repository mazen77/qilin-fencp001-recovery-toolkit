# Qilin FENCP001 Recovery Toolkit

[![Author: Mazen Bassiso](https://img.shields.io/badge/Author-Mazen%20Bassiso-2f81f7)](https://fa7ma.com)
![Focus: Cybersecurity Research](https://img.shields.io/badge/Focus-Cybersecurity%20Research-238636)
![Use: Defensive Recovery](https://img.shields.io/badge/Use-Defensive%20Recovery-8250df)


Experimental **defensive recovery/decryption toolkit** for Qilin-branded files that use the undocumented `FENCP001` footer.

> **Important:** this is **not a universal Qilin decryptor** and it does not break RSA-4096, AES, ChaCha20, or other secure ciphers. It provides a real recovery path when an implementation weakness exposes enough keystream material — especially **aligned stream/nonce reuse plus exact known plaintext** — and it can perform evidence-backed partial reconstruction for RAR4 backups.

[العربية](README_AR.md)

## Created by Mazen Bassiso

**Mazen Bassiso — Cybersecurity Researcher & Technology Builder**

- Website: https://fa7ma.com
- Public tech profile: **@maz_tech**
- Focus: defensive cybersecurity, ransomware recovery, incident response, privacy-first tooling, file-format analysis, and practical security hardening.

This project is led and maintained by **Mazen Bassiso**. It grew from hands-on defensive research into undocumented ransomware file behavior and was turned into a reusable, privacy-safe recovery toolkit for other victims, incident responders, and security researchers.

The work represented in this repository focuses on:

- evidence-backed ransomware recovery rather than unsupported “universal decryptor” claims;
- stream/nonce-reuse analysis and exact known-plaintext recovery;
- DFIR-friendly tooling that never executes suspicious input files;
- privacy-by-default reporting for public research;
- practical, reproducible security research that other researchers can test and extend.

If this project contributes to your research, recovery work, article, talk, or tooling, please credit **Mazen Bassiso** and this repository. A machine-readable citation is provided in `CITATION.cff`.

## Privacy-first public release

This repository contains **no victim files, customer databases, ransom notes, victim extensions, campaign contacts, private keys, server paths, incident hashes, company/product identifiers, or live malware**.

Reports produced by the CLI redact identifying material by default. Local filenames, hashes, inner filenames, opaque footer bytes, and similar identifiers are included only when the user explicitly passes an `--include-identifiers` or `--include-source-metadata` flag.

## Why this project exists

Public research describes mature Qilin/Agenda variants that use strong symmetric encryption protected by asymmetric key material. Separately, some incidents may expose implementation mistakes such as aligned stream reuse. When that happens, the underlying cipher does not need to be broken: if enough plaintext for one ciphertext is independently known, the reused keystream can be recovered and applied to another ciphertext that used the same aligned stream.

For stream/CTR-style encryption:

```text
keystream = known_plaintext XOR matching_ciphertext
recovered_plaintext = other_ciphertext XOR keystream
```

This toolkit automates that recovery model without claiming it applies to every Qilin generation.

## What the tool can do

- Safely inspect suspicious files without executing them.
- Recognize RAR4 archives even when their filename extension is misleading.
- Parse `FENCP001` version, flags, chunk size and original-extension metadata.
- Learn a reusable RAR4 packaging profile from two or more clean reference backups.
- Recover profile-backed RAR header plaintext and derive sparse keystream bytes.
- Compare multiple encrypted files for aligned stream-reuse evidence.
- Derive a **complete keystream** from an exact clean/encrypted pair.
- Use a verified keystream to decrypt another file that reused the same aligned stream.
- Merge sparse stream maps while refusing conflicts.
- Apply sparse maps to separate forensic/research copies without overwriting originals.
- Run a four-generation stability heuristic on two historical clean files and two encrypted files.
- Produce JSON reports with identifying fields redacted by default.

## What it cannot do

- Recover an RSA private key.
- Brute-force a properly random AES/ChaCha session key.
- Turn a merely *similar* historical backup into a complete keystream.
- Guarantee that every Qilin family/build uses `FENCP001` or stream reuse.
- Claim that a sparse output is fully decrypted when unknown bytes remain encrypted.

## Safety

The program never executes an input file and never overwrites it in place. Preserve original encrypted evidence and work on copies.

Do not upload victim databases, live malware, ransom communications, private keys, credentials, or personally identifying information to public issues.

## Requirements

- Python 3.10+
- No third-party Python packages for the core workflow

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

Or run directly:

```bash
python3 src/qilin_fencp001_recovery.py --help
```

Arabic CLI messages are available with `--lang ar`.

## Quick start

### 1. Inspect without executing

```bash
qilin-fencp-recovery inspect "reference_backup.bin"
qilin-fencp-recovery inspect "encrypted_sample.victim"
```

By default the output omits hashes, inner filenames and opaque footer values. For a private IR report only:

```bash
qilin-fencp-recovery inspect "encrypted_sample.victim" --include-identifiers
```

### 2. Build a generic RAR4 reference profile

Use at least two clean backups produced by the same backup process:

```bash
qilin-fencp-recovery profile-rar4 \
  --clean "clean_reference_A.bin" "clean_reference_B.bin" \
  --out rar4_profile.json
```

The generated profile omits source filenames and hashes by default. To include them in a private report:

```bash
qilin-fencp-recovery profile-rar4 \
  --clean "clean_reference_A.bin" "clean_reference_B.bin" \
  --out rar4_profile.json \
  --include-source-metadata
```

### 3. Derive a sparse header keystream map

The encrypted backup filename should preserve enough of the original naming pattern for the RAR filename/timestamp inference to be valid.

```bash
qilin-fencp-recovery rar4-header-map \
  --encrypted "backup_YYYYMMDD_HHMM.rar.victim" \
  --profile rar4_profile.json \
  --out stream_A.json
```

Merge several independently derived maps only when they do not conflict:

```bash
qilin-fencp-recovery merge-maps \
  --maps stream_A.json stream_B.json \
  --out merged_stream.json
```

### 4. Create a sparse forensic copy

```bash
qilin-fencp-recovery apply-map \
  --encrypted "backup_YYYYMMDD_HHMM.rar.victim" \
  --map merged_stream.json \
  --out sparse_recovery.rar
```

Unknown bytes remain encrypted. This is useful for structural validation and research; it is **not** a complete restore unless the map covers the complete encrypted body.

## Full decryption without the attacker key when an exact original exists

If you have the **exact pre-encryption counterpart** of one encrypted file from a reused-stream context:

```bash
qilin-fencp-recovery derive-exact \
  --plaintext exact_original.bin \
  --encrypted exact_original.bin.victim \
  --out recovered.stream.bin \
  --report derive_report.json
```

Then, if another encrypted file used the same aligned stream and is no longer than the recovered keystream:

```bash
qilin-fencp-recovery decrypt-keystream \
  --encrypted second_file.victim \
  --keystream recovered.stream.bin \
  --out second_file.recovered
```

This is genuine decryption via a verified reused keystream; no cryptographic brute force is involved.

## Pair analysis

```bash
qilin-fencp-recovery analyze-pair \
  encrypted_A.victim encrypted_B.victim \
  --out pair_report.json
```

The report checks footer equality internally, parameter-context reuse, longest equal ciphertext prefix and repeated equal runs while redacting identifiers by default.

## Four-generation heuristic

```bash
qilin-fencp-recovery stable-four-way \
  --clean-a clean_old.bin \
  --clean-b clean_newer.bin \
  --enc-a encrypted_A.victim \
  --enc-b encrypted_B.victim \
  --min-run 8 \
  --out stable_candidates.json
```

This is intentionally labelled **heuristic**. A byte range that stayed unchanged in two historical files and appears equal in two ciphertexts is interesting evidence, but it does not prove the later plaintext is identical.

## One-command generic RAR4 workflow

```bash
qilin-fencp-recovery auto-rar4 \
  --clean "clean_reference_A.bin" "clean_reference_B.bin" \
  --encrypted "encrypted_A.victim" "encrypted_B.victim" \
  --out-dir recovery_out
```

It creates a reference profile, pair analysis, one map per encrypted file, a conflict-checked merged map, generic sparse outputs (`sparse_1.rar`, `sparse_2.rar`, ...), and a summary.

## Privacy notes for researchers

Safe defaults intentionally omit:

- local filenames and paths;
- SHA-256 values;
- opaque `FENCP001` parameter/footer bytes;
- inner archive filenames;
- source backup metadata.

Those fields can be useful during private incident response, so opt-in flags exist. Do not publish opt-in reports without reviewing them first.

## Public research references

These resources describe standard Qilin/Agenda variants and explain why this project does not claim to defeat normal strong cryptography:

- Malware Cake Factory — Qilin Rust variant analysis: https://malwarecakefactory.github.io/malware-analysis/qilin-ransomware-rust-analysis/
- AhnLab — Qilin ransomware analysis: https://www.ahnlab.com/en/contents/content-center/35984
- KONDORDEVSECURITYCORP — Qilin static analysis: https://github.com/KONDORDEVSECURITYCORP/Qilin-Ransomware-Threat-Analysis
- No More Ransom — decryptor index: https://www.nomoreransom.org/en/decryption-tools.html
- RAR 1.5–4.x research notes: https://github.com/bitplane/rar-research

## Responsible use

This project is intended for incident response, data recovery, interoperability and defensive malware research. It contains no ransomware deployment, persistence, exploitation, credential theft or destructive functionality.

## Contributing

Useful contributions include:

- sanitized `FENCP001` layout observations;
- attacker-issued decryptor reverse engineering;
- documented stream/key reuse cases;
- parsers for additional Qilin container generations;
- independently verified known-plaintext mappings;
- privacy-preserving tests and format documentation.

Use synthetic fixtures whenever possible.

## Researcher / Author

This project is created and maintained by **Mazen Bassiso**, cybersecurity researcher and technology builder. See [`AUTHOR.md`](AUTHOR.md) for a public bio and [`MEDIA_KIT.md`](MEDIA_KIT.md) for citation, press, and launch material.

## License

MIT.
