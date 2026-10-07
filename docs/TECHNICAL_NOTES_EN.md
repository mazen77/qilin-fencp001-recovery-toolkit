# Technical Notes — Stream-Reuse Recovery


**Research project led by Mazen Bassiso — Cybersecurity Researcher & Technology Builder.**
This document intentionally uses synthetic labels and contains no victim-specific identifiers.

## Threat model

The toolkit does not assume that Qilin cryptography is weak. It targets a narrower implementation failure: two or more files may have been transformed with the same aligned XOR/CTR-like keystream.

If `C = P XOR K`, then for an exact plaintext/ciphertext pair:

```text
K = P XOR C
```

The recovered `K` can decrypt another ciphertext only when that ciphertext used the same stream at the same offsets.

## FENCP001 parser

The parser recognizes a compact footer beginning with ASCII `FENCP001`. It exposes structural fields such as version, flags, chunk size and original extension. Opaque parameter bytes are not interpreted as keys.

## RAR4 reference profiling

When two or more clean RAR4 backups were produced by the same process, stable header constants can be learned without retaining source filenames or hashes. The current parser supports a common single-file RAR4 layout and dynamically reads the RAR main-header size instead of using an incident-specific constant.

The header map intentionally leaves fields unknown when they cannot be independently established, such as file CRC, unpacked size, header CRC, and timestamp seconds when the name only provides minute precision.

## Exact-pair recovery

`derive-exact` requires byte-for-byte equality with the original pre-encryption file. Similar historical versions are not enough, especially when the source file is compressed before ransomware encryption.

## Four-generation heuristic

`stable-four-way` highlights ranges that were equal across two clean historical generations and equal across two later ciphertexts. This can prioritize research, but it is not a proof that historical plaintext remained unchanged.

## Privacy defaults

Reports redact identifiers by default. Use opt-in identifier flags only for private incident-response work.
