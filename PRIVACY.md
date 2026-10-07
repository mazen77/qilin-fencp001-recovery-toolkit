# Privacy and Public Sharing

This repository is designed to be safe to publish as source code.

## Not included

The source tree intentionally contains no:

- victim/customer files or database contents;
- incident-specific filenames or ransomware extensions;
- ransom-note contacts or chat identifiers;
- company/product/customer identifiers from a real incident;
- IP addresses, hostnames, usernames or server paths;
- incident file hashes;
- encryption/private keys;
- live ransomware binaries;
- copied opaque parameter blobs from a real victim.

## Safe defaults

CLI reports redact identifying data unless the user explicitly opts in.

The following options should be treated as **private-IR only** because they can add local identifiers to generated reports:

- `--include-identifiers`
- `--include-source-metadata`

Review generated JSON before attaching it to a public GitHub issue.

## Preferred contribution format

Use synthetic fixtures and minimal structural metadata. If a real sample is necessary, remove customer content and direct identifiers first, and obtain appropriate authorization before sharing it.

## Public author identity

This release intentionally includes the public researcher identity **Mazen Bassiso**, website `fa7ma.com`, and public handle `@maz_tech` for authorship, citation, and project discoverability. It does not include private contact details or victim/incident identifiers.
