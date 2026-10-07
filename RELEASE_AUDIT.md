# Public Release Audit — v1.1.0

- Source/test package only; no victim or malware samples included.
- Incident-specific filenames, dates, extensions, product/company names, hashes, contacts, server paths and opaque victim parameter blobs removed.
- Case-derived profile and case-study files removed.
- Generated reports redact identifiers by default.
- Six synthetic unit tests pass.
- Repository-wide sensitive-string scan completed before packaging with no matches for the removed incident identifiers.

Always review generated reports before publishing them; opt-in identifier flags intentionally add private IR metadata.

- Public author identity intentionally included: Mazen Bassiso, fa7ma.com, @maz_tech.
- No private contact information is included.

- Creator/maintainer attribution is intentionally public: Mazen Bassiso.
- Public profile links intentionally included: fa7ma.com and @maz_tech.
- Final v1.1.0 synthetic test suite: 6 passed, 0 failed.
- Final incident-identifier scan: passed with no matches for removed case identifiers.
