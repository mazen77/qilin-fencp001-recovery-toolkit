#!/usr/bin/env python3
"""Qilin FENCP001 Recovery Toolkit.

Defensive recovery toolkit created and maintained by Mazen Bassiso.
Built from defensive analysis of Qilin-branded FENCP001 files and clean reference RAR4 backups.

The tool never executes input files and never overwrites them in place.

Capabilities:
- Inspect FENCP001 footers.
- Inspect RAR4 headers safely (even when a file has an .exe extension).
- Build a reusable RAR4 packaging profile from clean reference backups.
- Recover high-confidence plaintext header bytes from encrypted RAR4 backups.
- Derive a full stream/CTR keystream from an exact plaintext/encrypted pair.
- Decrypt another same-stream FENCP001 file when a full verified keystream exists.
- Merge/apply sparse verified stream maps.
- Compare encrypted pairs for reuse evidence.
- Search for stable byte runs across clean/encrypted generations (heuristic only).

This does not break RSA-4096, AES, or ChaCha20. Full decryption without a key is
possible only when a recoverable implementation weakness supplies enough stream
material (for example, exact known plaintext under a reused stream).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

MAGIC = b"FENCP001"
RAR4_SIG = b"Rar!\x1a\x07\x00"
RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
TOOL_VERSION = "1.1.0"
TOOL_AUTHOR = "Mazen Bassiso"

MESSAGES = {
    "en": {
        "not_fencp": "FENCP001 footer not found",
        "not_rar4": "RAR4 signature not found",
        "wrote": "Wrote",
        "warning_sparse": "Sparse recovery: unknown bytes remain encrypted. Do not treat this as a complete decrypted file.",
        "warning_exact": "Use exact-pair derivation only when the plaintext is the exact pre-encryption counterpart.",
        "same_stream": "Evidence is consistent with aligned stream reuse.",
        "no_same_stream": "No strong aligned stream-reuse evidence was established.",
    },
    "ar": {
        "not_fencp": "لم يتم العثور على تذييل FENCP001",
        "not_rar4": "لم يتم العثور على توقيع RAR4",
        "wrote": "تم إنشاء",
        "warning_sparse": "استرداد جزئي: ما زالت بعض البايتات مشفرة. لا تعتبر الملف مفكوك التشفير بالكامل.",
        "warning_exact": "استخدم اشتقاق الزوج المطابق فقط عندما يكون الملف السليم هو النسخة الأصلية نفسها قبل التشفير.",
        "same_stream": "النتيجة متوافقة مع إعادة استخدام تيار تشفير بمحاذاة واحدة.",
        "no_same_stream": "لم يتم إثبات إعادة استخدام تيار التشفير بمحاذاة واحدة بشكل قوي.",
    },
}


def msg(lang: str, key: str) -> str:
    return MESSAGES.get(lang, MESSAGES["en"]).get(key, key)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass
class FencpFooter:
    file_size: int
    body_size: int
    footer_len: int
    version: int
    flags: int
    chunk_size: int
    parameter_blob_hex: str
    original_extension: str
    extension_length: int
    footer_hex: str


@dataclass
class Rar4Info:
    file_size: int
    head_crc: int
    head_type: int
    head_flags: int
    head_size: int
    pack_size: int
    unp_size: int
    host_os: int
    file_crc: int
    ftime_raw: int
    unp_ver: int
    method: int
    name_size: int
    attr: int
    filename: str
    file_header_offset: int
    data_offset: int
    endarc_size: int


def _locate_fencp_footer(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 18:
        raise ValueError("file too small")
    declared = struct.unpack("<I", data[-4:])[0]
    if 18 <= declared <= min(len(data), 4096):
        start = len(data) - declared
        footer = data[start:]
        if footer.startswith(MAGIC):
            return start, footer
    # Fallback: locate the last magic within 4 KiB.
    tail_start = max(0, len(data) - 4096)
    pos = data.rfind(MAGIC, tail_start)
    if pos >= 0:
        footer = data[pos:]
        if len(footer) >= 18 and struct.unpack("<I", footer[-4:])[0] == len(footer):
            return pos, footer
    raise ValueError("FENCP001 footer not found")


def parse_fencp(path: Path) -> FencpFooter:
    data = path.read_bytes()
    start, footer = _locate_fencp_footer(data)
    if len(footer) < 19:
        raise ValueError("truncated FENCP001 footer")
    version = footer[8]
    flags = footer[9]
    chunk_size = struct.unpack("<I", footer[10:14])[0]
    # Observed v2 layout: magic8 | version1 | flags1 | chunk4 |
    # parameter blob | extension_length1 | extension | footer_length4.
    ext = ""
    ext_len = 0
    ext_len_pos = None
    for candidate_len in range(1, min(32, len(footer) - 18) + 1):
        p = len(footer) - 4 - candidate_len - 1
        if p < 14:
            continue
        if footer[p] != candidate_len:
            continue
        raw = footer[p + 1 : p + 1 + candidate_len]
        if raw and all(32 <= b < 127 for b in raw):
            ext = raw.decode("ascii", errors="replace")
            ext_len = candidate_len
            ext_len_pos = p
            break
    if ext_len_pos is None:
        # Conservative fallback: keep all bytes after offset 14 as opaque except length dword.
        ext_len_pos = len(footer) - 4
    param = footer[14:ext_len_pos]
    return FencpFooter(
        file_size=len(data),
        body_size=start,
        footer_len=len(footer),
        version=version,
        flags=flags,
        chunk_size=chunk_size,
        parameter_blob_hex=param.hex(),
        original_extension=ext,
        extension_length=ext_len,
        footer_hex=footer.hex(),
    )


def parse_rar4(path: Path) -> Rar4Info:
    size = path.stat().st_size
    with path.open("rb") as f:
        first = f.read(256)
    if not first.startswith(RAR4_SIG):
        raise ValueError("RAR4 signature not found")
    # Parse the RAR4 MAIN_HEAD length instead of assuming a case-specific offset.
    if len(first) < 14:
        raise ValueError("truncated RAR4 main header")
    main_head_type = first[9]
    main_head_size = struct.unpack("<H", first[12:14])[0]
    if main_head_type != 0x73 or main_head_size < 7:
        raise ValueError("unexpected RAR4 main header")
    off = len(RAR4_SIG) + main_head_size
    if len(first) < off + 32:
        raise ValueError("truncated RAR4 file header")
    head_crc = struct.unpack("<H", first[off : off + 2])[0]
    head_type = first[off + 2]
    head_flags = struct.unpack("<H", first[off + 3 : off + 5])[0]
    head_size = struct.unpack("<H", first[off + 5 : off + 7])[0]
    if head_type != 0x74 or head_size < 32 or head_size > 65535:
        raise ValueError("unexpected RAR4 file header")
    if len(first) < off + head_size:
        with path.open("rb") as f:
            first = f.read(off + head_size)
    pack_size = struct.unpack("<I", first[off + 7 : off + 11])[0]
    unp_size = struct.unpack("<I", first[off + 11 : off + 15])[0]
    host_os = first[off + 15]
    file_crc = struct.unpack("<I", first[off + 16 : off + 20])[0]
    ftime_raw = struct.unpack("<I", first[off + 20 : off + 24])[0]
    unp_ver = first[off + 24]
    method = first[off + 25]
    name_size = struct.unpack("<H", first[off + 26 : off + 28])[0]
    attr = struct.unpack("<I", first[off + 28 : off + 32])[0]
    n0 = off + 32
    n1 = n0 + name_size
    if n1 > off + head_size:
        raise ValueError("RAR4 filename extends beyond header")
    filename = first[n0:n1].decode("utf-8", errors="replace")
    data_offset = off + head_size
    endarc_size = size - data_offset - pack_size
    return Rar4Info(
        file_size=size,
        head_crc=head_crc,
        head_type=head_type,
        head_flags=head_flags,
        head_size=head_size,
        pack_size=pack_size,
        unp_size=unp_size,
        host_os=host_os,
        file_crc=file_crc,
        ftime_raw=ftime_raw,
        unp_ver=unp_ver,
        method=method,
        name_size=name_size,
        attr=attr,
        filename=filename,
        file_header_offset=off,
        data_offset=data_offset,
        endarc_size=endarc_size,
    )


def dos_datetime(year: int, month: int, day: int, hour: int, minute: int, second: int = 0) -> int:
    if not (1980 <= year <= 2107):
        raise ValueError("DOS year must be 1980..2107")
    d = ((year - 1980) << 9) | (month << 5) | day
    t = (hour << 11) | (minute << 5) | (second // 2)
    return (d << 16) | t


def parse_backup_timestamp(name: str) -> Tuple[int, int, int, int, int]:
    # Supports generic names ending in _YYYYMMDD_HHMM.
    m = re.search(r"_(20\d{6})_(\d{4})(?:\b|$)", name)
    if not m:
        raise ValueError("could not infer YYYYMMDD_HHMM timestamp from backup name")
    ymd, hm = m.groups()
    return int(ymd[:4]), int(ymd[4:6]), int(ymd[6:8]), int(hm[:2]), int(hm[2:])


def strip_target_basename(path: Path, original_extension: str = "rar") -> str:
    name = path.name
    # Remove ransomware extension (last suffix) when present.
    if "." in name:
        name = name.rsplit(".", 1)[0]
    # Chat/upload duplicate decorations such as .rar(1)
    name = re.sub(r"\." + re.escape(original_extension) + r"\(\d+\)$", "", name, flags=re.I)
    # Normal original extension.
    name = re.sub(r"\." + re.escape(original_extension) + r"$", "", name, flags=re.I)
    return name


def stream_map_to_json(stream_map: Dict[int, int], metadata: dict | None = None) -> dict:
    entries = [{"offset": k, "keystream_byte": v} for k, v in sorted(stream_map.items())]
    intervals = []
    if entries:
        start = prev = entries[0]["offset"]
        for e in entries[1:]:
            o = e["offset"]
            if o == prev + 1:
                prev = o
            else:
                intervals.append([start, prev])
                start = prev = o
        intervals.append([start, prev])
    out = {
        "format": "qilin-fencp001-stream-map-v1",
        "tool_version": TOOL_VERSION,
        "known_bytes": len(entries),
        "intervals": intervals,
        "entries": entries,
    }
    if metadata:
        out["metadata"] = metadata
    return out


def load_stream_map(path: Path) -> Dict[int, int]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, dict) and "entries" in obj:
        return {int(e["offset"]): int(e["keystream_byte"]) for e in obj["entries"]}
    if isinstance(obj, dict):
        # Also accept {"123": 45} style.
        return {int(k): int(v) for k, v in obj.items() if str(k).isdigit()}
    raise ValueError("unsupported stream map JSON")


def merge_stream_maps(maps: Iterable[Dict[int, int]]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for m in maps:
        for off, val in m.items():
            if off in out and out[off] != val:
                raise ValueError(f"stream-map conflict at offset {off}: {out[off]:02x} != {val:02x}")
            out[off] = val
    return out


def build_rar4_profile(clean_paths: List[Path], include_source_metadata: bool = False) -> dict:
    if len(clean_paths) < 2:
        raise ValueError("use at least two clean RAR4 backups to build a profile")
    infos = [parse_rar4(p) for p in clean_paths]
    headers = []
    for p, info in zip(clean_paths, infos):
        with p.open("rb") as f:
            headers.append(f.read(info.data_offset))
    # Stable offsets across all clean headers up to the shortest data offset.
    limit = min(map(len, headers))
    stable = {}
    for i in range(limit):
        vals = {h[i] for h in headers}
        if len(vals) == 1:
            stable[i] = vals.pop()
    # Constants learned from parsed metadata.
    def same(attr: str):
        vals = {getattr(x, attr) for x in infos}
        return vals.pop() if len(vals) == 1 else None
    suffixes = []
    for info in infos:
        m = re.search(r"(\.[^.]+)$", info.filename)
        suffixes.append(m.group(1) if m else "")
    suffix = suffixes[0] if len(set(suffixes)) == 1 else ".dmp"
    profile = {
        "format": "rar4-reference-profile-v1",
        "tool_version": TOOL_VERSION,
        "source_count": len(clean_paths),
        "source_files": ([
            {
                "name": p.name,
                "sha256": sha256_file(p),
                "size": p.stat().st_size,
                "inner_filename": i.filename,
                "pack_size": i.pack_size,
                "unp_size": i.unp_size,
            }
            for p, i in zip(clean_paths, infos)
        ] if include_source_metadata else []),
        "rar4": {
            "file_header_offset": same("file_header_offset"),
            "head_type": same("head_type"),
            "head_flags": same("head_flags"),
            "head_size": same("head_size"),
            "host_os": same("host_os"),
            "unp_ver": same("unp_ver"),
            "method": same("method"),
            "attr": same("attr"),
            "endarc_size": same("endarc_size"),
            "inner_suffix": suffix,
        },
        "stable_header_bytes": [{"offset": o, "value": v} for o, v in sorted(stable.items())],
    }
    return profile


def build_target_plain_map(enc_path: Path, profile: dict) -> Tuple[Dict[int, int], dict]:
    footer = parse_fencp(enc_path)
    rar = profile["rar4"]
    body_size = footer.body_size
    off = int(rar.get("file_header_offset") or 20)
    head_size = int(rar.get("head_size") or 65)
    endarc_size = int(rar.get("endarc_size") or 7)
    base = strip_target_basename(enc_path, footer.original_extension or "rar")
    suffix = rar.get("inner_suffix") or ".dmp"
    inner_name = base + suffix
    y, mo, d, hh, mm = parse_backup_timestamp(base)
    ft = dos_datetime(y, mo, d, hh, mm, 0)
    plain: Dict[int, int] = {}
    # Use learned stable bytes, but do not blindly copy fields known to vary.
    varying_ranges = [
        range(off, off + 2),      # header CRC
        range(off + 7, off + 11), # packed size is predictable dynamically below
        range(off + 11, off + 15),# unpacked size unknown
        range(off + 16, off + 20),# file CRC unknown
        range(off + 20, off + 24),# mtime predictable dynamically below
        range(off + 26, off + 28),# filename length predictable dynamically below
        range(off + 32, off + head_size), # filename/tail dynamic below
    ]
    varying = {x for r in varying_ranges for x in r}
    for e in profile.get("stable_header_bytes", []):
        o = int(e["offset"])
        if o not in varying:
            plain[o] = int(e["value"])
    # RAR signature bytes are format constants; other fields come from the reference profile.
    for i, b in enumerate(RAR4_SIG):
        plain[i] = b
    # Predict structural fields from the clean-backup profile.
    if rar.get("head_type") is not None:
        plain[off + 2] = int(rar["head_type"])
    if rar.get("head_flags") is not None:
        for i, b in enumerate(struct.pack("<H", int(rar["head_flags"]))):
            plain[off + 3 + i] = b
    for i, b in enumerate(struct.pack("<H", head_size)):
        plain[off + 5 + i] = b
    if rar.get("host_os") is not None:
        plain[off + 15] = int(rar["host_os"])
    if rar.get("unp_ver") is not None:
        plain[off + 24] = int(rar["unp_ver"])
    if rar.get("method") is not None:
        plain[off + 25] = int(rar["method"])
    if rar.get("attr") is not None:
        for i, b in enumerate(struct.pack("<I", int(rar["attr"]))):
            plain[off + 28 + i] = b

    # Predict fields.
    pack_size = body_size - (off + head_size + endarc_size)
    if pack_size < 0 or pack_size > 0xFFFFFFFF:
        raise ValueError("derived RAR packed size is invalid")
    for i, b in enumerate(struct.pack("<I", pack_size)):
        plain[off + 7 + i] = b
    # DOS timestamp low byte contains seconds/2, which the YYYYMMDD_HHMM
    # filename does not reveal. Recover only the high time byte + 2 date bytes.
    ft_bytes = struct.pack("<I", ft)
    plain[off + 21] = ft_bytes[1]
    plain[off + 22] = ft_bytes[2]
    plain[off + 23] = ft_bytes[3]
    for i, b in enumerate(struct.pack("<H", len(inner_name.encode("utf-8")))):
        plain[off + 26 + i] = b
    name_bytes = inner_name.encode("utf-8")
    if off + 32 + len(name_bytes) > off + head_size:
        raise ValueError("inferred inner filename does not fit learned RAR header")
    for i, b in enumerate(name_bytes):
        plain[off + 32 + i] = b
    # If the clean profile proves stable bytes immediately after the name, retain only those
    # that are stable at the exact target positions. This commonly recovers EXT_TIME flags.
    stable_dict = {int(e["offset"]): int(e["value"]) for e in profile.get("stable_header_bytes", [])}
    tail_start = off + 32 + len(name_bytes)
    for o in range(tail_start, off + head_size):
        if o in stable_dict:
            plain[o] = stable_dict[o]
    meta = {
        "fencp": {
            "body_size": footer.body_size,
            "footer_len": footer.footer_len,
            "version": footer.version,
            "flags": footer.flags,
            "chunk_size": footer.chunk_size,
            "original_extension": footer.original_extension,
        },
        "inferred_pack_size": pack_size,
        "known_plaintext_positions": len(plain),
        "identifiers_redacted": True,
    }
    return plain, meta


def derive_map_from_plain_positions(enc_path: Path, plain: Dict[int, int]) -> Dict[int, int]:
    footer = parse_fencp(enc_path)
    with enc_path.open("rb") as f:
        data = f.read(footer.body_size)
    out = {}
    for off, p in plain.items():
        if off < 0 or off >= len(data):
            continue
        out[off] = data[off] ^ p
    return out


def apply_sparse_map(enc_path: Path, stream_map: Dict[int, int], out: Path) -> None:
    footer = parse_fencp(enc_path)
    with enc_path.open("rb") as src, out.open("wb") as dst:
        pos = 0
        remaining = footer.body_size
        block = 4 * 1024 * 1024
        while remaining:
            chunk = bytearray(src.read(min(block, remaining)))
            if not chunk:
                raise IOError("unexpected EOF")
            for i in range(len(chunk)):
                off = pos + i
                if off in stream_map:
                    chunk[i] ^= stream_map[off]
            dst.write(chunk)
            pos += len(chunk)
            remaining -= len(chunk)


def derive_exact_keystream(plain_path: Path, enc_path: Path, out: Path) -> dict:
    footer = parse_fencp(enc_path)
    if plain_path.stat().st_size != footer.body_size:
        raise ValueError(
            f"plaintext size {plain_path.stat().st_size} != encrypted body size {footer.body_size}; "
            "the plaintext must be the exact pre-encryption file"
        )
    h = hashlib.sha256()
    with plain_path.open("rb") as pf, enc_path.open("rb") as ef, out.open("wb") as of:
        remain = footer.body_size
        while remain:
            n = min(4 * 1024 * 1024, remain)
            p = pf.read(n)
            c = ef.read(n)
            if len(p) != n or len(c) != n:
                raise IOError("unexpected EOF")
            k = bytes(a ^ b for a, b in zip(p, c))
            of.write(k)
            h.update(k)
            remain -= n
    return {
        "plaintext_sha256": sha256_file(plain_path),
        "encrypted_sha256": sha256_file(enc_path),
        "keystream_sha256": h.hexdigest(),
        "keystream_size": footer.body_size,
        "fencp": asdict(footer),
    }


def decrypt_with_keystream(enc_path: Path, key_path: Path, out: Path) -> dict:
    footer = parse_fencp(enc_path)
    if key_path.stat().st_size < footer.body_size:
        raise ValueError("keystream is shorter than encrypted body")
    with enc_path.open("rb") as ef, key_path.open("rb") as kf, out.open("wb") as of:
        remain = footer.body_size
        while remain:
            n = min(4 * 1024 * 1024, remain)
            c = ef.read(n)
            k = kf.read(n)
            if len(c) != n or len(k) != n:
                raise IOError("unexpected EOF")
            of.write(bytes(a ^ b for a, b in zip(c, k)))
            remain -= n
    sig = out.read_bytes()[:8]
    return {
        "output": str(out),
        "output_sha256": sha256_file(out),
        "rar4_signature": sig[:7] == RAR4_SIG,
        "rar5_signature": sig == RAR5_SIG,
        "fencp": asdict(footer),
    }


def longest_equal_prefix(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


def equal_runs(a: bytes, b: bytes, min_len: int = 8) -> List[Tuple[int, int]]:
    n = min(len(a), len(b))
    out = []
    start = None
    for i in range(n):
        eq = a[i] == b[i]
        if eq and start is None:
            start = i
        elif not eq and start is not None:
            if i - start >= min_len:
                out.append((start, i - start))
            start = None
    if start is not None and n - start >= min_len:
        out.append((start, n - start))
    return out


def analyze_pair(a_path: Path, b_path: Path, min_run: int = 8, include_identifiers: bool = False) -> dict:
    fa, fb = parse_fencp(a_path), parse_fencp(b_path)
    with a_path.open("rb") as f:
        a = f.read(fa.body_size)
    with b_path.open("rb") as f:
        b = f.read(fb.body_size)
    runs = equal_runs(a, b, min_run)
    return {
        "tool_version": TOOL_VERSION,
        "a": ({"name": a_path.name, "sha256": sha256_file(a_path), "fencp": asdict(fa)} if include_identifiers else {"size": a_path.stat().st_size, "fencp": {"body_size": fa.body_size, "footer_len": fa.footer_len, "version": fa.version, "flags": fa.flags, "chunk_size": fa.chunk_size, "original_extension": fa.original_extension}}),
        "b": ({"name": b_path.name, "sha256": sha256_file(b_path), "fencp": asdict(fb)} if include_identifiers else {"size": b_path.stat().st_size, "fencp": {"body_size": fb.body_size, "footer_len": fb.footer_len, "version": fb.version, "flags": fb.flags, "chunk_size": fb.chunk_size, "original_extension": fb.original_extension}}),
        "identical_footer": fa.footer_hex == fb.footer_hex,
        "identical_parameter_blob": fa.parameter_blob_hex == fb.parameter_blob_hex,
        "longest_equal_ciphertext_prefix": longest_equal_prefix(a, b),
        "equal_runs_min_len": min_run,
        "equal_runs": [{"offset": s, "length": l} for s, l in sorted(runs, key=lambda x: x[1], reverse=True)[:500]],
        "assessment": "strong" if fa.parameter_blob_hex == fb.parameter_blob_hex and longest_equal_prefix(a, b) >= 7 else "limited",
    }


def stable_four_way(clean_a: Path, clean_b: Path, enc_a: Path, enc_b: Path, min_run: int = 8, include_identifiers: bool = False) -> dict:
    # Heuristic research aid only. A stable byte in two historical clean backups and
    # equal ciphertext in two later encrypted backups is a useful candidate, but does
    # not prove that the later plaintext equals the historical plaintext.
    fa, fb = parse_fencp(enc_a), parse_fencp(enc_b)
    ca = clean_a.read_bytes()
    cb = clean_b.read_bytes()
    with enc_a.open("rb") as f:
        ea = f.read(fa.body_size)
    with enc_b.open("rb") as f:
        eb = f.read(fb.body_size)
    n = min(len(ca), len(cb), len(ea), len(eb))
    mask_runs = []
    start = None
    for i in range(n):
        ok = ca[i] == cb[i] and ea[i] == eb[i]
        if ok and start is None:
            start = i
        elif not ok and start is not None:
            if i - start >= min_run:
                mask_runs.append((start, i - start))
            start = None
    if start is not None and n - start >= min_run:
        mask_runs.append((start, n - start))
    candidates = []
    for s, l in mask_runs:
        candidates.append({
            "offset": s,
            "length": l,
            "historical_plaintext_hex": ca[s:s+l].hex(),
            "candidate_keystream_hex": bytes(ea[i] ^ ca[i] for i in range(s, s+l)).hex(),
        })
    return {
        "tool_version": TOOL_VERSION,
        "warning": "HEURISTIC ONLY: historical stable plaintext is not proof of later plaintext equality.",
        "inputs": ({
            "clean_a": clean_a.name,
            "clean_b": clean_b.name,
            "enc_a": enc_a.name,
            "enc_b": enc_b.name,
        } if include_identifiers else {"redacted": True}),
        "min_run": min_run,
        "candidate_runs": candidates,
    }


def _public_fencp_view(f: FencpFooter) -> dict:
    return {
        "file_size": f.file_size,
        "body_size": f.body_size,
        "footer_len": f.footer_len,
        "version": f.version,
        "flags": f.flags,
        "chunk_size": f.chunk_size,
        "original_extension": f.original_extension,
        "extension_length": f.extension_length,
    }


def cmd_inspect(args):
    p = Path(args.file)
    try:
        f = parse_fencp(p)
        out = {"type": "FENCP001", **_public_fencp_view(f)}
        if args.include_identifiers:
            out.update({"sha256": sha256_file(p), "parameter_blob_hex": f.parameter_blob_hex, "footer_hex": f.footer_hex})
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    except Exception:
        pass
    try:
        r = parse_rar4(p)
        out = {"type": "RAR4", **asdict(r)}
        if not args.include_identifiers:
            out.pop("filename", None)
        else:
            out["sha256"] = sha256_file(p)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    except Exception:
        pass
    data = p.read_bytes()[:2]
    typ = "PE/EXE" if data == b"MZ" else "unknown"
    out = {"type": typ, "size": p.stat().st_size}
    if args.include_identifiers:
        out["sha256"] = sha256_file(p)
    print(json.dumps(out, indent=2))


def cmd_profile(args):
    paths = [Path(x) for x in args.clean]
    profile = build_rar4_profile(paths, include_source_metadata=args.include_source_metadata)
    out = Path(args.out)
    out.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{msg(args.lang, 'wrote')}: {out}")


def cmd_header_map(args):
    enc = Path(args.encrypted)
    profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    plain, meta = build_target_plain_map(enc, profile)
    stream = derive_map_from_plain_positions(enc, plain)
    obj = stream_map_to_json(stream, {**meta, "confidence": "reference-profile-derived RAR4 header bytes"})
    out = Path(args.out)
    out.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{msg(args.lang, 'wrote')}: {out} ({len(stream)} stream bytes)")


def cmd_merge_maps(args):
    maps = [load_stream_map(Path(x)) for x in args.maps]
    merged = merge_stream_maps(maps)
    out = Path(args.out)
    out.write_text(json.dumps(stream_map_to_json(merged), indent=2), encoding="utf-8")
    print(f"{msg(args.lang, 'wrote')}: {out} ({len(merged)} stream bytes)")


def cmd_apply_map(args):
    m = load_stream_map(Path(args.map))
    out = Path(args.out)
    apply_sparse_map(Path(args.encrypted), m, out)
    print(f"{msg(args.lang, 'wrote')}: {out}")
    print(msg(args.lang, "warning_sparse"))


def cmd_derive_exact(args):
    print(msg(args.lang, "warning_exact"))
    meta = derive_exact_keystream(Path(args.plaintext), Path(args.encrypted), Path(args.out))
    if not args.include_identifiers:
        meta = {"keystream_size": meta["keystream_size"], "identifiers_redacted": True}
    if args.report:
        Path(args.report).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"{msg(args.lang, 'wrote')}: {args.out}")


def cmd_decrypt(args):
    meta = decrypt_with_keystream(Path(args.encrypted), Path(args.keystream), Path(args.out))
    if not args.include_identifiers:
        meta = {
            "rar4_signature": meta["rar4_signature"],
            "rar5_signature": meta["rar5_signature"],
            "output_size": Path(args.out).stat().st_size,
            "identifiers_redacted": True,
        }
    print(json.dumps(meta, indent=2, ensure_ascii=False))


def cmd_pair(args):
    report = analyze_pair(Path(args.a), Path(args.b), args.min_run, args.include_identifiers)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"{msg(args.lang, 'wrote')}: {args.out}")
    print(msg(args.lang, "same_stream") if report["assessment"] == "strong" else msg(args.lang, "no_same_stream"))
    if not args.out:
        print(json.dumps(report, indent=2, ensure_ascii=False))


def cmd_stable(args):
    report = stable_four_way(Path(args.clean_a), Path(args.clean_b), Path(args.enc_a), Path(args.enc_b), args.min_run, args.include_identifiers)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{msg(args.lang, 'wrote')}: {args.out}")
    print(report["warning"])


def cmd_auto_rar4(args):
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    clean = [Path(x) for x in args.clean]
    encrypted = [Path(x) for x in args.encrypted]
    if len(clean) < 2 or len(encrypted) < 1:
        raise ValueError("auto-rar4 requires at least two clean backups and one encrypted file")

    profile = build_rar4_profile(clean, include_source_metadata=args.include_source_metadata)
    profile_path = out_dir / "rar4_profile.json"
    profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")

    map_paths = []
    sparse_paths = []
    maps = []
    per_file = []
    for idx, enc in enumerate(encrypted, 1):
        plain, meta = build_target_plain_map(enc, profile)
        stream = derive_map_from_plain_positions(enc, plain)
        maps.append(stream)
        mp = out_dir / f"stream_{idx}.json"
        mp.write_text(json.dumps(stream_map_to_json(stream, {**meta, "confidence": "reference-profile-derived"}), indent=2, ensure_ascii=False), encoding="utf-8")
        map_paths.append(str(mp))
        sp = out_dir / f"sparse_{idx}.rar"
        apply_sparse_map(enc, stream, sp)
        sparse_paths.append(str(sp))
        per_file.append({"index": idx, "stream_bytes": len(stream), "map": str(mp), "sparse_output": str(sp)})

    merged = merge_stream_maps(maps)
    merged_path = out_dir / "merged_stream.json"
    merged_path.write_text(json.dumps(stream_map_to_json(merged), indent=2), encoding="utf-8")

    pair_report = None
    if len(encrypted) >= 2:
        pair_report = analyze_pair(encrypted[0], encrypted[1], args.min_run, args.include_source_metadata)
        (out_dir / "pair_report.json").write_text(json.dumps(pair_report, indent=2), encoding="utf-8")

    summary = {
        "tool_version": TOOL_VERSION,
        "clean_backup_count": len(clean),
        "encrypted_file_count": len(encrypted),
        "merged_stream_bytes": len(merged),
        "pair_assessment": pair_report.get("assessment") if pair_report else None,
        "outputs": {
            "profile": str(profile_path),
            "merged_stream": str(merged_path),
            "maps": map_paths,
            "sparse_files": sparse_paths,
        },
        "warning": "Sparse files are not complete decrypts unless the stream map covers the entire encrypted body."
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def cmd_verify(args):
    p = Path(args.file)
    out = {"size": p.stat().st_size}
    if args.include_identifiers:
        out.update({"file": str(p), "sha256": sha256_file(p)})
    try:
        r = asdict(parse_rar4(p))
        if not args.include_identifiers:
            r.pop("filename", None)
        out["rar4"] = r
    except Exception as e:
        out["rar4_error"] = str(e)
    try:
        f = parse_fencp(p)
        out["fencp"] = asdict(f) if args.include_identifiers else _public_fencp_view(f)
    except Exception as e:
        out["fencp_error"] = str(e)
    print(json.dumps(out, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="qilin-fencp-recovery",
        description="Experimental defensive recovery toolkit for Qilin-branded FENCP001 files.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION} — by {TOOL_AUTHOR}")
    ap.add_argument("--lang", choices=["en", "ar"], default="en", help="CLI message language")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("inspect", help="safely inspect a file without executing it")
    p.add_argument("file")
    p.add_argument("--include-identifiers", action="store_true", help="include hashes, inner filename, and opaque footer bytes")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("profile-rar4", help="learn RAR4 packaging constants from clean reference backups")
    p.add_argument("--clean", nargs="+", required=True, help="two or more clean RAR4 reference backups")
    p.add_argument("--out", required=True)
    p.add_argument("--include-source-metadata", action="store_true", help="include local filenames and SHA-256 values in the generated profile")
    p.set_defaults(func=cmd_profile)

    p = sub.add_parser("rar4-header-map", help="derive profile-backed stream bytes from an encrypted RAR4 header")
    p.add_argument("--encrypted", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_header_map)

    p = sub.add_parser("merge-maps", help="merge stream maps; abort on conflicts")
    p.add_argument("--maps", nargs="+", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_merge_maps)

    p = sub.add_parser("apply-map", help="apply known stream bytes to a copy; unknown bytes remain encrypted")
    p.add_argument("--encrypted", required=True)
    p.add_argument("--map", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_apply_map)

    p = sub.add_parser("derive-exact", help="derive a full keystream from an exact original/encrypted pair")
    p.add_argument("--plaintext", required=True)
    p.add_argument("--encrypted", required=True)
    p.add_argument("--out", required=True, help="output full keystream file")
    p.add_argument("--report")
    p.add_argument("--include-identifiers", action="store_true", help="include hashes and full footer metadata in the report")
    p.set_defaults(func=cmd_derive_exact)

    p = sub.add_parser("decrypt-keystream", help="decrypt FENCP001 body with a full verified keystream")
    p.add_argument("--encrypted", required=True)
    p.add_argument("--keystream", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--include-identifiers", action="store_true", help="include output hash/path and full footer metadata")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("analyze-pair", help="compare two FENCP001 files for aligned reuse evidence")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--min-run", type=int, default=8)
    p.add_argument("--out")
    p.add_argument("--include-identifiers", action="store_true", help="include local filenames and hashes in the report")
    p.set_defaults(func=cmd_pair)

    p = sub.add_parser("stable-four-way", help="research heuristic using two clean and two encrypted generations")
    p.add_argument("--clean-a", required=True)
    p.add_argument("--clean-b", required=True)
    p.add_argument("--enc-a", required=True)
    p.add_argument("--enc-b", required=True)
    p.add_argument("--min-run", type=int, default=8)
    p.add_argument("--out", required=True)
    p.add_argument("--include-identifiers", action="store_true", help="include local filenames in the report")
    p.set_defaults(func=cmd_stable)

    p = sub.add_parser("auto-rar4", help="one-command generic RAR4 workflow: profile, pair analysis, maps and sparse copies")
    p.add_argument("--clean", nargs="+", required=True, help="two or more clean RAR4 reference backups")
    p.add_argument("--encrypted", nargs="+", required=True, help="one or more FENCP001 encrypted backups")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--min-run", type=int, default=8)
    p.add_argument("--include-source-metadata", action="store_true", help="include local filenames and SHA-256 values in the generated profile")
    p.set_defaults(func=cmd_auto_rar4)

    p = sub.add_parser("verify", help="print structural validation information")
    p.add_argument("file")
    p.add_argument("--include-identifiers", action="store_true", help="include local path, hashes, inner filename, and opaque footer bytes")
    p.set_defaults(func=cmd_verify)
    return ap


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    try:
        args.func(args)
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
