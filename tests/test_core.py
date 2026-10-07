import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]
MOD = ROOT / 'src' / 'qilin_fencp001_recovery.py'
spec = importlib.util.spec_from_file_location('qfr', MOD)
qfr = importlib.util.module_from_spec(spec)
sys.modules['qfr'] = qfr
spec.loader.exec_module(qfr)


def make_footer(ext=b'rar', param=b'P'*29, chunk=1_000_000):
    body = qfr.MAGIC + bytes([2,1]) + struct.pack('<I', chunk) + param + bytes([len(ext)]) + ext
    return body + struct.pack('<I', len(body)+4)


def make_rar4(name='Backup_20260101_0100.dmp', pack_size=100, unp_size=200):
    name_b = name.encode()
    head_size = 32 + len(name_b) + 3
    main = qfr.RAR4_SIG + bytes.fromhex('4170730c000d00000000000000')
    off = bytearray()
    off += b'\x00\x00'          # HEAD_CRC placeholder
    off += b'\x74'              # FILE_HEAD
    off += struct.pack('<H', 0x90c0)
    off += struct.pack('<H', head_size)
    off += struct.pack('<I', pack_size)
    off += struct.pack('<I', unp_size)
    off += b'\x02'
    off += struct.pack('<I', 0x12345678)
    off += struct.pack('<I', qfr.dos_datetime(2026,1,1,1,0,0))
    off += b'\x1d\x35'
    off += struct.pack('<H', len(name_b))
    off += struct.pack('<I', 0x20)
    off += name_b
    off += b'\x00\xd0\x00'
    assert len(off) == head_size
    # CRC in RAR4 is CRC32(header bytes starting at HEAD_TYPE) low 16 bits.
    crc = qfr.zlib.crc32(bytes(off[2:])) & 0xffff
    off[0:2] = struct.pack('<H', crc)
    endarc = b'\xc4\x3d\x7b\x00\x40\x07\x00'
    return main + bytes(off) + bytes([0xAA])*pack_size + endarc


class CoreTests(unittest.TestCase):
    def test_fencp_parse(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'x.rdj'
            p.write_bytes(b'abc123'+make_footer())
            f=qfr.parse_fencp(p)
            self.assertEqual(f.body_size,6)
            self.assertEqual(f.chunk_size,1_000_000)
            self.assertEqual(f.original_extension,'rar')
            self.assertEqual(f.parameter_blob_hex, (b'P'*29).hex())

    def test_rar4_parse(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'clean.exe'
            p.write_bytes(make_rar4())
            r=qfr.parse_rar4(p)
            self.assertEqual(r.filename,'Backup_20260101_0100.dmp')
            self.assertEqual(r.pack_size,100)
            self.assertEqual(r.unp_size,200)
            self.assertEqual(r.endarc_size,7)

    def test_exact_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            plain=td/'plain.rar'
            enc=td/'enc.rdj'
            key=td/'stream.bin'
            out=td/'out.rar'
            body=make_rar4(pack_size=1024, unp_size=2048)
            stream=bytes(((i*73+19)&255) for i in range(len(body)))
            cipher=bytes(a^b for a,b in zip(body,stream))
            plain.write_bytes(body)
            enc.write_bytes(cipher+make_footer())
            qfr.derive_exact_keystream(plain,enc,key)
            meta=qfr.decrypt_with_keystream(enc,key,out)
            self.assertEqual(out.read_bytes(),body)
            self.assertTrue(meta['rar4_signature'])

    def test_merge_conflict(self):
        self.assertEqual(qfr.merge_stream_maps([{1:2},{2:3},{1:2}]),{1:2,2:3})
        with self.assertRaises(ValueError):
            qfr.merge_stream_maps([{1:2},{1:4}])

    def test_profile_redacts_sources_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            a=td/'reference_A.bin'
            b=td/'reference_B.bin'
            a.write_bytes(make_rar4(name='Backup_20240101_0100.bin'))
            b.write_bytes(make_rar4(name='Backup_20240102_0100.bin'))
            profile=qfr.build_rar4_profile([a,b])
            self.assertEqual(profile['source_count'], 2)
            self.assertEqual(profile['source_files'], [])
            self.assertEqual(profile['format'], 'rar4-reference-profile-v1')

    def test_pair_report_redacts_identifiers_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            body=b'A'*128
            a=td/'private_name_A.victim'
            b=td/'private_name_B.victim'
            a.write_bytes(body+make_footer())
            b.write_bytes(body+make_footer())
            report=qfr.analyze_pair(a,b)
            self.assertNotIn('name', report['a'])
            self.assertNotIn('sha256', report['a'])
            self.assertNotIn('parameter_blob_hex', report['a']['fencp'])


if __name__ == '__main__':
    unittest.main()
