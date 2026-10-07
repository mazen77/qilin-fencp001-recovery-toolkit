#!/bin/sh
set -eu

qilin-fencp-recovery inspect "encrypted_sample.victim"

qilin-fencp-recovery profile-rar4 \
  --clean "clean_reference_A.bin" "clean_reference_B.bin" \
  --out rar4_profile.json

qilin-fencp-recovery rar4-header-map \
  --encrypted "backup_YYYYMMDD_HHMM.rar.victim" \
  --profile rar4_profile.json \
  --out stream_A.json

qilin-fencp-recovery derive-exact \
  --plaintext exact_original.bin \
  --encrypted exact_original.bin.victim \
  --out recovered.stream.bin

qilin-fencp-recovery decrypt-keystream \
  --encrypted second_file.victim \
  --keystream recovered.stream.bin \
  --out second_file.recovered
