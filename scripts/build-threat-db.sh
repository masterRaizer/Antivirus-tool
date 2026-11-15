#!/usr/bin/env bash
# Детерминированная сборка стартовой базы угроз data/threat_hashes.bin из публичных репозиториев IOC.
# Клонирует Neo23x0/signature-base и eset/malware-ioc (поверхностно) во временный каталог и собирает базу
# командой `sentinel threatdb build`. Метку времени можно зафиксировать: THREATDB_TIMESTAMP=2026-11-15T00:00:00Z.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 -q https://github.com/Neo23x0/signature-base "$WORK/signature-base"
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 -q https://github.com/eset/malware-ioc "$WORK/malware-ioc"
dotnet run --project "$ROOT/src/Sentinel.Cli" -c Release -- threatdb build \
  --out "$ROOT/data/threat_hashes.bin" \
  --signature-base "$WORK/signature-base" --eset "$WORK/malware-ioc" \
  --timestamp "${THREATDB_TIMESTAMP:-$(date -u +%Y-%m-%dT00:00:00Z)}"
echo "signature-base: $(git -C "$WORK/signature-base" rev-parse HEAD)"
echo "malware-ioc:    $(git -C "$WORK/malware-ioc" rev-parse HEAD)"
