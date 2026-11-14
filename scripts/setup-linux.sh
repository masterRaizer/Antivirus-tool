#!/usr/bin/env bash
# Подготовка Linux-окружения (Debian/Ubuntu) для сборки и тестов Sentinel.
# Устанавливает dotnet-sdk-8.0 через apt, если подходящего SDK ещё нет, и
# проверяет, что SDK действительно работает. Идемпотентен: повторный запуск
# в уже настроенном контейнере ничего не меняет.
#
#   scripts/setup-linux.sh           — установить при необходимости и проверить
#   scripts/setup-linux.sh --check   — только проверить, ничего не устанавливать
set -euo pipefail

REQUIRED_MAJOR=8
PACKAGE="dotnet-sdk-8.0"
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    -h|--help)
      sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      echo "Неизвестный аргумент: $arg" >&2
      exit 2 ;;
  esac
done

log() { printf '[setup-linux] %s\n' "$*"; }

# Возвращает 0, если установлен SDK нужной мажорной версии.
has_required_sdk() {
  command -v dotnet >/dev/null 2>&1 || return 1
  dotnet --list-sdks 2>/dev/null | grep -Eq "^${REQUIRED_MAJOR}\.[0-9]+\.[0-9]+"
}

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    log "Нужны права root (или sudo) для: $*" >&2
    return 1
  fi
}

install_sdk() {
  if ! command -v apt-get >/dev/null 2>&1; then
    log "apt-get не найден: скрипт рассчитан на Debian/Ubuntu." >&2
    log "Установите .NET SDK ${REQUIRED_MAJOR} вручную: https://learn.microsoft.com/dotnet/core/install/linux" >&2
    return 1
  fi

  export DEBIAN_FRONTEND=noninteractive
  log "Обновление индекса пакетов apt…"
  # Сбой одного стороннего репозитория не должен мешать установке из основного.
  run_as_root apt-get update -qq || log "apt-get update завершился с ошибками — продолжаю с имеющимся индексом."

  if ! apt-cache show "$PACKAGE" >/dev/null 2>&1; then
    log "Пакет $PACKAGE отсутствует в подключённых репозиториях apt." >&2
    log "Для Ubuntu < 22.04 / Debian подключите репозиторий Microsoft:" >&2
    log "  https://learn.microsoft.com/dotnet/core/install/linux" >&2
    return 1
  fi

  log "Установка $PACKAGE…"
  run_as_root apt-get install -y -qq --no-install-recommends "$PACKAGE"
}

if has_required_sdk; then
  log ".NET SDK ${REQUIRED_MAJOR} уже установлен."
elif [ "$CHECK_ONLY" -eq 1 ]; then
  log ".NET SDK ${REQUIRED_MAJOR} не найден (режим --check, установка не выполняется)." >&2
  exit 1
else
  log ".NET SDK ${REQUIRED_MAJOR} не найден."
  install_sdk
  hash -r
  if ! has_required_sdk; then
    log "После установки .NET SDK ${REQUIRED_MAJOR} по-прежнему недоступен." >&2
    exit 1
  fi
fi

# В контейнерах без телеметрии и баннера первого запуска вывод чище.
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

log "dotnet:   $(command -v dotnet)"
log "SDK:      $(dotnet --list-sdks | grep -E "^${REQUIRED_MAJOR}\." | tr '\n' ' ')"
log "Версия, выбранная global.json: $(cd "$(dirname "$0")/.." && dotnet --version)"
log "Окружение готово: dotnet build && dotnet test"
