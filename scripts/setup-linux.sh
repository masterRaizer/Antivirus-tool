#!/usr/bin/env bash
# Подготовка Linux-окружения (Debian/Ubuntu) для сборки и тестов Sentinel.
# Устанавливает dotnet-sdk-8.0 через apt, если подходящего SDK ещё нет, и
# проверяет, что SDK действительно работает. Идемпотентен: повторный запуск
# в уже настроенном контейнере ничего не меняет.
#
# WPF-проект Sentinel.App собирается из Linux кросс-сборкой (EnableWindowsTargeting),
# для чего нужен пакет Microsoft.NET.Sdk.WindowsDesktop. В SDK из репозиториев
# Ubuntu/Debian (source-build) его нет, поэтому при его отсутствии дополнительно
# ставится официальная сборка SDK Microsoft (dotnet-install.sh) в
# /usr/local/share/dotnet-ms со ссылкой /usr/local/bin/dotnet.
#
#   scripts/setup-linux.sh           — установить при необходимости и проверить
#   scripts/setup-linux.sh --check   — только проверить, ничего не устанавливать
set -euo pipefail

MS_SDK_DIR="/usr/local/share/dotnet-ms"
MS_SDK_LINK="/usr/local/bin/dotnet"
INSTALL_SCRIPT_URL="https://dot.net/v1/dotnet-install.sh"

REQUIRED_MAJOR=8
PACKAGE="dotnet-sdk-8.0"
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    -h|--help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
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

# Есть ли у выбранного dotnet пакет Microsoft.NET.Sdk.WindowsDesktop (нужен для сборки WPF).
has_windows_desktop() {
  local root
  root="$(dirname "$(readlink -f "$(command -v dotnet)")")"
  compgen -G "${root}/sdk/${REQUIRED_MAJOR}.*/Sdks/Microsoft.NET.Sdk.WindowsDesktop" >/dev/null 2>&1
}

install_ms_sdk() {
  if ! command -v curl >/dev/null 2>&1; then
    log "curl не найден — не могу загрузить ${INSTALL_SCRIPT_URL}." >&2
    return 1
  fi

  local installer
  installer="$(mktemp)"
  log "Загрузка dotnet-install.sh…"
  curl -fsSL "$INSTALL_SCRIPT_URL" -o "$installer"
  log "Установка официального .NET SDK ${REQUIRED_MAJOR} (с Microsoft.NET.Sdk.WindowsDesktop) в ${MS_SDK_DIR}…"
  run_as_root bash "$installer" --channel "${REQUIRED_MAJOR}.0" --install-dir "$MS_SDK_DIR" --no-path
  rm -f "$installer"
  run_as_root ln -sf "${MS_SDK_DIR}/dotnet" "$MS_SDK_LINK"
}

if has_windows_desktop; then
  log "Microsoft.NET.Sdk.WindowsDesktop доступен (сборка WPF возможна)."
elif [ "$CHECK_ONLY" -eq 1 ]; then
  log "В SDK нет Microsoft.NET.Sdk.WindowsDesktop — Sentinel.App не соберётся (режим --check)." >&2
  exit 1
else
  log "В установленном SDK нет Microsoft.NET.Sdk.WindowsDesktop (сборка из исходников дистрибутива)."
  install_ms_sdk
  hash -r
  if ! has_windows_desktop; then
    log "dotnet в PATH ($(command -v dotnet)) по-прежнему без WindowsDesktop." >&2
    log "Поставьте ${MS_SDK_LINK%/dotnet} раньше в PATH: export PATH=\"${MS_SDK_LINK%/dotnet}:\$PATH\"" >&2
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
