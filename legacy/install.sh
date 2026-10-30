#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s nullglob extglob

# XPPN reliability fixes (2026-09-26):
# - avoid systemd deadlock by applying port-80 lockdown only after Docker is ready
# - self-repair legacy Before=docker.service lockdown units on reruns
# - ensure an existing Docker installation is enabled, started and API-responsive
# - pin Remnawave Node to v3.4.1 by default instead of a floating latest tag
INSTALLER_BUILD="2026-09-26-node341-systemd-fix"

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

fatal_early() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

trim_spaces() {
  local s="$1"
  s="${s##+([[:space:]])}"
  s="${s%%+([[:space:]])}"
  printf '%s' "$s"
}

declare -A EXPLICIT_INPUT_VARS=()

remember_explicit_vars() {
  local name
  for name in "$@"; do
    if [[ -v $name ]]; then
      EXPLICIT_INPUT_VARS["$name"]=1
    fi
  done
  return 0
}

load_installer_env_file() {
  local file="$1"
  local mode="${2:-preserve}"
  local line key value

  [[ -f "$file" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="$(trim_spaces "$line")"
    [[ -n "$line" ]] || continue
    [[ "${line:0:1}" != "#" ]] || continue

    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
    else
      fatal_early "Некорректная строка в ${file}: ${line}"
    fi

    if [[ "$mode" == "preserve" && -v $key ]]; then
      continue
    fi
    if [[ "$mode" == "override" && -n "${EXPLICIT_INPUT_VARS[$key]+x}" ]]; then
      continue
    fi

    value="${value%$'\r'}"
    value="$(trim_spaces "$value")"
    if (( ${#value} >= 2 )) && [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
      value="${value:1:${#value}-2}"
      value="${value//\\\\/\\}"
      value="${value//\\\"/\"}"
    elif (( ${#value} >= 2 )) && [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    fi

    printf -v "$key" '%s' "$value"
  done < "$file"

  return 0
}

SCRIPT_ENV_FILE="${SCRIPT_ENV_FILE:-$SCRIPT_DIR/installer.env}"

remember_explicit_vars \
  BASE_DIR CONFIG_FILE CONTAINER_NAME NGINX_IMAGE ACME_HOME ACME_KEYLENGTH LE_SERVER ACME_EMAIL DOMAINS \
  REMNANODE_DIR REMNANODE_COMPOSE_FILE REMNANODE_ENV_FILE REMNANODE_CONTAINER_NAME REMNANODE_SERVICE_NAME \
  REMNANODE_IMAGE NODE_PORT SECRET_KEY SSL_CERT PANEL_DOMAIN PANEL_API_TOKEN PANEL_AUTO_REGISTER_NODE \
  PANEL_NODE_UUID PANEL_NODE_NAME PANEL_NODE_ADDRESS PANEL_NODE_COUNTRY_CODE PANEL_CONFIG_PROFILE_UUID \
  PANEL_CONFIG_PROFILE_NAME PANEL_ACTIVE_INBOUND_UUIDS PANEL_PROVIDER_UUID AUTO_INSTALL_NODE \
  REMNANODE_LOG_DIR REMNANODE_LOGROTATE_FILE REMNANODE_LOGROTATE_SIZE REMNANODE_LOGROTATE_ROTATE \
  DOCKER_LOG_MAX_SIZE DOCKER_LOG_MAX_FILE APT_LOCK_TIMEOUT APT_LOCK_RETRY_INTERVAL NGINX_LOG_DIR \
  INSTALL_LOG_FILE \
  FAIL2BAN_JAIL_FILE FAIL2BAN_FILTER_FILE FAIL2BAN_LOCAL_FILE FAIL2BAN_IGNORE_IPS FAIL2BAN_SSH_BANTIME \
  FAIL2BAN_SSH_FINDTIME FAIL2BAN_SSH_MAXRETRY FAIL2BAN_NGINX_BANTIME FAIL2BAN_NGINX_FINDTIME \
  FAIL2BAN_NGINX_MAXRETRY FAIL2BAN_RECIDIVE_BANTIME FAIL2BAN_RECIDIVE_FINDTIME FAIL2BAN_RECIDIVE_MAXRETRY \
  SITE_SOURCE_DIR EXTRA_INSTALL_DOMAINS

load_installer_env_file "$SCRIPT_ENV_FILE"

LEGACY_BASE_DIR="/opt/remnawave/nginx"
DEFAULT_BASE_DIR="/opt/nginx"
LEGACY_ACME_HOME_DEFAULT="/root/.acme.sh"
BASE_DIR="${BASE_DIR:-$DEFAULT_BASE_DIR}"
CONFIG_FILE="${CONFIG_FILE:-$BASE_DIR/config.env}"
CONTAINER_NAME="${CONTAINER_NAME:-nginx}"
NGINX_IMAGE="${NGINX_IMAGE:-mirror.gcr.io/library/nginx:stable-alpine}"
ACME_HOME="${ACME_HOME:-$BASE_DIR/.acme.sh}"
ACME_KEYLENGTH="${ACME_KEYLENGTH:-ec-256}"
LE_SERVER="${LE_SERVER:-letsencrypt}"
ACME_EMAIL="${ACME_EMAIL:-}"
DOMAINS="${DOMAINS:-}"

REMNANODE_DIR="${REMNANODE_DIR:-/opt/remnanode}"
REMNANODE_COMPOSE_FILE="${REMNANODE_COMPOSE_FILE:-$REMNANODE_DIR/docker-compose.yml}"
REMNANODE_ENV_FILE="${REMNANODE_ENV_FILE:-$REMNANODE_DIR/.env}"
REMNANODE_CONTAINER_NAME="${REMNANODE_CONTAINER_NAME:-remnanode}"
REMNANODE_SERVICE_NAME="${REMNANODE_SERVICE_NAME:-remnanode}"
REMNANODE_IMAGE="${REMNANODE_IMAGE:-remnawave/node:3.4.1}"
NODE_PORT="${NODE_PORT:-2222}"
SECRET_KEY="${SECRET_KEY:-}"
SSL_CERT="${SSL_CERT:-}"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
PANEL_API_TOKEN="${PANEL_API_TOKEN:-}"
PANEL_AUTO_REGISTER_NODE="${PANEL_AUTO_REGISTER_NODE:-1}"
PANEL_NODE_UUID="${PANEL_NODE_UUID:-}"
PANEL_NODE_NAME="${PANEL_NODE_NAME:-}"
PANEL_NODE_ADDRESS="${PANEL_NODE_ADDRESS:-}"
PANEL_NODE_COUNTRY_CODE="${PANEL_NODE_COUNTRY_CODE:-XX}"
PANEL_CONFIG_PROFILE_UUID="${PANEL_CONFIG_PROFILE_UUID:-}"
PANEL_CONFIG_PROFILE_NAME="${PANEL_CONFIG_PROFILE_NAME:-}"
PANEL_ACTIVE_INBOUND_UUIDS="${PANEL_ACTIVE_INBOUND_UUIDS:-}"
PANEL_PROVIDER_UUID="${PANEL_PROVIDER_UUID:-}"
AUTO_INSTALL_NODE="${AUTO_INSTALL_NODE:-1}"
REMNANODE_LOG_DIR="${REMNANODE_LOG_DIR:-/var/log/remnanode}"
REMNANODE_LOGROTATE_FILE="${REMNANODE_LOGROTATE_FILE:-/etc/logrotate.d/remnanode}"
REMNANODE_LOGROTATE_SIZE="${REMNANODE_LOGROTATE_SIZE:-50M}"
REMNANODE_LOGROTATE_ROTATE="${REMNANODE_LOGROTATE_ROTATE:-5}"
DOCKER_LOG_MAX_SIZE="${DOCKER_LOG_MAX_SIZE:-10m}"
DOCKER_LOG_MAX_FILE="${DOCKER_LOG_MAX_FILE:-5}"
APT_LOCK_TIMEOUT="${APT_LOCK_TIMEOUT:-600}"
APT_LOCK_RETRY_INTERVAL="${APT_LOCK_RETRY_INTERVAL:-5}"
SITE_SOURCE_DIR="${SITE_SOURCE_DIR:-}"
EXTRA_INSTALL_DOMAINS="${EXTRA_INSTALL_DOMAINS:-}"
NGINX_LOG_DIR="${NGINX_LOG_DIR:-}"
NGINX_ACCESS_LOG=""
NGINX_ERROR_LOG=""
FAIL2BAN_JAIL_FILE="${FAIL2BAN_JAIL_FILE:-/etc/fail2ban/jail.d/remnanode.local}"
FAIL2BAN_FILTER_FILE="${FAIL2BAN_FILTER_FILE:-/etc/fail2ban/filter.d/remnanode-nginx-botsearch.conf}"
FAIL2BAN_LOCAL_FILE="${FAIL2BAN_LOCAL_FILE:-/etc/fail2ban/fail2ban.d/remnanode.local}"
FAIL2BAN_IGNORE_IPS="${FAIL2BAN_IGNORE_IPS:-127.0.0.1/8 ::1}"
FAIL2BAN_SSH_BANTIME="${FAIL2BAN_SSH_BANTIME:-1h}"
FAIL2BAN_SSH_FINDTIME="${FAIL2BAN_SSH_FINDTIME:-10m}"
FAIL2BAN_SSH_MAXRETRY="${FAIL2BAN_SSH_MAXRETRY:-6}"
FAIL2BAN_NGINX_BANTIME="${FAIL2BAN_NGINX_BANTIME:-12h}"
FAIL2BAN_NGINX_FINDTIME="${FAIL2BAN_NGINX_FINDTIME:-10m}"
FAIL2BAN_NGINX_MAXRETRY="${FAIL2BAN_NGINX_MAXRETRY:-6}"
FAIL2BAN_RECIDIVE_BANTIME="${FAIL2BAN_RECIDIVE_BANTIME:-7d}"
FAIL2BAN_RECIDIVE_FINDTIME="${FAIL2BAN_RECIDIVE_FINDTIME:-1d}"
FAIL2BAN_RECIDIVE_MAXRETRY="${FAIL2BAN_RECIDIVE_MAXRETRY:-5}"

ACME=""
SERVICE_RENEW="/etc/systemd/system/remnawave-acme-renew.service"
TIMER_RENEW="/etc/systemd/system/remnawave-acme-renew.timer"
SERVICE_LOCKDOWN="/etc/systemd/system/remnawave-port80-lockdown.service"
GLOBAL_NODE_HELP_BIN="/usr/local/bin/node-help"
GLOBAL_COMMANDS_DIR="/usr/local/bin"
PORT80_RULE_COMMENT="remnawave-port80"

WWW_DIR=""
ACME_WEBROOT=""
CERTS_DIR=""
SCRIPTS_DIR=""
COMPOSE_FILE=""
NGINX_CONF=""
INDEX_FILE=""
RELOAD_HELPER=""
INSTALL_LOG_FILE=""

DOMAINS_ARR=()
AUTO_INSTALL_DOCKER=0

COLOR_RESET=""
COLOR_INFO=""
COLOR_WARN=""
COLOR_ERROR=""
COLOR_OK=""

# Preserve the user's original stderr for cases where command output is
# redirected into the install log and we still need to show a summary.
exec 4>&2

have_cmd() { command -v "$1" >/dev/null 2>&1; }

init_colors() {
  if [[ -t 1 ]] && have_cmd tput && [[ -n "${TERM:-}" ]] && tput colors >/dev/null 2>&1; then
    COLOR_RESET="$(tput sgr0)"
    COLOR_INFO="$(tput setaf 6)"
    COLOR_WARN="$(tput setaf 3)"
    COLOR_ERROR="$(tput setaf 1)"
    COLOR_OK="$(tput setaf 2)"
  fi
}

ts() { date '+%Y-%m-%d %H:%M:%S'; }

say() {
  local level="$1" color="$2"; shift 2
  printf '%s %b[%s]%b %s\n' "$(ts)" "$color" "$level" "$COLOR_RESET" "$*"
}

log()  { say "INFO" "$COLOR_INFO" "$*"; }
ok()   { say "OK" "$COLOR_OK" "$*"; }
warn() { say "WARN" "$COLOR_WARN" "$*" >&2; }
err()  { say "ERROR" "$COLOR_ERROR" "$*" >&2; }
die()  { err "$*"; exit 1; }

on_error() {
  local exit_code="$1" line_no="$2" cmd="$3"
  local message="Скрипт остановлен. Код выхода: ${exit_code}. Строка: ${line_no}. Команда: ${cmd}"
  if [[ -n "${INSTALL_LOG_FILE:-}" ]]; then
    message="${message}. Лог: ${INSTALL_LOG_FILE}"
  fi
  err "$message"
  if [[ ! -t 2 && -t 4 ]]; then
    printf '%s [ERROR] %s\n' "$(ts)" "$message" >&4
  fi
  exit "$exit_code"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Запусти этот скрипт от root"
}

stdin_is_tty() { [[ -t 0 ]]; }

prompt_input() {
  local __var_name="$1"
  local prompt="$2"
  local default_value="${3:-}"
  local secret="${4:-0}"
  local input=""

  if ! stdin_is_tty; then
    printf -v "$__var_name" '%s' "$default_value"
    return 0
  fi

  if [[ "$secret" == "1" ]]; then
    read -r -s -p "$prompt" input || return 1
    echo
  else
    read -r -p "$prompt" input || return 1
  fi

  printf -v "$__var_name" '%s' "${input:-$default_value}"
}

quote_sh() { printf '%q' "$1"; }

quote_config_value() {
  local value="$1"

  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "Р—РЅР°С‡РµРЅРёРµ РЅРµ РґРѕР»Р¶РЅРѕ СЃРѕРґРµСЂР¶Р°С‚СЊ РїРµСЂРµРІРѕРґС‹ СЃС‚СЂРѕРє"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

require_installer_env() {
  [[ -f "$SCRIPT_ENV_FILE" ]] || die "Не найден файл настроек рядом со скриптом: $SCRIPT_ENV_FILE"
}

mask_secret() {
  local s="$1" len
  len=${#s}
  if (( len == 0 )); then
    echo "(не задан)"
  elif (( len <= 4 )); then
    printf '%*s' "$len" '' | tr ' ' '*'
  else
    printf '%s***%s' "${s:0:2}" "${s: -2}"
  fi
}

validate_compose_env_value() {
  local name="$1" value="$2"

  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "${name} не должен содержать переводы строк"
  [[ "$value" != *[[:space:]]* ]] || die "${name} не должен содержать пробелы или табы для Docker env_file"
  [[ "$value" != *'#'* ]] || die "${name} не должен содержать символ # для Docker env_file"
}

validate_path_value() {
  local name="$1" value="$2"

  [[ -n "$value" ]] || die "${name} РЅРµ РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ РїСѓСЃС‚С‹Рј"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "${name} РЅРµ РґРѕР»Р¶РµРЅ СЃРѕРґРµСЂР¶Р°С‚СЊ РїРµСЂРµРІРѕРґС‹ СЃС‚СЂРѕРє"
  [[ "$value" != *[[:space:]]* ]] || die "${name} РЅРµ РґРѕР»Р¶РµРЅ СЃРѕРґРµСЂР¶Р°С‚СЊ РїСЂРѕР±РµР»С‹"
}

quote_config_value() {
  local value="$1"

  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "Config values must be single-line"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

validate_path_value() {
  local name="$1" value="$2"

  [[ -n "$value" ]] || die "${name} must not be empty"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "${name} must be single-line"
  [[ "$value" != *[[:space:]]* ]] || die "${name} must not contain whitespace"
}

script_abs_path() {
  local dir
  dir="$(cd "$(dirname "$0")" && pwd -P)"
  printf '%s/%s' "$dir" "$(basename "$0")"
}

compose_bin() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi
  if have_cmd docker-compose; then
    echo "docker-compose"
    return 0
  fi
  return 1
}

compose_run() {
  local file="$1"; shift
  local cb file_dir
  [[ -n "$file" ]] || die "Compose file path is empty"
  [[ -f "$file" ]] || die "Compose file not found: $file"
  file_dir="$(cd "$(dirname "$file")" && pwd -P)" || die "Unable to access compose project directory: $(dirname "$file")"
  cb="$(compose_bin)" || die "docker compose не найден"
  if [[ "$cb" == "docker compose" ]]; then
    docker compose --project-directory "$file_dir" -f "$file" "$@"
  else
    docker-compose --project-directory "$file_dir" -f "$file" "$@"
  fi
}

compose_try_logged() {
  local file="$1"; shift
  local tmp rc
  local message="docker compose failed for ${file}"

  [[ -n "$file" ]] || die "Compose file path is empty"
  [[ -f "$file" ]] || die "Compose file not found: $file"
  tmp="$(mktemp)" || die "Failed to create temporary file for docker compose output"
  if compose_run "$file" "$@" >"$tmp" 2>&1; then
    if [[ -n "${INSTALL_LOG_FILE:-}" ]]; then
      cat "$tmp" >>"$INSTALL_LOG_FILE" 2>/dev/null || true
    else
      cat "$tmp"
    fi
    rm -f "$tmp"
    return 0
  fi

  rc=$?
  if [[ $# -gt 0 ]]; then
    message="${message} (args: $*)"
  fi
  if [[ -n "${INSTALL_LOG_FILE:-}" ]]; then
    cat "$tmp" >>"$INSTALL_LOG_FILE" 2>/dev/null || true
    message="${message}. Details were appended to ${INSTALL_LOG_FILE}"
  fi

  err "$message"
  if [[ -s "$tmp" ]]; then
    sed -n '1,120p' "$tmp" >&2 || true
  fi
  if [[ ! -t 2 && -t 4 ]]; then
    printf '%s [ERROR] %s\n' "$(ts)" "$message" >&4
    if [[ -s "$tmp" ]]; then
      sed -n '1,120p' "$tmp" >&4 || true
    fi
  fi
  rm -f "$tmp"
  return "$rc"
}

compose_must_logged() {
  local file="$1"; shift

  if compose_try_logged "$file" "$@"; then
    return 0
  fi

  if [[ -n "${INSTALL_LOG_FILE:-}" ]]; then
    die "docker compose command failed. See ${INSTALL_LOG_FILE}"
  fi
  die "docker compose command failed"
}

compose_nginx() { compose_run "$COMPOSE_FILE" "$@"; }
compose_node() { compose_run "$REMNANODE_COMPOSE_FILE" "$@"; }

cert_fullchain_path() {
  local domain="$1"
  echo "$CERTS_DIR/${domain}_fullchain.pem"
}

cert_privkey_path() {
  local domain="$1"
  echo "$CERTS_DIR/${domain}_privkey.key"
}

load_saved_config() {
  local legacy_config=""
  local legacy_base_config="$LEGACY_BASE_DIR/config.env"
  local legacy_acme_home="$LEGACY_BASE_DIR/.acme.sh"
  local migrated_default_acme_home=""

  if [[ -f "$CONFIG_FILE" ]]; then
    load_installer_env_file "$CONFIG_FILE" override
  elif [[ -z "${EXPLICIT_INPUT_VARS[CONFIG_FILE]+x}" && -f "$SCRIPT_DIR/config.env" ]]; then
    legacy_config="$SCRIPT_DIR/config.env"
    warn "Using legacy config from $legacy_config; it will be migrated to $CONFIG_FILE on next save"
    load_installer_env_file "$legacy_config" override
  elif [[ -z "${EXPLICIT_INPUT_VARS[CONFIG_FILE]+x}" && -f "$legacy_base_config" ]]; then
    legacy_config="$legacy_base_config"
    warn "Using legacy config from $legacy_config; it will be migrated to $CONFIG_FILE on next save"
    load_installer_env_file "$legacy_config" override
  fi

  if [[ -n "$legacy_config" ]]; then
    if [[ -z "${EXPLICIT_INPUT_VARS[BASE_DIR]+x}" && "$BASE_DIR" == "$LEGACY_BASE_DIR" ]]; then
      BASE_DIR="$DEFAULT_BASE_DIR"
    fi
  fi

  if [[ -z "${EXPLICIT_INPUT_VARS[ACME_HOME]+x}" ]]; then
    migrated_default_acme_home="$BASE_DIR/.acme.sh"
    if [[ -z "$ACME_HOME" || "$ACME_HOME" == "$legacy_acme_home" || "$ACME_HOME" == "$LEGACY_ACME_HOME_DEFAULT" ]]; then
      [[ "$ACME_HOME" == "$LEGACY_ACME_HOME_DEFAULT" ]] && warn "Migrating ACME_HOME from $LEGACY_ACME_HOME_DEFAULT to $migrated_default_acme_home"
      ACME_HOME="$migrated_default_acme_home"
    fi
  fi

  load_installer_env_file "$SCRIPT_ENV_FILE" override
}

load_node_env_if_exists() {
  if [[ -f "$REMNANODE_ENV_FILE" ]]; then
    while IFS='=' read -r key value; do
      [[ -n "$key" ]] || continue
      case "$key" in
        SECRET_KEY) SECRET_KEY="${SECRET_KEY:-$value}" ;;
        NODE_PORT) NODE_PORT="${NODE_PORT:-$value}" ;;
        SSL_CERT) SSL_CERT="${SSL_CERT:-$value}" ;;
      esac
    done < <(grep -E '^(SECRET_KEY|NODE_PORT|SSL_CERT)=' "$REMNANODE_ENV_FILE" || true)
  fi
}

normalize_panel_domain() {
  local domain="$1"
  domain="${domain#http://}"
  domain="${domain#https://}"
  domain="${domain%/}"
  printf '%s' "$domain"
}

apt_get_retry() {
  local timeout="${APT_LOCK_TIMEOUT:-600}"
  local interval="${APT_LOCK_RETRY_INTERVAL:-5}"
  local waited=0
  local log_emitted=0
  local tmp rc

  while true; do
    tmp="$(mktemp)"
    if apt-get -o Dpkg::Use-Pty=0 "$@" >"$tmp" 2>&1; then
      rm -f "$tmp"
      return 0
    fi

    rc=$?
    if grep -qiE 'Could not get lock|Unable to acquire the dpkg frontend lock|Could not open lock file|Unable to lock directory|is another process using it' "$tmp"; then
      if (( log_emitted == 0 )); then
        warn "apt/dpkg сейчас занят другим процессом. Жду освобождения блокировки до ${timeout} сек"
        log_emitted=1
      elif (( waited > 0 && waited % 30 == 0 )); then
        log "Все еще жду освобождения apt/dpkg... прошло ${waited} сек"
      fi

      if (( waited >= timeout )); then
        sed -n '1,120p' "$tmp" >&2 || true
        rm -f "$tmp"
        die "Не удалось дождаться освобождения apt/dpkg за ${timeout} сек. Обычно это unattended-upgrades. Повтори запуск позже"
      fi

      rm -f "$tmp"
      sleep "$interval"
      waited=$((waited + interval))
      continue
    fi

    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    return "$rc"
  done
}

ensure_panel_api_tools() {
  local missing=()
  have_cmd curl || missing+=("curl")
  have_cmd jq || missing+=("jq")

  ((${#missing[@]} == 0)) && return 0

  log "Устанавливаю инструменты для работы с API панели: ${missing[*]}"

  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt_get_retry update -y >/dev/null
    apt_get_retry install -y curl jq ca-certificates >/dev/null
  elif have_cmd dnf; then
    dnf install -y curl jq ca-certificates >/dev/null
  elif have_cmd yum; then
    yum install -y curl jq ca-certificates >/dev/null
  else
    die "Неизвестный пакетный менеджер. Не могу установить curl/jq для работы с API панели"
  fi

  have_cmd curl || die "curl не найден после установки"
  have_cmd jq || die "jq не найден после установки"
}

panel_base_url() {
  PANEL_DOMAIN="$(normalize_panel_domain "$PANEL_DOMAIN")"
  printf 'https://%s' "$PANEL_DOMAIN"
}

panel_api_request() {
  local method="$1"
  local path="$2"
  local payload="${3:-}"
  local url response http_code body error_message

  [[ -n "$PANEL_API_TOKEN" ]] || die "PANEL_API_TOKEN не задан"
  url="$(panel_base_url)$path"

  if [[ -n "$payload" ]]; then
    response="$(
      curl -sS \
        -X "$method" \
        -H "Authorization: Bearer $PANEL_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "$payload" \
        -w $'\n%{http_code}' \
        "$url"
    )" || die "Не удалось выполнить ${method} ${url}"
  else
    response="$(
      curl -sS \
        -X "$method" \
        -H "Authorization: Bearer $PANEL_API_TOKEN" \
        -w $'\n%{http_code}' \
        "$url"
    )" || die "Не удалось выполнить ${method} ${url}"
  fi

  http_code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  if [[ ! "$http_code" =~ ^2 ]]; then
    error_message="$(printf '%s' "$body" | jq -r '.message // .error // (.errors[0].message // empty)' 2>/dev/null || true)"
    [[ -n "$error_message" && "$error_message" != "null" ]] || error_message="$body"
    die "API панели вернул HTTP ${http_code} для ${method} ${path}: ${error_message}"
  fi

  printf '%s' "$body"
}

derived_panel_node_name() {
  local base=""
  if ((${#DOMAINS_ARR[@]} > 0)); then
    base="${DOMAINS_ARR[0]%%.*}"
  else
    base="$(hostname -s 2>/dev/null || echo node)"
  fi
  base="${base^^}"
  base="${base//[^A-Z0-9_-]/-}"
  printf '%s' "${base:-NODE}"
}

default_panel_node_name() {
  if [[ -n "$PANEL_NODE_NAME" ]]; then
    printf '%s' "$PANEL_NODE_NAME"
    return 0
  fi
  derived_panel_node_name
}

derived_panel_node_address() {
  if ((${#DOMAINS_ARR[@]} > 0)); then
    printf '%s' "${DOMAINS_ARR[0]}"
    return 0
  fi
  printf '%s' ""
}

default_panel_node_address() {
  if [[ -n "$PANEL_NODE_ADDRESS" ]]; then
    printf '%s' "$PANEL_NODE_ADDRESS"
    return 0
  fi
  derived_panel_node_address
}

default_panel_country_code() {
  local domain="${1:-}"
  local label

  if [[ -n "$PANEL_NODE_COUNTRY_CODE" && "$PANEL_NODE_COUNTRY_CODE" != "XX" ]]; then
    printf '%s' "${PANEL_NODE_COUNTRY_CODE^^}"
    return 0
  fi

  label="${domain%%.*}"
  label="${label,,}"
  if [[ "$label" =~ ^([a-z]{2})[a-z0-9-]*$ ]]; then
    printf '%s' "${BASH_REMATCH[1]^^}"
  else
    printf 'XX'
  fi
}

apply_domain_defaults() {
  if ((${#DOMAINS_ARR[@]} == 0)); then
    return 0
  fi

  PANEL_NODE_NAME="${PANEL_NODE_NAME:-$(derived_panel_node_name)}"
  PANEL_NODE_ADDRESS="${PANEL_NODE_ADDRESS:-$(derived_panel_node_address)}"
  PANEL_NODE_COUNTRY_CODE="$(default_panel_country_code "${DOMAINS_ARR[0]}")"
  PANEL_ACTIVE_INBOUND_UUIDS="${PANEL_ACTIVE_INBOUND_UUIDS//,/ }"
}

panel_fetch_keygen_secret() {
  local json
  json="$(panel_api_request GET '/api/keygen')"
  SECRET_KEY="$(printf '%s' "$json" | jq -r '.response.pubKey // empty')"
  [[ -n "$SECRET_KEY" && "$SECRET_KEY" != "null" ]] || die "Панель не вернула Secret Key для ноды"
  log "Secret Key ноды получен из панели: $(mask_secret "$SECRET_KEY") (${#SECRET_KEY} символов)"
}

panel_fetch_config_profiles() {
  panel_api_request GET '/api/config-profiles'
}

prompt_panel_config_profile() {
  local profiles_json="$1"
  local total profile_index

  total="$(printf '%s' "$profiles_json" | jq -r '.response.configProfiles | length')"
  [[ "$total" =~ ^[0-9]+$ ]] || die "Не удалось разобрать список config profiles из панели"
  (( total > 0 )) || die "В панели нет config profiles. Сначала создай профиль в панели"

  if [[ -n "$PANEL_CONFIG_PROFILE_UUID" ]]; then
    profile_index="$(printf '%s' "$profiles_json" | jq -r --arg uuid "$PANEL_CONFIG_PROFILE_UUID" '.response.configProfiles | map(.uuid) | index($uuid)')"
    [[ "$profile_index" =~ ^[0-9]+$ ]] || die "PANEL_CONFIG_PROFILE_UUID не найден в панели: ${PANEL_CONFIG_PROFILE_UUID}"
  else
    (( total == 1 )) || die "Задай PANEL_CONFIG_PROFILE_UUID в ${SCRIPT_ENV_FILE}"
    profile_index="0"
    PANEL_CONFIG_PROFILE_UUID="$(printf '%s' "$profiles_json" | jq -r '.response.configProfiles[0].uuid')"
  fi

  PANEL_CONFIG_PROFILE_NAME="$(printf '%s' "$profiles_json" | jq -r ".response.configProfiles[$profile_index].name")"
  log "Config profile выбран из ${SCRIPT_ENV_FILE}: ${PANEL_CONFIG_PROFILE_NAME} (${PANEL_CONFIG_PROFILE_UUID})"
}

prompt_panel_active_inbounds() {
  local profiles_json="$1"
  local profile_index_json="$2"
  local total inbound_uuid idx
  local -a selected_uuids=()
  local -A seen=()

  total="$(printf '%s' "$profiles_json" | jq -r ".response.configProfiles[$profile_index_json].inbounds | length")"
  [[ "$total" =~ ^[0-9]+$ ]] || die "Не удалось разобрать список inbound'ов из панели"
  (( total > 0 )) || die "У выбранного config profile нет inbound'ов"

  if [[ -n "$PANEL_ACTIVE_INBOUND_UUIDS" ]]; then
    read -r -a selected_uuids <<< "${PANEL_ACTIVE_INBOUND_UUIDS//,/ }"
    for inbound_uuid in "${selected_uuids[@]}"; do
      idx="$(printf '%s' "$profiles_json" | jq -r --arg uuid "$inbound_uuid" ".response.configProfiles[$profile_index_json].inbounds | map(.uuid) | index(\$uuid)")"
      [[ "$idx" =~ ^[0-9]+$ ]] || die "Inbound UUID не найден в выбранном config profile: ${inbound_uuid}"
      [[ -n "${seen[$inbound_uuid]+x}" ]] && continue
      seen[$inbound_uuid]=1
    done
  else
    (( total == 1 )) || die "Задай PANEL_ACTIVE_INBOUND_UUIDS в ${SCRIPT_ENV_FILE}"
    inbound_uuid="$(printf '%s' "$profiles_json" | jq -r ".response.configProfiles[$profile_index_json].inbounds[0].uuid")"
    [[ -n "$inbound_uuid" && "$inbound_uuid" != "null" ]] || die "Не удалось получить UUID единственного inbound'а"
    selected_uuids=("$inbound_uuid")
  fi

  ((${#selected_uuids[@]} > 0)) || die "Нужно выбрать хотя бы один inbound"
  PANEL_ACTIVE_INBOUND_UUIDS="${selected_uuids[*]}"
  log "Inbound UUID для панели: ${PANEL_ACTIVE_INBOUND_UUIDS}"
}

prompt_panel_node_registration_settings() {
  local profiles_json profile_index_json

  ensure_panel_api_tools

  PANEL_DOMAIN="$(normalize_panel_domain "$PANEL_DOMAIN")"
  apply_domain_defaults

  PANEL_NODE_NAME="${PANEL_NODE_NAME:-$(default_panel_node_name)}"
  [[ ${#PANEL_NODE_NAME} -ge 3 && ${#PANEL_NODE_NAME} -le 30 ]] || die "Имя ноды должно быть длиной от 3 до 30 символов"
  PANEL_NODE_ADDRESS="${PANEL_NODE_ADDRESS:-$(default_panel_node_address)}"
  [[ -n "$PANEL_NODE_ADDRESS" ]] || die "Публичный адрес ноды не может быть пустым"
  PANEL_NODE_COUNTRY_CODE="$(default_panel_country_code "$PANEL_NODE_ADDRESS")"
  [[ "$PANEL_NODE_COUNTRY_CODE" =~ ^[A-Z]{2}$ ]] || die "Не удалось определить PANEL_NODE_COUNTRY_CODE по домену ${PANEL_NODE_ADDRESS}"

  log "Проверяю доступ к панели ${PANEL_DOMAIN} через API"
  panel_fetch_keygen_secret
  profiles_json="$(panel_fetch_config_profiles)"

  prompt_panel_config_profile "$profiles_json"
  profile_index_json="$(printf '%s' "$profiles_json" | jq -r --arg uuid "$PANEL_CONFIG_PROFILE_UUID" '.response.configProfiles | map(.uuid) | index($uuid)')"
  [[ "$profile_index_json" =~ ^[0-9]+$ ]] || die "Не удалось найти выбранный config profile в ответе панели"
  prompt_panel_active_inbounds "$profiles_json" "$profile_index_json"

  log "Параметры регистрации ноды подготовлены: панель=${PANEL_DOMAIN}, нода=${PANEL_NODE_NAME}, адрес=${PANEL_NODE_ADDRESS}, порт=${NODE_PORT}, профиль=${PANEL_CONFIG_PROFILE_NAME}"
}

panel_inbounds_json() {
  local -a inbound_uuids=()
  read -r -a inbound_uuids <<< "$PANEL_ACTIVE_INBOUND_UUIDS"
  printf '%s\n' "${inbound_uuids[@]}" | jq -R . | jq -s .
}

panel_find_existing_node_uuid() {
  local nodes_json="$1"
  local existing matches count line found_uuid

  if [[ -n "$PANEL_NODE_UUID" ]]; then
    existing="$(printf '%s' "$nodes_json" | jq -r --arg uuid "$PANEL_NODE_UUID" '.response[] | select(.uuid == $uuid) | .uuid' | head -n1)"
    if [[ -n "$existing" ]]; then
      printf '%s' "$existing"
      return 0
    fi
    warn "Сохранённая PANEL_NODE_UUID больше не найдена в панели, пробую найти ноду по имени или адресу"
  fi

  matches="$(printf '%s' "$nodes_json" | jq -r --arg name "$PANEL_NODE_NAME" --arg address "$PANEL_NODE_ADDRESS" '[.response[] | select(.name == $name or .address == $address) | .uuid] | unique | .[]')"
  count=0
  found_uuid=""
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    found_uuid="$line"
    count=$((count + 1))
  done <<< "$matches"

  if (( count > 1 )); then
    die "В панели найдено несколько нод с таким именем или адресом. Очисти дубликаты или задай другое имя ноды"
  fi

  printf '%s' "$found_uuid"
}

ensure_panel_node_registered() {
  local nodes_json existing_uuid inbounds_json payload response

  [[ "$AUTO_INSTALL_NODE" =~ ^(1|yes|true)$ ]] || return 0
  [[ "$PANEL_AUTO_REGISTER_NODE" =~ ^(1|yes|true)$ ]] || return 0

  ensure_panel_api_tools
  panel_fetch_keygen_secret
  [[ -n "$PANEL_NODE_NAME" ]] || die "Имя ноды для панели не задано"
  [[ -n "$PANEL_NODE_ADDRESS" ]] || die "Публичный адрес ноды для панели не задан"
  [[ -n "$PANEL_CONFIG_PROFILE_UUID" ]] || die "UUID config profile для панели не задан"
  [[ -n "$PANEL_ACTIVE_INBOUND_UUIDS" ]] || die "Inbound'ы для панели не заданы"

  nodes_json="$(panel_api_request GET '/api/nodes')"
  existing_uuid="$(panel_find_existing_node_uuid "$nodes_json")"
  inbounds_json="$(panel_inbounds_json)"

  if [[ -n "$existing_uuid" ]]; then
    payload="$(jq -cn \
      --arg uuid "$existing_uuid" \
      --arg name "$PANEL_NODE_NAME" \
      --arg address "$PANEL_NODE_ADDRESS" \
      --arg countryCode "$PANEL_NODE_COUNTRY_CODE" \
      --arg profileUuid "$PANEL_CONFIG_PROFILE_UUID" \
      --argjson port "$NODE_PORT" \
      --argjson inbounds "$inbounds_json" \
      --argjson isTrafficTrackingActive false \
      --argjson consumptionMultiplier 1 \
      '{
        uuid: $uuid,
        name: $name,
        address: $address,
        port: $port,
        countryCode: $countryCode,
        isTrafficTrackingActive: $isTrafficTrackingActive,
        consumptionMultiplier: $consumptionMultiplier,
        configProfile: {
          activeConfigProfileUuid: $profileUuid,
          activeInbounds: $inbounds
        }
      }'
    )"
    response="$(panel_api_request PATCH '/api/nodes' "$payload")"
    PANEL_NODE_UUID="$(printf '%s' "$response" | jq -r '.response.uuid // empty')"
    ok "Нода обновлена в панели: ${PANEL_NODE_NAME} (${PANEL_NODE_UUID})"
  else
    payload="$(jq -cn \
      --arg name "$PANEL_NODE_NAME" \
      --arg address "$PANEL_NODE_ADDRESS" \
      --arg countryCode "$PANEL_NODE_COUNTRY_CODE" \
      --arg profileUuid "$PANEL_CONFIG_PROFILE_UUID" \
      --arg providerUuid "$PANEL_PROVIDER_UUID" \
      --argjson port "$NODE_PORT" \
      --argjson inbounds "$inbounds_json" \
      --argjson isTrafficTrackingActive false \
      --argjson consumptionMultiplier 1 \
      '{
        name: $name,
        address: $address,
        port: $port,
        countryCode: $countryCode,
        isTrafficTrackingActive: $isTrafficTrackingActive,
        consumptionMultiplier: $consumptionMultiplier,
        configProfile: {
          activeConfigProfileUuid: $profileUuid,
          activeInbounds: $inbounds
        }
      } + (if ($providerUuid | length) > 0 then { providerUuid: $providerUuid } else {} end)'
    )"
    response="$(panel_api_request POST '/api/nodes' "$payload")"
    PANEL_NODE_UUID="$(printf '%s' "$response" | jq -r '.response.uuid // empty')"
    ok "Нода создана в панели: ${PANEL_NODE_NAME} (${PANEL_NODE_UUID})"
  fi

  [[ -n "$PANEL_NODE_UUID" && "$PANEL_NODE_UUID" != "null" ]] || die "Панель не вернула UUID ноды после регистрации"
  save_config
}

is_valid_domain() {
  local domain="$1" label
  (( ${#domain} >= 1 && ${#domain} <= 253 )) || return 1
  [[ "$domain" == *.* ]] || return 1
  [[ "$domain" != .* && "$domain" != *. ]] || return 1
  [[ "$domain" != *..* ]] || return 1

  IFS='.' read -r -a _labels <<< "$domain"
  for label in "${_labels[@]}"; do
    (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
    [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
  done
  return 0
}

normalize_domains() {
  local raw="$1"
  local token
  local -A seen=()
  DOMAINS_ARR=()

  raw="${raw//,/ }"
  raw="${raw//$'\r'/ }"
  raw="${raw//$'\n'/ }"

  for token in $raw; do
    token="${token,,}"
    token="${token#.}"
    token="${token%.}"
    [[ -n "$token" ]] || continue
    [[ "$token" != \*.* ]] || die "Wildcard-домены не поддерживаются в режиме HTTP-01/webroot: $token"
    is_valid_domain "$token" || die "Некорректный домен: $token"
    [[ -z "${seen[$token]+x}" ]] || continue
    seen[$token]=1
    DOMAINS_ARR+=("$token")
  done

  ((${#DOMAINS_ARR[@]} > 0)) || die "Нужно указать хотя бы один домен"
  DOMAINS="${DOMAINS_ARR[*]}"
}

rebuild_runtime_paths() {
  WWW_DIR="${WWW_DIR:-$BASE_DIR/www}"
  ACME_WEBROOT="${ACME_WEBROOT:-$BASE_DIR/acme}"
  CERTS_DIR="${CERTS_DIR:-$BASE_DIR/certs}"
  SCRIPTS_DIR="${SCRIPTS_DIR:-$BASE_DIR/scripts}"
  COMPOSE_FILE="${COMPOSE_FILE:-$BASE_DIR/docker-compose.yml}"
  NGINX_CONF="${NGINX_CONF:-$BASE_DIR/nginx.conf}"
  INDEX_FILE="${INDEX_FILE:-$WWW_DIR/index.html}"
  RELOAD_HELPER="${RELOAD_HELPER:-$SCRIPTS_DIR/reload_hook.sh}"
  NGINX_LOG_DIR="${NGINX_LOG_DIR:-$BASE_DIR/logs}"
  INSTALL_LOG_FILE="${INSTALL_LOG_FILE:-$NGINX_LOG_DIR/install.log}"
  ACME_HOME="${ACME_HOME:-$BASE_DIR/.acme.sh}"
  ACME="$ACME_HOME/acme.sh"
  NGINX_ACCESS_LOG="$NGINX_LOG_DIR/access.log"
  NGINX_ERROR_LOG="$NGINX_LOG_DIR/error.log"
  if [[ -n "${SITE_SOURCE_DIR:-}" ]]; then
    SITE_SOURCE_DIR="$SITE_SOURCE_DIR"
  elif [[ -d "$SCRIPT_DIR/dist" ]]; then
    SITE_SOURCE_DIR="$SCRIPT_DIR/dist"
  elif [[ -d "$SCRIPT_DIR/site" ]]; then
    SITE_SOURCE_DIR="$SCRIPT_DIR/site"
  else
    SITE_SOURCE_DIR="$SCRIPT_DIR/dist"
  fi

  if [[ -z "$ACME_EMAIL" && ${#DOMAINS_ARR[@]} -gt 0 ]]; then
    ACME_EMAIL="admin@${DOMAINS_ARR[0]}"
  fi

  validate_path_value "BASE_DIR" "$BASE_DIR"
  validate_path_value "CONFIG_FILE" "$CONFIG_FILE"
  validate_path_value "ACME_HOME" "$ACME_HOME"
  validate_path_value "WWW_DIR" "$WWW_DIR"
  validate_path_value "ACME_WEBROOT" "$ACME_WEBROOT"
  validate_path_value "CERTS_DIR" "$CERTS_DIR"
  validate_path_value "SCRIPTS_DIR" "$SCRIPTS_DIR"
  validate_path_value "COMPOSE_FILE" "$COMPOSE_FILE"
  validate_path_value "NGINX_CONF" "$NGINX_CONF"
  validate_path_value "INDEX_FILE" "$INDEX_FILE"
  validate_path_value "RELOAD_HELPER" "$RELOAD_HELPER"
  validate_path_value "NGINX_LOG_DIR" "$NGINX_LOG_DIR"
  validate_path_value "INSTALL_LOG_FILE" "$INSTALL_LOG_FILE"
  validate_path_value "REMNANODE_DIR" "$REMNANODE_DIR"
  validate_path_value "REMNANODE_COMPOSE_FILE" "$REMNANODE_COMPOSE_FILE"
  validate_path_value "REMNANODE_ENV_FILE" "$REMNANODE_ENV_FILE"
  validate_path_value "REMNANODE_LOG_DIR" "$REMNANODE_LOG_DIR"
  validate_path_value "REMNANODE_LOGROTATE_FILE" "$REMNANODE_LOGROTATE_FILE"
  validate_path_value "FAIL2BAN_JAIL_FILE" "$FAIL2BAN_JAIL_FILE"
  validate_path_value "FAIL2BAN_FILTER_FILE" "$FAIL2BAN_FILTER_FILE"
  validate_path_value "FAIL2BAN_LOCAL_FILE" "$FAIL2BAN_LOCAL_FILE"
}

prepare_domains_from_runtime() {
  if [[ -n "$EXTRA_INSTALL_DOMAINS" ]]; then
    normalize_domains "$EXTRA_INSTALL_DOMAINS"
  elif [[ -n "$DOMAINS" ]]; then
    normalize_domains "$DOMAINS"
  else
    die "Домены не настроены"
  fi
  rebuild_runtime_paths
}

prompt_if_needed_for_install() {
  local input

  if [[ -z "$EXTRA_INSTALL_DOMAINS" && -z "$DOMAINS" ]]; then
    if ! stdin_is_tty; then
      die "Укажи домен при старте скрипта или задай DOMAINS в ${SCRIPT_ENV_FILE}"
    fi
    prompt_input input "Domain (через пробел): " "" || die "Не удалось прочитать домены"
    [[ -n "$input" ]] || die "Нужно указать хотя бы один домен"
    EXTRA_INSTALL_DOMAINS="$input"
  fi

  prepare_domains_from_runtime
  apply_domain_defaults
  ACME_EMAIL="${ACME_EMAIL:-admin@${DOMAINS_ARR[0]}}"
  rebuild_runtime_paths
}

prompt_install_docker_if_missing() {
  if have_cmd docker; then
    AUTO_INSTALL_DOCKER=0
    return 0
  fi

  warn "Docker не найден, запускаю автоматическую установку"
  AUTO_INSTALL_DOCKER=1
}

prompt_node_settings() {
  load_node_env_if_exists

  if [[ "$AUTO_INSTALL_NODE" =~ ^(0|no|false)$ ]]; then
    AUTO_INSTALL_NODE=0
    warn "Установка remnanode отключена через AUTO_INSTALL_NODE"
    return 0
  else
    AUTO_INSTALL_NODE=1
  fi

  [[ "$NODE_PORT" =~ ^[0-9]+$ ]] || die "Порт remnanode должен быть числом"
  (( NODE_PORT >= 1 && NODE_PORT <= 65535 )) || die "Порт remnanode должен быть в диапазоне 1..65535"

  if [[ "$PANEL_AUTO_REGISTER_NODE" =~ ^(1|yes|true)$ && -n "$PANEL_DOMAIN" && -n "$PANEL_API_TOKEN" ]]; then
    log "Регистрация ноды в панели включена. Secret Key будет получен автоматически из панели"
    prompt_panel_node_registration_settings
    return 0
  fi

  [[ -n "$SECRET_KEY" ]] || die "Задай SECRET_KEY в ${SCRIPT_ENV_FILE} или включи PANEL_AUTO_REGISTER_NODE=1"
  log "Secret Key ноды сохранён вручную: $(mask_secret "$SECRET_KEY") (${#SECRET_KEY} символов)"

}

save_config() {
  mkdir -p "$BASE_DIR"
  cat > "$CONFIG_FILE" <<CFG
BASE_DIR=$(quote_config_value "$BASE_DIR")
CONTAINER_NAME=$(quote_config_value "$CONTAINER_NAME")
NGINX_IMAGE=$(quote_config_value "$NGINX_IMAGE")
ACME_HOME=$(quote_config_value "$ACME_HOME")
ACME_KEYLENGTH=$(quote_config_value "$ACME_KEYLENGTH")
LE_SERVER=$(quote_config_value "$LE_SERVER")
ACME_EMAIL=$(quote_config_value "$ACME_EMAIL")
DOMAINS=$(quote_config_value "$DOMAINS")
REMNANODE_DIR=$(quote_config_value "$REMNANODE_DIR")
REMNANODE_CONTAINER_NAME=$(quote_config_value "$REMNANODE_CONTAINER_NAME")
REMNANODE_SERVICE_NAME=$(quote_config_value "$REMNANODE_SERVICE_NAME")
REMNANODE_IMAGE=$(quote_config_value "$REMNANODE_IMAGE")
NODE_PORT=$(quote_config_value "$NODE_PORT")
PANEL_DOMAIN=$(quote_config_value "$PANEL_DOMAIN")
PANEL_API_TOKEN=$(quote_config_value "$PANEL_API_TOKEN")
PANEL_AUTO_REGISTER_NODE=$(quote_config_value "$PANEL_AUTO_REGISTER_NODE")
PANEL_NODE_UUID=$(quote_config_value "$PANEL_NODE_UUID")
PANEL_NODE_NAME=$(quote_config_value "$PANEL_NODE_NAME")
PANEL_NODE_ADDRESS=$(quote_config_value "$PANEL_NODE_ADDRESS")
PANEL_NODE_COUNTRY_CODE=$(quote_config_value "$PANEL_NODE_COUNTRY_CODE")
PANEL_CONFIG_PROFILE_UUID=$(quote_config_value "$PANEL_CONFIG_PROFILE_UUID")
PANEL_CONFIG_PROFILE_NAME=$(quote_config_value "$PANEL_CONFIG_PROFILE_NAME")
PANEL_ACTIVE_INBOUND_UUIDS=$(quote_config_value "$PANEL_ACTIVE_INBOUND_UUIDS")
PANEL_PROVIDER_UUID=$(quote_config_value "$PANEL_PROVIDER_UUID")
SSL_CERT=$(quote_config_value "$SSL_CERT")
AUTO_INSTALL_NODE=$(quote_config_value "$AUTO_INSTALL_NODE")
REMNANODE_LOG_DIR=$(quote_config_value "$REMNANODE_LOG_DIR")
REMNANODE_LOGROTATE_FILE=$(quote_config_value "$REMNANODE_LOGROTATE_FILE")
REMNANODE_LOGROTATE_SIZE=$(quote_config_value "$REMNANODE_LOGROTATE_SIZE")
REMNANODE_LOGROTATE_ROTATE=$(quote_config_value "$REMNANODE_LOGROTATE_ROTATE")
DOCKER_LOG_MAX_SIZE=$(quote_config_value "$DOCKER_LOG_MAX_SIZE")
DOCKER_LOG_MAX_FILE=$(quote_config_value "$DOCKER_LOG_MAX_FILE")
NGINX_LOG_DIR=$(quote_config_value "$NGINX_LOG_DIR")
INSTALL_LOG_FILE=$(quote_config_value "$INSTALL_LOG_FILE")
FAIL2BAN_JAIL_FILE=$(quote_config_value "$FAIL2BAN_JAIL_FILE")
FAIL2BAN_FILTER_FILE=$(quote_config_value "$FAIL2BAN_FILTER_FILE")
FAIL2BAN_LOCAL_FILE=$(quote_config_value "$FAIL2BAN_LOCAL_FILE")
FAIL2BAN_IGNORE_IPS=$(quote_config_value "$FAIL2BAN_IGNORE_IPS")
FAIL2BAN_SSH_BANTIME=$(quote_config_value "$FAIL2BAN_SSH_BANTIME")
FAIL2BAN_SSH_FINDTIME=$(quote_config_value "$FAIL2BAN_SSH_FINDTIME")
FAIL2BAN_SSH_MAXRETRY=$(quote_config_value "$FAIL2BAN_SSH_MAXRETRY")
FAIL2BAN_NGINX_BANTIME=$(quote_config_value "$FAIL2BAN_NGINX_BANTIME")
FAIL2BAN_NGINX_FINDTIME=$(quote_config_value "$FAIL2BAN_NGINX_FINDTIME")
FAIL2BAN_NGINX_MAXRETRY=$(quote_config_value "$FAIL2BAN_NGINX_MAXRETRY")
FAIL2BAN_RECIDIVE_BANTIME=$(quote_config_value "$FAIL2BAN_RECIDIVE_BANTIME")
FAIL2BAN_RECIDIVE_FINDTIME=$(quote_config_value "$FAIL2BAN_RECIDIVE_FINDTIME")
FAIL2BAN_RECIDIVE_MAXRETRY=$(quote_config_value "$FAIL2BAN_RECIDIVE_MAXRETRY")
CFG
  chmod 600 "$CONFIG_FILE"
  ok "Конфигурация сохранена: $CONFIG_FILE"
}

install_packages() {
  log "Checking and installing system dependencies"
  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt_get_retry update -y >/dev/null
    apt_get_retry install -y curl jq ca-certificates openssl socat iptables iproute2 logrotate fail2ban tar >/dev/null
  elif have_cmd dnf; then
    dnf install -y curl jq ca-certificates openssl socat iptables iproute logrotate fail2ban tar >/dev/null
  elif have_cmd yum; then
    yum install -y curl jq ca-certificates openssl socat iptables iproute logrotate fail2ban tar >/dev/null
  else
    die "Неизвестный пакетный менеджер. Поддерживаются: apt, dnf, yum"
  fi
  ok "Системные зависимости готовы"
}

ensure_docker_compose_plugin() {
  compose_bin >/dev/null 2>&1 && return 0

  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt_get_retry install -y docker-compose-plugin >/dev/null 2>&1 || true
  elif have_cmd dnf; then
    dnf install -y docker-compose-plugin >/dev/null 2>&1 || true
  elif have_cmd yum; then
    yum install -y docker-compose-plugin >/dev/null 2>&1 || true
  fi

  compose_bin >/dev/null 2>&1 || die "docker compose не найден"
}

ensure_docker_service_ready() {
  have_cmd systemctl || die "systemctl is required to manage Docker"
  have_cmd docker || die "Docker CLI is not installed"

  systemctl enable docker.service docker.socket >/dev/null 2>&1 || true

  if ! systemctl is-active --quiet docker.service; then
    log "docker.service is not active; starting it"
    if have_cmd timeout; then
      timeout 60 systemctl start docker.service || die "Docker service failed or timed out while starting"
    else
      systemctl start docker.service || die "Docker service failed to start"
    fi
  fi

  if have_cmd timeout; then
    timeout 20 docker info >/dev/null 2>&1 || die "Docker API is not responding"
  else
    docker info >/dev/null 2>&1 || die "Docker API is not responding"
  fi
}

install_docker_if_missing() {
  if have_cmd docker; then
    ensure_docker_compose_plugin
    ensure_docker_service_ready
    return 0
  fi

  warn "Docker не найден"

  AUTO_INSTALL_DOCKER=1
  log "Устанавливаю Docker автоматически"

  local docker_install_log="/tmp/remnawave-docker-install.log"

  if ! curl -fsSL https://get.docker.com | sh >"$docker_install_log" 2>&1; then
    [[ -s "$docker_install_log" ]] && sed -n '1,200p' "$docker_install_log"
    die "Не удалось установить Docker"
  fi
  have_cmd docker || die "Не удалось установить Docker"
  ensure_docker_compose_plugin
  ensure_docker_service_ready
  ok "Docker установлен"
}

install_docker_if_missing() {
  local docker_install_log="/tmp/remnawave-docker-install.log"
  local docker_install_script="/tmp/remnawave-get-docker.sh"

  if have_cmd docker; then
    ensure_docker_compose_plugin
    ensure_docker_service_ready
    return 0
  fi

  AUTO_INSTALL_DOCKER=1
  log "Installing Docker automatically"

  if ! curl -fsSL https://get.docker.com -o "$docker_install_script"; then
    die "Failed to download Docker install script"
  fi

  if ! sh "$docker_install_script" >"$docker_install_log" 2>&1; then
    [[ -s "$docker_install_log" ]] && sed -n '1,200p' "$docker_install_log"
    rm -f "$docker_install_script"
    die "Failed to install Docker"
  fi

  rm -f "$docker_install_script"
  have_cmd docker || die "Docker binary not found after install"
  ensure_docker_compose_plugin
  ensure_docker_service_ready
  ok "Docker installed"
}

repair_legacy_lockdown_unit() {
  have_cmd systemctl || return 0
  [[ -f "$SERVICE_LOCKDOWN" ]] || return 0

  if ! grep -Eq '^[[:space:]]*Before=docker\.service([[:space:]]|$)' "$SERVICE_LOCKDOWN"; then
    return 0
  fi

  warn "Detected legacy remnawave port-80 unit with Before=docker.service; repairing it before Docker startup"

  systemctl stop --no-block remnawave-port80-lockdown.service >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5; do
    if ! systemctl is-active --quiet remnawave-port80-lockdown.service && \
       [[ "$(systemctl show -p SubState --value remnawave-port80-lockdown.service 2>/dev/null || true)" != "start" ]]; then
      break
    fi
    sleep 1
  done

  if systemctl is-active --quiet remnawave-port80-lockdown.service || \
     [[ "$(systemctl show -p SubState --value remnawave-port80-lockdown.service 2>/dev/null || true)" == "start" ]]; then
    warn "Legacy lockdown unit is stuck; terminating only that unit's processes"
    systemctl kill --kill-who=all --signal=SIGKILL remnawave-port80-lockdown.service >/dev/null 2>&1 || true
    sleep 1
  fi

  local installed_script="$BASE_DIR/install.sh"
  [[ -f "$installed_script" ]] || installed_script="$SCRIPT_DIR/install.sh"

  cat > "$SERVICE_LOCKDOWN" <<SERVICE
[Unit]
Description=Apply remnawave port 80 lockdown after Docker starts
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} lockdown80
RemainAfterExit=yes
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
SERVICE

  chmod 644 "$SERVICE_LOCKDOWN"
  systemctl daemon-reload
  systemctl reset-failed remnawave-port80-lockdown.service >/dev/null 2>&1 || true
  ok "Legacy Docker/lockdown boot deadlock repaired"
}

check_prereqs() {
  have_cmd systemctl || die "systemctl не найден"
  repair_legacy_lockdown_unit
  install_docker_if_missing
  have_cmd iptables || die "iptables не найден"
}

ensure_dirs() {
  mkdir -p "$BASE_DIR" "$WWW_DIR" "$ACME_WEBROOT/.well-known/acme-challenge" "$CERTS_DIR" "$SCRIPTS_DIR" "$NGINX_LOG_DIR"
  touch "$NGINX_ACCESS_LOG" "$NGINX_ERROR_LOG"
  chmod 755 "$BASE_DIR" "$WWW_DIR" "$ACME_WEBROOT" "$SCRIPTS_DIR" "$NGINX_LOG_DIR"
  chmod 700 "$CERTS_DIR"
  ok "Рабочие директории nginx готовы"
}

ensure_node_dirs() {
  mkdir -p "$REMNANODE_DIR" "$REMNANODE_LOG_DIR" "$CERTS_DIR"
  chmod 700 "$REMNANODE_DIR"
  chmod 755 "$REMNANODE_LOG_DIR"
  chmod 700 "$CERTS_DIR"
  ok "Директории remnanode готовы: $REMNANODE_DIR, $REMNANODE_LOG_DIR"
}


write_index_html() {
  cat > "$INDEX_FILE" <<HTML
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Remnawave / Xray helper</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 820px; margin: 48px auto; padding: 0 16px; line-height: 1.6; }
    code { background: #f2f2f2; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>Remnawave / Xray helper</h1>
  <p>Вспомогательный контейнер nginx запущен.</p>
  <p>Локальный сайт доступен на <code>127.0.0.1:8080</code> и предназначен для Xray fallback.</p>
  <p>Домены: <code>${DOMAINS}</code></p>
</body>
</html>
HTML
  ok "Создан стандартный index.html: $INDEX_FILE"
}

install_site_assets() {
  if [[ -d "$SITE_SOURCE_DIR" ]] && find "$SITE_SOURCE_DIR" -mindepth 1 -print -quit | grep -q .; then
    log "Найдена папка с файлами сайта: $SITE_SOURCE_DIR"
    find "$WWW_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    cp -a "$SITE_SOURCE_DIR"/. "$WWW_DIR"/
    ok "Файлы сайта скопированы в $WWW_DIR"
  else
    log "Папка с файлами сайта не найдена или пуста: $SITE_SOURCE_DIR"
    write_index_html
  fi
}

write_compose() {

  cat > "$COMPOSE_FILE" <<YAML
services:
  ${CONTAINER_NAME}:
    image: ${NGINX_IMAGE}
    container_name: ${CONTAINER_NAME}
    hostname: ${CONTAINER_NAME}
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./acme:/var/www/acme:rw
      - ./www:/var/www/html:ro
      - ./logs:/var/log/remnawave-nginx:rw
    ports:
      - "0.0.0.0:80:80"
      - "127.0.0.1:8080:8080"
    restart: unless-stopped
YAML
  ok "Сгенерирован docker-compose для nginx: $COMPOSE_FILE"
}

write_nginx_conf() {
  local server_names
  server_names="$DOMAINS"

  cat > "$NGINX_CONF" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${server_names};
    access_log /var/log/remnawave-nginx/access.log combined;
    error_log  /var/log/remnawave-nginx/error.log warn;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 8080;
    server_name ${server_names};
    access_log /var/log/remnawave-nginx/access.log combined;
    error_log  /var/log/remnawave-nginx/error.log warn;

    root /var/www/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX
  ok "Сгенерирован nginx config: $NGINX_CONF"
}

write_reload_helper() {
  mkdir -p "$SCRIPTS_DIR"
  cat > "$RELOAD_HELPER" <<EOSH
#!/usr/bin/env bash
set -Eeuo pipefail

COMPOSE_FILE=$(quote_sh "$REMNANODE_COMPOSE_FILE")
CONTAINER_NAME=$(quote_sh "$REMNANODE_CONTAINER_NAME")
SERVICE_NAME=$(quote_sh "$REMNANODE_SERVICE_NAME")

log() {
  printf '%s [acme-reload] %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$*"
}

compose_restart() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "\$COMPOSE_FILE" restart "\$SERVICE_NAME"
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "\$COMPOSE_FILE" restart "\$SERVICE_NAME"
    return 0
  fi
  return 1
}

main() {
  if [[ -f "\$COMPOSE_FILE" ]]; then
    log "Перезапускаю remnanode через compose, чтобы Xray перечитал обновлённые сертификаты"
    compose_restart
    return 0
  fi

  if command -v docker >/dev/null 2>&1 && docker inspect "\$CONTAINER_NAME" >/dev/null 2>&1; then
    log "Compose-файл не найден, перезапускаю контейнер \$CONTAINER_NAME напрямую"
    docker restart "\$CONTAINER_NAME" >/dev/null
    return 0
  fi

  log "Remnanode не найден, пропускаю перезапуск"
}

main "\$@"
EOSH
  chmod +x "$RELOAD_HELPER"
}

run_acme() {
  env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND \
    HOME=/root "$ACME" "$@"
}

ensure_acme_installed() {
  local install_output rc=0

  if [[ -x "$ACME" ]]; then
    run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
    run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
    ok "acme.sh уже установлен"
    return 0
  fi

  log "Установка acme.sh"
  install_output="$({
    env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND HOME=/root \
      sh -c 'curl -fsSL https://get.acme.sh | sh -s email="$1"' _ "$ACME_EMAIL"
  } 2>&1)" || rc=$?

  if [[ -n "$install_output" ]]; then
    printf '%s\n' "$install_output" | sed \
      -e '/Installing cron job/d' \
      -e '/^no crontab for /d' \
      -e '/Close and reopen your terminal to start using acme\.sh/d' \
      -e '/Installing alias to /d' \
      -e '/bash has been found\. Changing the shebang to use bash as preferred\./d'
  fi

  (( rc == 0 )) || die "Не удалось установить acme.sh"
  [[ -x "$ACME" ]] || die "Не удалось установить acme.sh"

  run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
  run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
  ok "acme.sh установлен, встроенный cron отключён в пользу systemd timer"
}

ensure_acme_installed() {
  local install_output="" rc=0 tmpdir="" archive="" installer_bin="" installer_dir=""
  local -a install_args=()

  if [[ -x "$ACME" ]]; then
    run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
    run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
    ok "acme.sh СѓР¶Рµ СѓСЃС‚Р°РЅРѕРІР»РµРЅ"
    return 0
  fi

  log "РЈСЃС‚Р°РЅРѕРІРєР° acme.sh РІ $ACME_HOME"
  tmpdir="$(mktemp -d)"
  archive="$tmpdir/acme.sh.tar.gz"

  curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz" -o "$archive" || {
    rm -rf "$tmpdir"
    die "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРєР°С‡Р°С‚СЊ acme.sh"
  }
  tar -xzf "$archive" -C "$tmpdir" || {
    rm -rf "$tmpdir"
    die "РќРµ СѓРґР°Р»РѕСЃСЊ СЂР°СЃРїР°РєРѕРІР°С‚СЊ acme.sh"
  }

  installer_bin="$(find "$tmpdir" -maxdepth 2 -type f -name acme.sh | head -n1)"
  [[ -n "$installer_bin" ]] || {
    rm -rf "$tmpdir"
    die "РќРµ СѓРґР°Р»РѕСЃСЊ РЅР°Р№С‚Рё install script acme.sh"
  }

  install_args=(--install --home "$ACME_HOME" --nocron)
  if [[ -n "$ACME_EMAIL" ]]; then
    install_args+=(--accountemail "$ACME_EMAIL")
  fi

  install_output="$(
    env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND HOME=/root \
      "$installer_bin" "${install_args[@]}" 2>&1
  )" || rc=$?

  rm -rf "$tmpdir"

  if [[ -n "$install_output" ]]; then
    printf '%s\n' "$install_output"
  fi

  (( rc == 0 )) || die "РќРµ СѓРґР°Р»РѕСЃСЊ СѓСЃС‚Р°РЅРѕРІРёС‚СЊ acme.sh"
  [[ -x "$ACME" ]] || die "РќРµ СѓРґР°Р»РѕСЃСЊ СѓСЃС‚Р°РЅРѕРІРёС‚СЊ acme.sh"

  run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
  run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
  ok "acme.sh СѓСЃС‚Р°РЅРѕРІР»РµРЅ РІ $ACME_HOME, РІСЃС‚СЂРѕРµРЅРЅС‹Р№ cron РѕС‚РєР»СЋС‡С‘РЅ РІ РїРѕР»СЊР·Сѓ systemd timer"
}

ensure_docker_user_chain() {
  local has_chain=0

  if ! iptables -nL DOCKER-USER >/dev/null 2>&1; then
    warn "Цепочка DOCKER-USER пока не существует. Docker обычно создаёт её после запуска"
  else
    has_chain=1
  fi
  if have_cmd ip6tables && ! ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    warn "IPv6-цепочка DOCKER-USER не найдена. Ограничение 80/tcp по IPv6 может пока не работать"
  elif have_cmd ip6tables; then
    has_chain=1
  fi

  (( has_chain == 1 )) || die "Цепочка DOCKER-USER не найдена. Нужен Docker с iptables backend и запущенным daemon"
}

ensure_acme_installed() {
  local install_output="" rc=0 tmpdir="" archive="" installer_bin="" installer_dir=""
  local -a install_args=()

  if [[ -x "$ACME" ]]; then
    run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
    run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
    ok "acme.sh already installed"
    return 0
  fi

  log "Installing acme.sh into $ACME_HOME"
  tmpdir="$(mktemp -d)"
  archive="$tmpdir/acme.sh.tar.gz"

  curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz" -o "$archive" || {
    rm -rf "$tmpdir"
    die "Failed to download acme.sh"
  }
  tar -xzf "$archive" -C "$tmpdir" || {
    rm -rf "$tmpdir"
    die "Failed to extract acme.sh"
  }

  installer_bin="$(find "$tmpdir" -maxdepth 2 -type f -name acme.sh | head -n1)"
  [[ -n "$installer_bin" ]] || {
    rm -rf "$tmpdir"
    die "Failed to find acme.sh installer"
  }
  installer_dir="$(dirname "$installer_bin")"
  mkdir -p "$(dirname "$ACME_HOME")"

  install_args=(--install --home "$ACME_HOME" --nocron)
  if [[ -n "$ACME_EMAIL" ]]; then
    install_args+=(--accountemail "$ACME_EMAIL")
  fi

  install_output="$(
    (
      cd "$installer_dir"
      env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND HOME=/root \
        ./acme.sh "${install_args[@]}"
    ) 2>&1
  )" || rc=$?

  rm -rf "$tmpdir"

  if [[ -n "$install_output" ]]; then
    printf '%s\n' "$install_output"
  fi

  (( rc == 0 )) || die "Failed to install acme.sh"
  [[ -x "$ACME" ]] || die "acme.sh binary not found after install"

  run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
  run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
  ok "acme.sh installed into $ACME_HOME; cron disabled in favor of systemd timer"
}

delete_all_rule_matches() {
  local bin="$1"; shift
  while "$bin" -C DOCKER-USER "$@" >/dev/null 2>&1; do
    "$bin" -D DOCKER-USER "$@" >/dev/null 2>&1 || break
  done
}

nginx_container_ipv4() {
  local ip

  have_cmd docker || return 1
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if .IPAddress}}{{.IPAddress}} {{end}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  ip="${ip%% *}"
  [[ -n "$ip" ]] || return 1
  printf '%s' "$ip"
}

nginx_container_ipv6() {
  local ip

  have_cmd docker || return 1
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if .GlobalIPv6Address}}{{.GlobalIPv6Address}} {{end}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  ip="${ip%% *}"
  [[ -n "$ip" ]] || return 1
  printf '%s' "$ip"
}

purge_port80_rules() {
  local bin="$1"

  delete_all_rule_matches "$bin" -m comment --comment "$PORT80_RULE_COMMENT" -p tcp --dport 80 -j ACCEPT
  delete_all_rule_matches "$bin" -m comment --comment "$PORT80_RULE_COMMENT" -p tcp --dport 80 -j DROP
  delete_all_rule_matches "$bin" -p tcp --dport 80 -j ACCEPT
  delete_all_rule_matches "$bin" -p tcp --dport 80 -j DROP
}

open80() {
  ensure_docker_user_chain

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    delete_all_rule_matches iptables -p tcp --dport 80 -j DROP
    delete_all_rule_matches iptables -p tcp --dport 80 -j ACCEPT
    iptables -I DOCKER-USER 1 -p tcp --dport 80 -j ACCEPT
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    delete_all_rule_matches ip6tables -p tcp --dport 80 -j DROP
    delete_all_rule_matches ip6tables -p tcp --dport 80 -j ACCEPT
    ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -j ACCEPT
  fi

  ok "Порт 80/tcp открыт в DOCKER-USER"
}

close80() {
  ensure_docker_user_chain

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    delete_all_rule_matches iptables -p tcp --dport 80 -j ACCEPT
    delete_all_rule_matches iptables -p tcp --dport 80 -j DROP
    iptables -I DOCKER-USER 1 -p tcp --dport 80 -j DROP
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    delete_all_rule_matches ip6tables -p tcp --dport 80 -j ACCEPT
    delete_all_rule_matches ip6tables -p tcp --dport 80 -j DROP
    ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -j DROP
  fi

  ok "Порт 80/tcp закрыт в DOCKER-USER"
}

lockdown80() { close80; }

ensure_docker_user_chain() {
  local has_chain=0

  if iptables -nL DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER >/dev/null 2>&1 || iptables -nL DOCKER-USER >/dev/null 2>&1; then
    has_chain=1
  else
    warn "Unable to prepare IPv4 DOCKER-USER chain"
  fi

  if have_cmd ip6tables; then
    if ip6tables -nL DOCKER-USER >/dev/null 2>&1 || ip6tables -N DOCKER-USER >/dev/null 2>&1 || ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
      has_chain=1
    else
      warn "Unable to prepare IPv6 DOCKER-USER chain"
    fi
  fi

  (( has_chain == 1 )) || die "DOCKER-USER chain is unavailable"
}

purge_port80_rules() {
  local bin="$1"

  delete_all_rule_matches "$bin" -m comment --comment "$PORT80_RULE_COMMENT" -p tcp --dport 80 -j ACCEPT
  delete_all_rule_matches "$bin" -m comment --comment "$PORT80_RULE_COMMENT" -p tcp --dport 80 -j DROP
}

open80() {
  local helper_ipv4="" helper_ipv6=""
  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "Unable to detect helper-nginx IPv4; using broad Docker 80/tcp allow rule"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "Unable to detect helper-nginx IPv6; using broad Docker IPv6 80/tcp allow rule"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  ok "Port 80/tcp opened in DOCKER-USER"
}

close80() {
  local helper_ipv4="" helper_ipv6=""
  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "Unable to detect helper-nginx IPv4; using broad Docker 80/tcp block rule"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "Unable to detect helper-nginx IPv6; using broad Docker IPv6 80/tcp block rule"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  ok "Port 80/tcp blocked in DOCKER-USER"
}

lockdown80() { close80; }

open80() {
  local helper_ipv4="" helper_ipv6=""
  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРїСЂРµРґРµР»РёС‚СЊ IPv4 helper-nginx, РІРєР»СЋС‡Р°СЋ fallback-РїСЂР°РІРёР»Рѕ РґР»СЏ РІСЃРµРіРѕ Docker 80/tcp"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРїСЂРµРґРµР»РёС‚СЊ IPv6 helper-nginx, РІРєР»СЋС‡Р°СЋ fallback-РїСЂР°РІРёР»Рѕ РґР»СЏ РІСЃРµРіРѕ Docker IPv6 80/tcp"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  ok "РџРѕСЂС‚ 80/tcp РѕС‚РєСЂС‹С‚ РІ DOCKER-USER"
}

close80() {
  local helper_ipv4="" helper_ipv6=""
  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРїСЂРµРґРµР»РёС‚СЊ IPv4 helper-nginx, РІРєР»СЋС‡Р°СЋ fallback-Р±Р»РѕРєРёСЂРѕРІРєСѓ РґР»СЏ РІСЃРµРіРѕ Docker 80/tcp"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРїСЂРµРґРµР»РёС‚СЊ IPv6 helper-nginx, РІРєР»СЋС‡Р°СЋ fallback-Р±Р»РѕРєРёСЂРѕРІРєСѓ РґР»СЏ РІСЃРµРіРѕ Docker IPv6 80/tcp"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  ok "РџРѕСЂС‚ 80/tcp Р·Р°РєСЂС‹С‚ РІ DOCKER-USER"
}

lockdown80() { close80; }

open80() {
  local helper_ipv4="" helper_ipv6=""
  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "Unable to detect helper-nginx IPv4; using broad Docker 80/tcp allow rule"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "Unable to detect helper-nginx IPv6; using broad Docker IPv6 80/tcp allow rule"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  ok "Port 80/tcp opened in DOCKER-USER"
}

close80() {
  local helper_ipv4="" helper_ipv6=""
  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "Unable to detect helper-nginx IPv4; using broad Docker 80/tcp block rule"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "Unable to detect helper-nginx IPv6; using broad Docker IPv6 80/tcp block rule"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  ok "Port 80/tcp blocked in DOCKER-USER"
}

lockdown80() { close80; }

is_valid_ipv4_addr() {
  local ip="$1"
  local IFS='.'
  local -a octets=()
  local octet

  [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  read -r -a octets <<< "$ip"
  ((${#octets[@]} == 4)) || return 1

  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( octet >= 0 && octet <= 255 )) || return 1
  done

  return 0
}

is_valid_ipv6_addr() {
  local ip="$1"

  [[ -n "$ip" ]] || return 1
  [[ "$ip" == *:* ]] || return 1
  [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
}

nginx_container_ipv4() {
  local ip

  have_cmd docker || return 1
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if .IPAddress}}{{.IPAddress}} {{end}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  ip="${ip%% *}"
  ip="${ip//$'\r'/}"
  ip="${ip//$'\n'/}"
  is_valid_ipv4_addr "$ip" || return 1
  printf '%s' "$ip"
}

nginx_container_ipv6() {
  local ip

  have_cmd docker || return 1
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if .GlobalIPv6Address}}{{.GlobalIPv6Address}} {{end}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  ip="${ip%% *}"
  ip="${ip//$'\r'/}"
  ip="${ip//$'\n'/}"
  is_valid_ipv6_addr "$ip" || return 1
  printf '%s' "$ip"
}

open80() {
  local helper_ipv4="" helper_ipv6=""

  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    else
      warn "Unable to detect helper-nginx IPv4; using broad Docker 80/tcp allow rule"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      if ! ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT; then
        warn "Failed to add IPv6-specific allow rule for helper-nginx; using broad Docker IPv6 80/tcp allow rule"
        ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
      fi
    else
      warn "Unable to detect helper-nginx IPv6; using broad Docker IPv6 80/tcp allow rule"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j ACCEPT
    fi
  fi

  ok "Port 80/tcp opened in DOCKER-USER"
}

close80() {
  local helper_ipv4="" helper_ipv6=""

  ensure_docker_user_chain
  helper_ipv4="$(nginx_container_ipv4 || true)"
  helper_ipv6="$(nginx_container_ipv6 || true)"

  if iptables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules iptables
    if [[ -n "$helper_ipv4" ]]; then
      iptables -I DOCKER-USER 1 -d "$helper_ipv4" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    else
      warn "Unable to detect helper-nginx IPv4; using broad Docker 80/tcp block rule"
      iptables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  if have_cmd ip6tables && ip6tables -nL DOCKER-USER >/dev/null 2>&1; then
    purge_port80_rules ip6tables
    if [[ -n "$helper_ipv6" ]]; then
      if ! ip6tables -I DOCKER-USER 1 -d "$helper_ipv6" -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP; then
        warn "Failed to add IPv6-specific block rule for helper-nginx; using broad Docker IPv6 80/tcp block rule"
        ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
      fi
    else
      warn "Unable to detect helper-nginx IPv6; using broad Docker IPv6 80/tcp block rule"
      ip6tables -I DOCKER-USER 1 -p tcp --dport 80 -m comment --comment "$PORT80_RULE_COMMENT" -j DROP
    fi
  fi

  ok "Port 80/tcp blocked in DOCKER-USER"
}

lockdown80() { close80; }

start_nginx_helper() {
  log "Запуск nginx"
  compose_nginx down --remove-orphans >/dev/null 2>&1 || true
  compose_nginx up -d
}

validate_nginx_inside_container() {
  log "Проверка конфигурации nginx внутри контейнера"
  compose_nginx exec -T "$CONTAINER_NAME" nginx -t >/dev/null
  ok "Конфигурация nginx внутри контейнера валидна"
}

check_local_backend() {
  log "Проверка локального backend на 127.0.0.1:8080"
  curl -fsS -H "Host: ${DOMAINS_ARR[0]}" http://127.0.0.1:8080/ >/dev/null
  ok "Локальный backend 127.0.0.1:8080 отвечает"
}

install_one_cert() {
  local domain="$1"
  local -a install_args
  local fullchain privkey

  fullchain="$(cert_fullchain_path "$domain")"
  privkey="$(cert_privkey_path "$domain")"

  local acme_issue_log="/tmp/remnawave-acme-issue-${domain//[^a-zA-Z0-9_.-]/_}.log"
  local acme_install_log="/tmp/remnawave-acme-install-${domain//[^a-zA-Z0-9_.-]/_}.log"

  log "Выпуск сертификата для ${domain}"
  if ! run_acme --home "$ACME_HOME" --issue -d "$domain" -w "$ACME_WEBROOT" --keylength "$ACME_KEYLENGTH" >"$acme_issue_log" 2>&1; then
    if grep -Eq 'Domains not changed\.|Skipping\.' "$acme_issue_log"; then
      [[ -s "$acme_issue_log" ]] && sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/d' "$acme_issue_log"
      log "Сертификат для ${domain} уже выпущен и пока не требует продления"
    else
      [[ -s "$acme_issue_log" ]] && sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/d' "$acme_issue_log"
      die "Не удалось выпустить сертификат для ${domain}"
    fi
  else
    [[ -s "$acme_issue_log" ]] && sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/d' "$acme_issue_log"
  fi

  install_args=(--home "$ACME_HOME" --install-cert -d "$domain")
  if [[ "$ACME_KEYLENGTH" == ec-* ]]; then
    install_args+=(--ecc)
  fi
  install_args+=(
    --fullchain-file "$fullchain"
    --key-file "$privkey"
    --reloadcmd "$RELOAD_HELPER"
  )
  if ! run_acme "${install_args[@]}" >"$acme_install_log" 2>&1; then
    [[ -s "$acme_install_log" ]] && sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/d' "$acme_install_log"
    die "Не удалось установить сертификат для ${domain}"
  fi
  [[ -s "$acme_install_log" ]] && sed '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/d' "$acme_install_log"

  chmod 640 "$fullchain" "$privkey"
  ok "Сертификат сохранён: $fullchain"
  ok "Приватный ключ сохранён: $privkey"
}

issue_all_certs() {
  local trap_enabled=0
  local d

  ((${#DOMAINS_ARR[@]} > 0)) || die "Домены не настроены"
  ensure_acme_installed
  ensure_dirs
  write_reload_helper
  write_nginx_conf
  start_nginx_helper
  validate_nginx_inside_container
  open80
  trap_enabled=1
  trap '[[ "$trap_enabled" -eq 1 ]] && close80 || true' RETURN

  mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge" "$CERTS_DIR"
  run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER"

  for d in "${DOMAINS_ARR[@]}"; do
    install_one_cert "$d"
  done

  close80
  trap_enabled=0
  trap - RETURN

  check_local_backend
  ok "Все сертификаты выпущены и установлены"
  log "После продления сертификата remnanode будет перезапускаться автоматически через reload hook"
}

renew_cert() {
  local trap_enabled=0
  ensure_acme_installed
  ensure_dirs
  write_reload_helper
  start_nginx_helper
  validate_nginx_inside_container
  open80
  trap_enabled=1
  trap '[[ "$trap_enabled" -eq 1 ]] && close80 || true' RETURN
  log "Запуск цикла продления сертификатов"
  run_acme --home "$ACME_HOME" --cron
  close80
  trap_enabled=0
  trap - RETURN
  ok "Проверка продления сертификатов завершена"
}

issue_all_certs() {
  local trap_enabled=0
  local d

  ((${#DOMAINS_ARR[@]} > 0)) || die "Domains are not configured"
  ensure_acme_installed
  ensure_dirs
  write_reload_helper
  write_nginx_conf
  close80
  start_nginx_helper
  validate_nginx_inside_container
  open80
  trap_enabled=1
  trap '[[ "$trap_enabled" -eq 1 ]] && close80 || true' RETURN

  mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge" "$CERTS_DIR"
  run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER"

  for d in "${DOMAINS_ARR[@]}"; do
    install_one_cert "$d"
  done

  close80
  trap_enabled=0
  trap - RETURN

  check_local_backend
  ok "All certificates were issued and installed"
  log "Reload hook is configured to restart remnanode after certificate updates"
}

renew_cert() {
  local trap_enabled=0

  ensure_acme_installed
  ensure_dirs
  write_reload_helper
  close80
  start_nginx_helper
  validate_nginx_inside_container
  open80
  trap_enabled=1
  trap '[[ "$trap_enabled" -eq 1 ]] && close80 || true' RETURN

  log "Starting certificate renewal cycle"
  run_acme --home "$ACME_HOME" --cron

  close80
  trap_enabled=0
  trap - RETURN
  ok "Certificate renewal check completed"
}

write_fail2ban_local() {
  mkdir -p "$(dirname "$FAIL2BAN_LOCAL_FILE")"
  touch /var/log/fail2ban.log
  cat > "$FAIL2BAN_LOCAL_FILE" <<LOCAL
[Definition]
logtarget = /var/log/fail2ban.log
allowipv6 = auto
LOCAL
  chmod 644 "$FAIL2BAN_LOCAL_FILE"
  ok "Создан fail2ban.local: $FAIL2BAN_LOCAL_FILE"
}

write_fail2ban_filter() {
  mkdir -p "$(dirname "$FAIL2BAN_FILTER_FILE")"
  cat > "$FAIL2BAN_FILTER_FILE" <<'FILTER'
[Definition]
failregex = ^<HOST> - - \[[^\]]+\] "(?:GET|POST|HEAD|OPTIONS|PROPFIND|CONNECT|PUT|DELETE|TRACE|PATCH) /(?:wp-login\.php|xmlrpc\.php|wp-admin(?:/.*)?|phpmyadmin(?:/.*)?|pma(?:/.*)?|\.env(?:\..*)?|\.git(?:/.*)?|cgi-bin(?:/.*)?|boaform(?:/.*)?|HNAP1(?:/.*)?|manager/html(?:/.*)?|vendor/phpunit(?:/.*)?|server-status(?:/.*)?|actuator(?:/.*)?|autodiscover/autodiscover\.xml(?:/.*)?|\.aws(?:/.*)?).* HTTP/[0-9.]+" (?:400|401|403|404|405|444) \d+ "[^"]*" "[^"]*"$
ignoreregex = ^<HOST> - - \[[^\]]+\] "(?:GET|HEAD) /(favicon\.ico|robots\.txt|apple-touch-icon(?:-precomposed)?\.png) HTTP/[0-9.]+" 404 \d+ "[^"]*" "[^"]*"$
FILTER
  chmod 644 "$FAIL2BAN_FILTER_FILE"
  ok "Создан фильтр fail2ban для nginx-сканеров: $FAIL2BAN_FILTER_FILE"
}

write_fail2ban_jail() {
  mkdir -p "$(dirname "$FAIL2BAN_JAIL_FILE")"
  cat > "$FAIL2BAN_JAIL_FILE" <<JAIL
[DEFAULT]
ignoreip = ${FAIL2BAN_IGNORE_IPS}

[sshd]
enabled = true
bantime = ${FAIL2BAN_SSH_BANTIME}
findtime = ${FAIL2BAN_SSH_FINDTIME}
maxretry = ${FAIL2BAN_SSH_MAXRETRY}

[remnanode-nginx-botsearch]
enabled = true
port = http,https
filter = remnanode-nginx-botsearch
logpath = ${NGINX_ACCESS_LOG}
findtime = ${FAIL2BAN_NGINX_FINDTIME}
maxretry = ${FAIL2BAN_NGINX_MAXRETRY}
bantime = ${FAIL2BAN_NGINX_BANTIME}

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
findtime = ${FAIL2BAN_RECIDIVE_FINDTIME}
maxretry = ${FAIL2BAN_RECIDIVE_MAXRETRY}
bantime = ${FAIL2BAN_RECIDIVE_BANTIME}
JAIL
  chmod 644 "$FAIL2BAN_JAIL_FILE"
  ok "Создан jail fail2ban: $FAIL2BAN_JAIL_FILE"
}

enable_fail2ban() {
  have_cmd systemctl || die "systemctl не найден"
  mkdir -p "$NGINX_LOG_DIR"
  touch "$NGINX_ACCESS_LOG" "$NGINX_ERROR_LOG" /var/log/fail2ban.log
  write_fail2ban_local
  write_fail2ban_filter
  write_fail2ban_jail
  systemctl enable --now fail2ban >/dev/null 2>&1
  if have_cmd fail2ban-client; then
    fail2ban-client reload >/dev/null 2>&1 || systemctl restart fail2ban >/dev/null 2>&1 || true
  else
    systemctl restart fail2ban >/dev/null 2>&1 || true
  fi
  systemctl is-active --quiet fail2ban || die "fail2ban не запустился"
  ok "fail2ban включён: sshd + nginx 4xx scan + recidive"
}

write_systemd_units() {
  local installed_script
  installed_script="$BASE_DIR/install.sh"

  cat > "$SERVICE_RENEW" <<SERVICE
[Unit]
Description=Renew Let's Encrypt certificates for remnawave/Xray
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} renew
SERVICE

  cat > "$TIMER_RENEW" <<TIMER
[Unit]
Description=Daily renewal check for remnawave/Xray certificates

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  cat > "$SERVICE_LOCKDOWN" <<SERVICE
[Unit]
Description=Apply remnawave port 80 lockdown after Docker starts
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} lockdown80
RemainAfterExit=yes
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload
  systemctl enable --now remnawave-acme-renew.timer
  systemctl enable --now remnawave-port80-lockdown.service
  ok "Systemd timer and 80/tcp lockdown service are enabled"
}

write_systemd_units() {
  local installed_script
  installed_script="$BASE_DIR/install.sh"

  cat > "$SERVICE_RENEW" <<SERVICE
[Unit]
Description=Renew Let's Encrypt certificates for remnawave/Xray
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} renew
SERVICE

  cat > "$TIMER_RENEW" <<TIMER
[Unit]
Description=Daily renewal check for remnawave/Xray certificates

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  cat > "$SERVICE_LOCKDOWN" <<SERVICE
[Unit]
Description=Apply remnawave port 80 lockdown after Docker starts
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} lockdown80
RemainAfterExit=yes
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
SERVICE

  chmod 644 "$SERVICE_RENEW" "$TIMER_RENEW" "$SERVICE_LOCKDOWN"
  systemctl daemon-reload
  systemctl enable --now remnawave-acme-renew.timer
  systemctl enable --now remnawave-port80-lockdown.service
  ok "Systemd timer and 80/tcp lockdown service are enabled"
}

install_self_copy() {
  local target="$BASE_DIR/install.sh"
  if [[ "$(script_abs_path)" != "$target" ]]; then
    cp -f "$0" "$target"
    chmod +x "$target"
    ok "Скрипт скопирован в $target"
  fi
}

install_global_node_help() {
  local installed_script="$BASE_DIR/install.sh"
  cat > "$GLOBAL_NODE_HELP_BIN" <<EOF
#!/usr/bin/env bash
exec $(quote_sh "$installed_script") node-help
EOF
  chmod +x "$GLOBAL_NODE_HELP_BIN"
  ok "Глобальная команда node-help установлена: $GLOBAL_NODE_HELP_BIN"
}

write_remnanode_env() {
  ensure_node_dirs
  validate_compose_env_value "NODE_PORT" "$NODE_PORT"
  validate_compose_env_value "SECRET_KEY" "$SECRET_KEY"
  if [[ -n "$SSL_CERT" ]]; then
    validate_compose_env_value "SSL_CERT" "$SSL_CERT"
  fi
  cat > "$REMNANODE_ENV_FILE" <<ENV
NODE_PORT=${NODE_PORT}
SECRET_KEY=${SECRET_KEY}
ENV
  if [[ -n "$SSL_CERT" ]]; then
    printf 'SSL_CERT=%s
' "$SSL_CERT" >> "$REMNANODE_ENV_FILE"
  fi
  chmod 600 "$REMNANODE_ENV_FILE"
  ok "Создан env-файл remnanode: $REMNANODE_ENV_FILE"
}

write_remnanode_logrotate() {
  mkdir -p "$(dirname "$REMNANODE_LOGROTATE_FILE")"
  cat > "$REMNANODE_LOGROTATE_FILE" <<ROTATE
${REMNANODE_LOG_DIR}/*.log {
    size ${REMNANODE_LOGROTATE_SIZE}
    rotate ${REMNANODE_LOGROTATE_ROTATE}
    compress
    missingok
    notifempty
    copytruncate
}
ROTATE
  chmod 644 "$REMNANODE_LOGROTATE_FILE"
  ok "Создан config logrotate для remnanode: $REMNANODE_LOGROTATE_FILE"
}

write_remnanode_compose() {
  ensure_node_dirs
  cat > "$REMNANODE_COMPOSE_FILE" <<YAML
services:
  ${REMNANODE_SERVICE_NAME}:
    container_name: ${REMNANODE_CONTAINER_NAME}
    hostname: ${REMNANODE_CONTAINER_NAME}
    image: ${REMNANODE_IMAGE}
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    logging:
      driver: json-file
      options:
        max-size: "${DOCKER_LOG_MAX_SIZE}"
        max-file: "${DOCKER_LOG_MAX_FILE}"
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - ${CERTS_DIR}:${CERTS_DIR}:ro
      - ${REMNANODE_LOG_DIR}:${REMNANODE_LOG_DIR}
    env_file:
      - ./.env
YAML
  ok "Сгенерирован docker-compose для remnanode: $REMNANODE_COMPOSE_FILE"
}

start_remnanode() {
  [[ "$AUTO_INSTALL_NODE" =~ ^(1|yes|true)$ ]] || {
    warn "Установка remnanode отключена"
    return 0
  }

  if [[ "$PANEL_AUTO_REGISTER_NODE" =~ ^(1|yes|true)$ && -n "$PANEL_DOMAIN" && -n "$PANEL_API_TOKEN" ]] && \
     [[ -z "$PANEL_NODE_UUID" || -z "$SECRET_KEY" ]]; then
    ensure_panel_node_registered
  fi

  [[ -n "$SECRET_KEY" ]] || die "SECRET_KEY для remnanode не задан"
  write_remnanode_env
  write_remnanode_logrotate
  write_remnanode_compose

  log "Запуск remnanode"
  compose_node pull || true
  compose_node down --remove-orphans >/dev/null 2>&1 || true
  compose_node up -d --force-recreate
  ok "remnanode запущен"
}


show_recent_node_logs() {
  if [[ -f "$REMNANODE_COMPOSE_FILE" ]]; then
    log "Последние Docker-логи remnanode (50 строк)"
    compose_node logs --tail=50 -t || true
    if [[ -f "$REMNANODE_LOG_DIR/access.log" || -f "$REMNANODE_LOG_DIR/error.log" ]]; then
      echo
      log "Файловые логи Xray/remnanode:"
      [[ -f "$REMNANODE_LOG_DIR/access.log" ]] && echo "     - $REMNANODE_LOG_DIR/access.log"
      [[ -f "$REMNANODE_LOG_DIR/error.log" ]] && echo "     - $REMNANODE_LOG_DIR/error.log"
    fi
  else
    warn "Файл docker-compose remnanode не найден: $REMNANODE_COMPOSE_FILE"
  fi
}

show_live_node_logs() {
  [[ -f "$REMNANODE_COMPOSE_FILE" ]] || die "Файл docker-compose remnanode не найден: $REMNANODE_COMPOSE_FILE"
  log "Live Docker-логи remnanode"
  compose_node logs -f -t
}

show_node_file_log() {
  local label="$1" file="$2"
  [[ -f "$file" ]] || die "Файл ${label} не найден: $file"
  log "Показываю ${label}: $file"
  tail -f "$file"
}

show_node_error_log() {
  show_node_file_log "error.log" "$REMNANODE_LOG_DIR/error.log"
}

show_node_access_log() {
  show_node_file_log "access.log" "$REMNANODE_LOG_DIR/access.log"
}

show_node_container_log() {
  local label="$1" file="$2"

  have_cmd docker || die "docker не найден"
  if ! docker ps --format '{{.Names}}' | grep -qx "$REMNANODE_CONTAINER_NAME"; then
    die "Контейнер ${REMNANODE_CONTAINER_NAME} не запущен"
  fi

  log "Показываю ${label} внутри контейнера"
  docker exec -it "$REMNANODE_CONTAINER_NAME" tail -n +1 -f "$file"
}

show_node_container_log() {
  local label="$1" file="$2"
  local -a exec_args

  have_cmd docker || die "docker РЅРµ РЅР°Р№РґРµРЅ"
  if ! docker ps --format '{{.Names}}' | grep -qx "$REMNANODE_CONTAINER_NAME"; then
    die "РљРѕРЅС‚РµР№РЅРµСЂ ${REMNANODE_CONTAINER_NAME} РЅРµ Р·Р°РїСѓС‰РµРЅ"
  fi

  exec_args=(-i)
  if stdin_is_tty && [[ -t 1 ]]; then
    exec_args=(-it)
  fi

  log "РџРѕРєР°Р·С‹РІР°СЋ ${label} РІРЅСѓС‚СЂРё РєРѕРЅС‚РµР№РЅРµСЂР°"
  docker exec "${exec_args[@]}" "$REMNANODE_CONTAINER_NAME" tail -n +1 -f "$file"
}

show_node_container_log() {
  local label="$1" file="$2"
  local -a exec_args

  have_cmd docker || die "docker not found"
  if ! docker ps --format '{{.Names}}' | grep -qx "$REMNANODE_CONTAINER_NAME"; then
    die "Container ${REMNANODE_CONTAINER_NAME} is not running"
  fi

  exec_args=(-i)
  if stdin_is_tty && [[ -t 1 ]]; then
    exec_args=(-it)
  fi

  log "Showing ${label} inside container"
  docker exec "${exec_args[@]}" "$REMNANODE_CONTAINER_NAME" tail -n +1 -f "$file"
}

show_node_xray_out_log() {
  show_node_container_log "xray.out.log" "/var/log/supervisor/xray.out.log"
}

show_node_xray_err_log() {
  show_node_container_log "xray.err.log" "/var/log/supervisor/xray.err.log"
}

show_install_node_logs() {
  local seconds="${1:-6}"
  if ! have_cmd docker; then
    return 0
  fi
  if ! docker ps -a --format '{{.Names}}' | grep -qx "$REMNANODE_CONTAINER_NAME"; then
    warn "Контейнер remnanode не найден для предпросмотра live-логов"
    return 0
  fi

  log "Показываю стартовые Docker-логи remnanode в течение ${seconds} секунд"
  if have_cmd timeout; then
    timeout "${seconds}s" docker logs --tail=50 -f --timestamps "$REMNANODE_CONTAINER_NAME" || true
  else
    docker logs --tail=50 --timestamps "$REMNANODE_CONTAINER_NAME" || true
  fi

  if [[ -f "$REMNANODE_LOG_DIR/access.log" || -f "$REMNANODE_LOG_DIR/error.log" ]]; then
    echo
    log "Файловые логи Xray/remnanode:"
    [[ -f "$REMNANODE_LOG_DIR/access.log" ]] && echo "     - $REMNANODE_LOG_DIR/access.log"
    [[ -f "$REMNANODE_LOG_DIR/error.log" ]] && echo "     - $REMNANODE_LOG_DIR/error.log"
  fi
}

restart_remnanode() {

  [[ -f "$REMNANODE_COMPOSE_FILE" ]] || die "Файл docker-compose remnanode не найден: $REMNANODE_COMPOSE_FILE"
  log "Пересоздание remnanode"
  compose_node down --remove-orphans >/dev/null 2>&1 || true
  compose_node up -d --force-recreate
  ok "remnanode пересоздан"
}


stop_remnanode() {
  [[ -f "$REMNANODE_COMPOSE_FILE" ]] || die "Файл docker-compose remnanode не найден: $REMNANODE_COMPOSE_FILE"
  log "Остановка remnanode"
  compose_node down --remove-orphans
  ok "remnanode остановлен"
}

print_tls_hints() {
  local d
  cat <<EOT

Подсказки по TLS / fallback
--------------------------
Сертификаты выпущены отдельно для каждого домена:
EOT
  if ((${#DOMAINS_ARR[@]} == 0)); then
    echo "  Сохранённые домены не найдены, пути к сертификатам недоступны."
  else
    for d in "${DOMAINS_ARR[@]}"; do
      echo "  ${d}"
      echo "    certificateFile: $(cert_fullchain_path "$d")"
      echo "    keyFile:         $(cert_privkey_path "$d")"
    done
  fi
  cat <<EOT

Примечания:
  - Вспомогательный сайт слушает на 127.0.0.1:8080.
  - Для Xray fallback используй dest: 127.0.0.1:8080.
  - Порт 8080 привязан только к localhost.
  - Порт 80 открывается только на время ACME issue/renew, затем снова закрывается в DOCKER-USER.
EOT
}


print_fail2ban_hints() {
  cat <<EOT

Подсказки по fail2ban
--------------------
SSH:
  - bantime:  ${FAIL2BAN_SSH_BANTIME}
  - findtime: ${FAIL2BAN_SSH_FINDTIME}
  - maxretry: ${FAIL2BAN_SSH_MAXRETRY}

Nginx 4xx scan:
  - лог:      ${NGINX_ACCESS_LOG}
  - bantime:  ${FAIL2BAN_NGINX_BANTIME}
  - findtime: ${FAIL2BAN_NGINX_FINDTIME}
  - maxretry: ${FAIL2BAN_NGINX_MAXRETRY}

Recidive:
  - bantime:  ${FAIL2BAN_RECIDIVE_BANTIME}
  - findtime: ${FAIL2BAN_RECIDIVE_FINDTIME}
  - maxretry: ${FAIL2BAN_RECIDIVE_MAXRETRY}

Полезные команды:
  fail2ban-client status
  fail2ban-client status sshd
  fail2ban-client status remnanode-nginx-botsearch
  fail2ban-client status recidive
EOT
}

print_node_hints() {
  local cb panel_profile installed_script
  cb="$(compose_bin 2>/dev/null || echo 'docker compose')"
  panel_profile="${PANEL_CONFIG_PROFILE_NAME:-$PANEL_CONFIG_PROFILE_UUID}"
  installed_script="$BASE_DIR/install.sh"
  cat <<EOT

Подсказки по remnanode
----------------------
Директория ноды:       ${REMNANODE_DIR}
Compose-файл ноды:     ${REMNANODE_COMPOSE_FILE}
Env-файл ноды:         ${REMNANODE_ENV_FILE}
Service ноды:          ${REMNANODE_SERVICE_NAME}
Имя контейнера:        ${REMNANODE_CONTAINER_NAME}
Порт ноды:             ${NODE_PORT}
SECRET_KEY:            $(mask_secret "$SECRET_KEY")
$([[ -n "${SSL_CERT:-}" ]] && echo "SSL_CERT:              ${SSL_CERT}")
Installer env:         ${SCRIPT_ENV_FILE}
Директория логов:      ${REMNANODE_LOG_DIR}
Файл logrotate:        ${REMNANODE_LOGROTATE_FILE}
$([[ -n "${PANEL_DOMAIN:-}" ]] && echo "Панель:                ${PANEL_DOMAIN}")
$([[ -n "${PANEL_AUTO_REGISTER_NODE:-}" ]] && echo "Авто-регистрация:      ${PANEL_AUTO_REGISTER_NODE}")
$([[ -n "${PANEL_NODE_NAME:-}" ]] && echo "Имя ноды в панели:     ${PANEL_NODE_NAME}")
$([[ -n "${PANEL_NODE_ADDRESS:-}" ]] && echo "Адрес ноды в панели:   ${PANEL_NODE_ADDRESS}")
$([[ -n "${PANEL_NODE_UUID:-}" ]] && echo "UUID ноды в панели:    ${PANEL_NODE_UUID}")
$([[ -n "${PANEL_NODE_COUNTRY_CODE:-}" ]] && echo "Код страны ноды:       ${PANEL_NODE_COUNTRY_CODE}")
$([[ -n "${panel_profile:-}" ]] && echo "Config profile:        ${panel_profile}")

Полезные команды:
  sudo bash ${installed_script} status
  sudo bash ${installed_script} start-node
  sudo bash ${installed_script} stop-node
  sudo bash ${installed_script} restart-node
  sudo bash ${installed_script} logs-node
  sudo bash ${installed_script} logs-node-live
  sudo bash ${installed_script} logs-node-error
  sudo bash ${installed_script} logs-node-access
  sudo bash ${installed_script} logs-node-xray-out
  sudo bash ${installed_script} logs-node-xray-err
  ${cb} -f ${REMNANODE_COMPOSE_FILE} up -d --force-recreate
  ${cb} -f ${REMNANODE_COMPOSE_FILE} down --remove-orphans

Чтобы включить файловые access/error логи, добавь этот блок в Xray Config:
  "log": {
    "error": "${REMNANODE_LOG_DIR}/error.log",
    "access": "${REMNANODE_LOG_DIR}/access.log",
    "loglevel": "warning"
  }
EOT
}

status() {

  local d panel_profile
  load_runtime_or_die
  panel_profile="${PANEL_CONFIG_PROFILE_NAME:-$PANEL_CONFIG_PROFILE_UUID}"

  echo "Домены:               $DOMAINS"
  echo "Базовая директория:   $BASE_DIR"
  echo "Файл конфигурации:    $CONFIG_FILE"
  echo "docker-compose nginx: $COMPOSE_FILE"
  echo "nginx.conf:           $NGINX_CONF"
  echo "ACME webroot:         $ACME_WEBROOT"
  echo "Имя контейнера nginx: $CONTAINER_NAME"
  echo "Образ nginx:          $NGINX_IMAGE"
  echo "Источник сайта:       ${SITE_SOURCE_DIR}"
  echo "Логи nginx:           ${NGINX_ACCESS_LOG}, ${NGINX_ERROR_LOG}"
  echo "Директория remnanode: $REMNANODE_DIR"
  echo "Compose remnanode:    $REMNANODE_COMPOSE_FILE"
  echo "Service remnanode:    $REMNANODE_SERVICE_NAME"
  echo "NODE_PORT:            $NODE_PORT"
  echo "SECRET_KEY:           $(mask_secret "$SECRET_KEY")"
  echo "Installer env:        $SCRIPT_ENV_FILE"
  [[ -n "$SSL_CERT" ]] && echo "SSL_CERT:              $SSL_CERT"
  [[ -n "$PANEL_DOMAIN" ]] && echo "Панель:               $PANEL_DOMAIN"
  echo "Авто-регистрация:     $PANEL_AUTO_REGISTER_NODE"
  [[ -n "$PANEL_NODE_NAME" ]] && echo "Имя ноды в панели:    $PANEL_NODE_NAME"
  [[ -n "$PANEL_NODE_ADDRESS" ]] && echo "Адрес ноды в панели:  $PANEL_NODE_ADDRESS"
  [[ -n "$PANEL_NODE_UUID" ]] && echo "UUID ноды в панели:   $PANEL_NODE_UUID"
  [[ -n "$PANEL_NODE_COUNTRY_CODE" ]] && echo "Код страны ноды:      $PANEL_NODE_COUNTRY_CODE"
  [[ -n "$panel_profile" ]] && echo "Config profile:       $panel_profile"
  echo "Директория логов:     $REMNANODE_LOG_DIR"
  echo "Logrotate:            $REMNANODE_LOGROTATE_FILE"
  echo "Fail2Ban jail:        $FAIL2BAN_JAIL_FILE"
  echo "Fail2Ban filter:      $FAIL2BAN_FILTER_FILE"
  echo "Fail2Ban local:       $FAIL2BAN_LOCAL_FILE"
  echo

  [[ -f "$CONFIG_FILE" ]] && echo "[OK] конфигурация сохранена" || echo "[--] конфигурация не найдена"
  [[ -f "$COMPOSE_FILE" ]] && echo "[OK] docker-compose nginx найден" || echo "[--] docker-compose nginx не найден"
  [[ -f "$NGINX_CONF" ]] && echo "[OK] nginx.conf найден" || echo "[--] nginx.conf отсутствует"
  [[ -f "$REMNANODE_COMPOSE_FILE" ]] && echo "[OK] docker-compose remnanode найден" || echo "[--] docker-compose remnanode не найден"
  [[ -f "$REMNANODE_ENV_FILE" ]] && echo "[OK] .env remnanode найден" || echo "[--] .env remnanode отсутствует"
  [[ -d "$REMNANODE_LOG_DIR" ]] && echo "[OK] директория логов remnanode найдена" || echo "[--] директория логов remnanode отсутствует"
  [[ -f "$REMNANODE_LOGROTATE_FILE" ]] && echo "[OK] logrotate remnanode найден" || echo "[--] logrotate remnanode отсутствует"
  [[ -f "$FAIL2BAN_JAIL_FILE" ]] && echo "[OK] jail fail2ban найден" || echo "[--] jail fail2ban отсутствует"
  [[ -f "$FAIL2BAN_FILTER_FILE" ]] && echo "[OK] фильтр fail2ban найден" || echo "[--] фильтр fail2ban отсутствует"
  [[ -f "$FAIL2BAN_LOCAL_FILE" ]] && echo "[OK] fail2ban.local найден" || echo "[--] fail2ban.local отсутствует"
  [[ -f "$REMNANODE_LOG_DIR/access.log" ]] && echo "[OK] access.log найден" || echo "[--] access.log пока отсутствует"
  [[ -f "$REMNANODE_LOG_DIR/error.log" ]] && echo "[OK] error.log найден" || echo "[--] error.log пока отсутствует"

  for d in "${DOMAINS_ARR[@]}"; do
    [[ -f "$(cert_fullchain_path "$d")" ]] && echo "[OK] ${d}: fullchain на месте" || echo "[--] ${d}: fullchain отсутствует"
    [[ -f "$(cert_privkey_path "$d")" ]] && echo "[OK] ${d}: privkey на месте" || echo "[--] ${d}: privkey отсутствует"
  done

  if have_cmd docker; then
    docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME" && \
      echo "[OK] nginx работает" || \
      echo "[--] nginx не запущен"

    docker ps --format '{{.Names}}' | grep -qx "$REMNANODE_CONTAINER_NAME" && \
      echo "[OK] remnanode работает" || \
      echo "[--] remnanode не запущен"
  fi

  echo
  print_tls_hints
  print_fail2ban_hints
  print_node_hints
}

install_node_only() {
  require_root
  require_installer_env
  load_runtime_or_die
  log "Старт установки/обновления remnanode"
  prompt_node_settings
  [[ "$AUTO_INSTALL_NODE" =~ ^(1|yes|true)$ ]] || return 0
  save_config
  install_packages
  check_prereqs
  install_self_copy
  install_global_node_help
  enable_fail2ban
  start_remnanode
  show_install_node_logs 6
  print_fail2ban_hints
  print_node_hints
  ok "Установка remnanode завершена"
}

install_all() {
  require_root
  require_installer_env
  load_saved_config
  prompt_install_docker_if_missing
  if [[ -n "$EXTRA_INSTALL_DOMAINS" ]]; then
    prepare_domains_from_runtime
  else
    prompt_if_needed_for_install
  fi
  apply_domain_defaults
  ACME_EMAIL="${ACME_EMAIL:-admin@${DOMAINS_ARR[0]}}"
  log "Старт полной установки для доменов: ${DOMAINS}"
  prompt_node_settings
  save_config
  install_packages
  check_prereqs
  ensure_dirs
  install_site_assets
  write_compose
  write_nginx_conf
  write_reload_helper
  install_self_copy
  install_global_node_help
  enable_fail2ban
  issue_all_certs
  write_systemd_units
  start_remnanode
  print_tls_hints
  print_fail2ban_hints
  print_node_hints
  show_install_node_logs 6
  ok "Установка завершена"
}

load_runtime_or_die() {
  load_saved_config
  [[ -f "$CONFIG_FILE" ]] || die "Конфигурация не найдена: $CONFIG_FILE. Сначала запусти установку"

  if [[ -n "$EXTRA_INSTALL_DOMAINS" ]]; then
    normalize_domains "$EXTRA_INSTALL_DOMAINS"
  elif [[ -n "$DOMAINS" ]]; then
    normalize_domains "$DOMAINS"
  else
    die "В сохранённой конфигурации нет доменов: $CONFIG_FILE"
  fi
  rebuild_runtime_paths
  load_node_env_if_exists
}

print_node_help() {
  local installed_script
  installed_script="$BASE_DIR/install.sh"
  cat <<EOT
${COLOR_INFO}Команды управления Remnawave / remnanode${COLOR_RESET}
----------------------------------------

  - Показать эту справку из любой папки
  ${COLOR_OK}node-help${COLOR_RESET}

  - Показать текущую конфигурацию, сертификаты и состояние сервисов
  ${COLOR_OK}sudo bash ${installed_script} status${COLOR_RESET}

  - Запустить remnanode
  ${COLOR_OK}sudo bash ${installed_script} start-node${COLOR_RESET}

  - Остановить remnanode
  ${COLOR_OK}sudo bash ${installed_script} stop-node${COLOR_RESET}

  - Перезапустить remnanode
  ${COLOR_OK}sudo bash ${installed_script} restart-node${COLOR_RESET}

  - Показать последние Docker-логи remnanode
  ${COLOR_OK}sudo bash ${installed_script} logs-node${COLOR_RESET}

  - Смотреть live Docker-логи remnanode
  ${COLOR_OK}sudo bash ${installed_script} logs-node-live${COLOR_RESET}

  - Смотреть файловый error.log Xray на хосте
  ${COLOR_OK}sudo bash ${installed_script} logs-node-error${COLOR_RESET}

  - Смотреть файловый access.log Xray на хосте
  ${COLOR_OK}sudo bash ${installed_script} logs-node-access${COLOR_RESET}

  - Смотреть stdout-лог Xray внутри контейнера
  ${COLOR_OK}sudo bash ${installed_script} logs-node-xray-out${COLOR_RESET}

  - Смотреть stderr-лог Xray внутри контейнера
  ${COLOR_OK}sudo bash ${installed_script} logs-node-xray-err${COLOR_RESET}

  - Перевыпустить сертификаты по сохранённой конфигурации
  ${COLOR_OK}sudo bash ${installed_script} issue${COLOR_RESET}

  - Запустить один цикл продления сертификатов вручную
  ${COLOR_OK}sudo bash ${installed_script} renew${COLOR_RESET}

  - Временно открыть 80/tcp для ACME
  ${COLOR_OK}sudo bash ${installed_script} open80${COLOR_RESET}

  - Снова закрыть 80/tcp
  ${COLOR_OK}sudo bash ${installed_script} close80${COLOR_RESET}

  - Показать список активных jail fail2ban
  ${COLOR_OK}sudo fail2ban-client status${COLOR_RESET}

  - Показать состояние fail2ban для SSH
  ${COLOR_OK}sudo fail2ban-client status sshd${COLOR_RESET}

  - Показать состояние fail2ban для nginx-сканеров
  ${COLOR_OK}sudo fail2ban-client status remnanode-nginx-botsearch${COLOR_RESET}

Первая установка:
  ${COLOR_OK}cd ~/installer_ssl_node${COLOR_RESET}
  ${COLOR_OK}sudo bash ./install.sh de1.example.site${COLOR_RESET}
EOT
}

usage() {
  cat <<EOT
Использование:
  $SCRIPT_NAME install [domains...]            полная установка nginx, сертификатов и remnanode
  $SCRIPT_NAME [domains...]                    то же самое, что install [domains...]
  $SCRIPT_NAME install-node                    установить или обновить только remnanode
  $SCRIPT_NAME start-node                      запустить remnanode по сохранённому compose
  $SCRIPT_NAME stop-node                       остановить remnanode
  $SCRIPT_NAME restart-node                    перезапустить remnanode
  $SCRIPT_NAME logs-node                       показать последние Docker-логи remnanode
  $SCRIPT_NAME logs-node-live                  смотреть live Docker-логи remnanode
  $SCRIPT_NAME logs-node-error                 смотреть файловый error.log Xray на хосте
  $SCRIPT_NAME logs-node-access                смотреть файловый access.log Xray на хосте
  $SCRIPT_NAME logs-node-xray-out              смотреть stdout-лог Xray внутри контейнера
  $SCRIPT_NAME logs-node-xray-err              смотреть stderr-лог Xray внутри контейнера
  $SCRIPT_NAME issue                           выпустить или перевыпустить сертификаты по сохранённой конфигурации
  $SCRIPT_NAME renew                           запустить один цикл продления сертификатов по сохранённой конфигурации
  $SCRIPT_NAME open80                          открыть опубликованный Docker-порт 80/tcp в DOCKER-USER
  $SCRIPT_NAME close80                         закрыть опубликованный Docker-порт 80/tcp в DOCKER-USER
  $SCRIPT_NAME lockdown80                      то же самое, что close80
  $SCRIPT_NAME status                          показать текущую конфигурацию и состояние
  $SCRIPT_NAME node-help                       показать команды управления нодой
Рекомендуемый запуск:
  cd ~/installer_ssl_node && sudo bash ./install.sh de1.example.site

После установки из любой папки будет доступна команда:
  node-help

Файл настроек инсталлятора:
  ${SCRIPT_ENV_FILE}
  В нём хранятся только постоянные значения, а при старте обычно передаётся только домен.

Структура рядом со скриптом:
  ./dist     папка с файлами сайта
  ./site     запасной вариант, если ./dist отсутствует

Что делает скрипт:
  - при необходимости устанавливает Docker;
  - запускает nginx в Docker;
  - публикует 80/tcp наружу, а 8080 только на 127.0.0.1 хоста;
  - выпускает отдельный сертификат для каждого домена;
  - сохраняет сертификаты в ${CERTS_DIR};
  - копирует твой fallback-сайт из ./dist в ${WWW_DIR}, если эта папка существует;
  - настраивает systemd timer для продления сертификатов;
  - берёт параметры ноды и панели из installer.env, а если домен не передан, спрашивает только домен;
  - автоматически получает Secret Key ноды из панели и сохраняет его в ${REMNANODE_ENV_FILE} с правами 600;
  - устанавливает remnanode в ${REMNANODE_DIR};
  - включает ротацию Docker-логов и готовит файловые логи в ${REMNANODE_LOG_DIR};
  - создаёт ${REMNANODE_LOGROTATE_FILE} для ротации файловых логов;
  - настраивает fail2ban для SSH и повторяющихся 4xx-сканирований nginx;
  - устанавливает глобальную команду node-help в ${GLOBAL_NODE_HELP_BIN}.
EOT
}

main() {
  init_colors

  local cmd="${1:-install}"
  case "$cmd" in
    install|install-node|start-node|stop-node|restart-node|logs-node|logs-node-live|logs-node-error|logs-node-access|logs-node-xray-out|logs-node-xray-err|issue|renew|open80|close80|lockdown80|status|node-help|help|-h|--help)
      shift || true
      ;;
    *)
      cmd="install"
      ;;
  esac

  if [[ "$cmd" == "install" && $# -gt 0 ]]; then
    EXTRA_INSTALL_DOMAINS="$*"
  fi

  log "Запуск install.sh: команда=${cmd}, папка=${SCRIPT_DIR}"

  case "$cmd" in
    install)
      install_all
      ;;
    install-node)
      install_node_only
      ;;
    start-node)
      require_root
      load_runtime_or_die
      check_prereqs
      start_remnanode
      ;;
    stop-node)
      require_root
      check_prereqs
      load_runtime_or_die
      stop_remnanode
      ;;
    restart-node)
      require_root
      check_prereqs
      load_runtime_or_die
      restart_remnanode
      ;;
    logs-node)
      require_root
      check_prereqs
      load_runtime_or_die
      show_recent_node_logs
      ;;
    logs-node-live)
      require_root
      check_prereqs
      load_runtime_or_die
      show_live_node_logs
      ;;
    logs-node-error)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_error_log
      ;;
    logs-node-access)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_access_log
      ;;
    logs-node-xray-out)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_xray_out_log
      ;;
    logs-node-xray-err)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_xray_err_log
      ;;
    issue)
      require_root
      check_prereqs
      load_runtime_or_die
      issue_all_certs
      ;;
    renew)
      require_root
      check_prereqs
      load_runtime_or_die
      renew_cert
      ;;
    open80)
      require_root
      open80
      ;;
    close80)
      require_root
      close80
      ;;
    lockdown80)
      require_root
      lockdown80
      ;;
    status)
      load_runtime_or_die
      status
      ;;
    node-help|help|-h|--help)
      print_node_help
      ;;
  esac
}

log_file_append_from_file() {
  local file="$1"
  [[ -n "${INSTALL_LOG_FILE:-}" && -f "$file" ]] || return 0
  cat "$file" >>"$INSTALL_LOG_FILE" 2>/dev/null || true
}

run_install_detail() {
  if [[ -n "${INSTALL_LOG_FILE:-}" ]]; then
    "$@" >>"$INSTALL_LOG_FILE" 2>&1
  else
    "$@"
  fi
}

apt_get_retry() {
  local timeout="${APT_LOCK_TIMEOUT:-600}"
  local interval="${APT_LOCK_RETRY_INTERVAL:-5}"
  local waited=0
  local log_emitted=0
  local tmp rc

  while true; do
    tmp="$(mktemp)"
    if apt-get -o Dpkg::Use-Pty=0 "$@" >"$tmp" 2>&1; then
      log_file_append_from_file "$tmp"
      rm -f "$tmp"
      return 0
    fi

    rc=$?
    log_file_append_from_file "$tmp"

    if grep -qiE 'Could not get lock|Unable to acquire the dpkg frontend lock|Could not open lock file|Unable to lock directory|is another process using it' "$tmp"; then
      if (( log_emitted == 0 )); then
        warn "apt/dpkg is locked by another process, waiting up to ${timeout} seconds"
        log_emitted=1
      elif (( waited > 0 && waited % 30 == 0 )); then
        log "Still waiting for apt/dpkg lock after ${waited} seconds"
      fi

      if (( waited >= timeout )); then
        sed -n '1,120p' "$tmp" >&2 || true
        rm -f "$tmp"
        die "Timed out waiting for apt/dpkg lock"
      fi

      rm -f "$tmp"
      sleep "$interval"
      waited=$((waited + interval))
      continue
    fi

    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    return "$rc"
  done
}

install_packages() {
  log "Проверка и установка системных зависимостей"
  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt_get_retry update -y
    apt_get_retry install -y curl jq ca-certificates openssl socat iptables iproute2 logrotate fail2ban tar
  elif have_cmd dnf; then
    run_install_detail dnf install -y curl jq ca-certificates openssl socat iptables iproute logrotate fail2ban tar
  elif have_cmd yum; then
    run_install_detail yum install -y curl jq ca-certificates openssl socat iptables iproute logrotate fail2ban tar
  else
    die "Unsupported package manager. Supported: apt, dnf, yum"
  fi
  ok "System dependencies are ready"
}

setup_command_logging() {
  local log_dir=""

  [[ "${INSTALL_LOG_ACTIVE:-0}" == "1" ]] && return 0

  load_saved_config
  rebuild_runtime_paths
  log_dir="$(dirname "$INSTALL_LOG_FILE")"
  mkdir -p "$log_dir" >/dev/null 2>&1 || return 0
  touch "$INSTALL_LOG_FILE" >/dev/null 2>&1 || return 0
  chmod 600 "$INSTALL_LOG_FILE" >/dev/null 2>&1 || true

  export INSTALL_LOG_ACTIVE=1
  if have_cmd tee; then
    exec > >(tee -a "$INSTALL_LOG_FILE") 2>&1
  else
    exec >>"$INSTALL_LOG_FILE" 2>&1
  fi
}

show_install_logs() {
  local arg="${1:-}"
  local -a tail_args=()

  load_saved_config
  rebuild_runtime_paths
  [[ -f "$INSTALL_LOG_FILE" ]] || die "Install log not found: $INSTALL_LOG_FILE"

  if [[ "$arg" == "-f" || "$arg" == "--follow" ]]; then
    tail_args=(-n 200 -f)
  elif [[ -n "$arg" ]]; then
    [[ "$arg" =~ ^[0-9]+$ ]] || die "Usage: install-logs [lines|-f]"
    tail_args=(-n "$arg")
  else
    tail_args=(-n 200)
  fi

  tail "${tail_args[@]}" "$INSTALL_LOG_FILE"
}

install_global_node_help() {
  local installed_script="$BASE_DIR/install.sh"
  local wrapper_path wrapper_name wrapper_target
  local -a script_wrappers=(
    "node-help:node-help"
    "status:status"
    "install-logs:install-logs"
    "install-node:install-node"
    "start-node:start-node"
    "stop-node:stop-node"
    "restart-node:restart-node"
    "logs-node:logs-node"
    "logs-node-live:logs-node-live"
    "logs-node-error:logs-node-error"
    "logs-node-access:logs-node-access"
    "logs-node-xray-out:logs-node-xray-out"
    "logs-node-xray-err:logs-node-xray-err"
    "issue:issue"
    "renew:renew"
    "open80:open80"
    "close80:close80"
    "lockdown80:lockdown80"
    "fail2ban-status:fail2ban-status"
    "fail2ban-sshd:fail2ban-sshd"
    "fail2ban-nginx:fail2ban-nginx"
  )

  mkdir -p "$GLOBAL_COMMANDS_DIR"

  for wrapper_name in "${script_wrappers[@]}"; do
    wrapper_target="${wrapper_name#*:}"
    wrapper_name="${wrapper_name%%:*}"
    wrapper_path="$GLOBAL_COMMANDS_DIR/$wrapper_name"

    case "$wrapper_target" in
      node-help)
        cat > "$wrapper_path" <<EOF
#!/usr/bin/env bash
exec $(quote_sh "$installed_script") node-help "\$@"
EOF
        ;;
      fail2ban-status)
        cat > "$wrapper_path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  exec fail2ban-client status "$@"
fi
exec sudo fail2ban-client status "$@"
EOF
        ;;
      fail2ban-sshd)
        cat > "$wrapper_path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  exec fail2ban-client status sshd "$@"
fi
exec sudo fail2ban-client status sshd "$@"
EOF
        ;;
      fail2ban-nginx)
        cat > "$wrapper_path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  exec fail2ban-client status remnanode-nginx-botsearch "$@"
fi
exec sudo fail2ban-client status remnanode-nginx-botsearch "$@"
EOF
        ;;
      *)
        cat > "$wrapper_path" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "\${EUID:-\$(id -u)}" -eq 0 ]]; then
  exec bash $(quote_sh "$installed_script") $(quote_sh "$wrapper_target") "\$@"
fi
exec sudo bash $(quote_sh "$installed_script") $(quote_sh "$wrapper_target") "\$@"
EOF
        ;;
    esac
    chmod +x "$wrapper_path"
  done

  ok "Global command wrappers installed in $GLOBAL_COMMANDS_DIR"
}

validate_nginx_inside_container() {
  local tmp
  tmp="$(mktemp)"
  log "Validating nginx config inside container"
  if ! compose_nginx exec -T "$CONTAINER_NAME" nginx -t >"$tmp" 2>&1; then
    log_file_append_from_file "$tmp"
    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    die "nginx config inside container is invalid"
  fi
  log_file_append_from_file "$tmp"
  rm -f "$tmp"
  ok "nginx config inside container is valid"
}

ensure_acme_installed() {
  local install_output="" rc=0 tmpdir="" archive="" installer_bin="" installer_dir=""
  local -a install_args=()

  if [[ -x "$ACME" ]]; then
    run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
    run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
    ok "acme.sh already installed"
    return 0
  fi

  log "Installing acme.sh into $ACME_HOME"
  tmpdir="$(mktemp -d)"
  archive="$tmpdir/acme.sh.tar.gz"

  curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz" -o "$archive" >>"$INSTALL_LOG_FILE" 2>&1 || {
    rm -rf "$tmpdir"
    die "Failed to download acme.sh"
  }
  tar -xzf "$archive" -C "$tmpdir" >>"$INSTALL_LOG_FILE" 2>&1 || {
    rm -rf "$tmpdir"
    die "Failed to extract acme.sh"
  }

  installer_bin="$(find "$tmpdir" -maxdepth 2 -type f -name acme.sh | head -n1)"
  [[ -n "$installer_bin" ]] || {
    rm -rf "$tmpdir"
    die "Failed to find acme.sh installer"
  }
  installer_dir="$(dirname "$installer_bin")"
  mkdir -p "$(dirname "$ACME_HOME")"

  install_args=(--install --home "$ACME_HOME" --nocron)
  if [[ -n "$ACME_EMAIL" ]]; then
    install_args+=(--accountemail "$ACME_EMAIL")
  fi

  install_output="$(
    (
      cd "$installer_dir"
      env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_COMMAND HOME=/root \
        ./acme.sh "${install_args[@]}"
    ) 2>&1
  )" || rc=$?

  [[ -n "$install_output" ]] && printf '%s\n' "$install_output" >>"$INSTALL_LOG_FILE"
  rm -rf "$tmpdir"

  (( rc == 0 )) || die "Failed to install acme.sh"
  [[ -x "$ACME" ]] || die "acme.sh binary not found after install"

  run_acme --home "$ACME_HOME" --uninstall-cronjob >/dev/null 2>&1 || true
  run_acme --home "$ACME_HOME" --set-default-ca --server "$LE_SERVER" >/dev/null 2>&1 || true
  ok "acme.sh installed into $ACME_HOME; cron disabled in favor of systemd timer"
}

start_nginx_helper() {
  log "Starting nginx helper"
  compose_try_logged "$COMPOSE_FILE" pull --quiet || true
  compose_try_logged "$COMPOSE_FILE" down --remove-orphans || true
  compose_must_logged "$COMPOSE_FILE" up -d
}

install_one_cert() {
  local domain="$1"
  local -a install_args
  local fullchain privkey
  local acme_issue_log acme_install_log

  fullchain="$(cert_fullchain_path "$domain")"
  privkey="$(cert_privkey_path "$domain")"
  acme_issue_log="/tmp/remnawave-acme-issue-${domain//[^a-zA-Z0-9_.-]/_}.log"
  acme_install_log="/tmp/remnawave-acme-install-${domain//[^a-zA-Z0-9_.-]/_}.log"

  log "Issuing certificate for ${domain}"
  if ! run_acme --home "$ACME_HOME" --issue -d "$domain" -w "$ACME_WEBROOT" --keylength "$ACME_KEYLENGTH" >"$acme_issue_log" 2>&1; then
    log_file_append_from_file "$acme_issue_log"
    if grep -Eq 'Domains not changed\.|Skipping\.' "$acme_issue_log"; then
      log "Certificate for ${domain} already exists and does not need renewal yet"
    else
      sed -n '1,120p' "$acme_issue_log" >&2 || true
      rm -f "$acme_issue_log" "$acme_install_log"
      die "Failed to issue certificate for ${domain}"
    fi
  else
    log_file_append_from_file "$acme_issue_log"
  fi

  install_args=(--home "$ACME_HOME" --install-cert -d "$domain")
  if [[ "$ACME_KEYLENGTH" == ec-* ]]; then
    install_args+=(--ecc)
  fi
  install_args+=(
    --fullchain-file "$fullchain"
    --key-file "$privkey"
    --reloadcmd "$RELOAD_HELPER"
  )
  if ! run_acme "${install_args[@]}" >"$acme_install_log" 2>&1; then
    log_file_append_from_file "$acme_install_log"
    sed -n '1,120p' "$acme_install_log" >&2 || true
    rm -f "$acme_issue_log" "$acme_install_log"
    die "Failed to install certificate for ${domain}"
  fi
  log_file_append_from_file "$acme_install_log"
  rm -f "$acme_issue_log" "$acme_install_log"

  chmod 640 "$fullchain" "$privkey"
  ok "Certificate saved: $fullchain"
  ok "Private key saved: $privkey"
}

write_systemd_units() {
  local installed_script
  installed_script="$BASE_DIR/install.sh"

  cat > "$SERVICE_RENEW" <<SERVICE
[Unit]
Description=Renew Let's Encrypt certificates for remnawave/Xray
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} renew
SERVICE

  cat > "$TIMER_RENEW" <<TIMER
[Unit]
Description=Daily renewal check for remnawave/Xray certificates

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  cat > "$SERVICE_LOCKDOWN" <<SERVICE
[Unit]
Description=Apply remnawave port 80 lockdown after Docker starts
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
EnvironmentFile=-${CONFIG_FILE}
ExecStart=${installed_script} lockdown80
RemainAfterExit=yes
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
SERVICE

  chmod 644 "$SERVICE_RENEW" "$TIMER_RENEW" "$SERVICE_LOCKDOWN"
  systemctl daemon-reload >>"$INSTALL_LOG_FILE" 2>&1
  systemctl enable --now remnawave-acme-renew.timer >>"$INSTALL_LOG_FILE" 2>&1
  systemctl enable --now remnawave-port80-lockdown.service >>"$INSTALL_LOG_FILE" 2>&1
  ok "Systemd timer and 80/tcp lockdown service are enabled"
}

start_remnanode() {
  [[ "$AUTO_INSTALL_NODE" =~ ^(1|yes|true)$ ]] || {
    warn "remnanode installation is disabled"
    return 0
  }

  if [[ "$PANEL_AUTO_REGISTER_NODE" =~ ^(1|yes|true)$ && -n "$PANEL_DOMAIN" && -n "$PANEL_API_TOKEN" ]] && \
     [[ -z "$PANEL_NODE_UUID" || -z "$SECRET_KEY" ]]; then
    ensure_panel_node_registered
  fi

  [[ -n "$SECRET_KEY" ]] || die "SECRET_KEY for remnanode is not set"
  write_remnanode_env
  write_remnanode_logrotate
  write_remnanode_compose

  log "Starting remnanode"
  compose_try_logged "$REMNANODE_COMPOSE_FILE" pull --quiet || true
  compose_try_logged "$REMNANODE_COMPOSE_FILE" down --remove-orphans || true
  compose_must_logged "$REMNANODE_COMPOSE_FILE" up -d --force-recreate
  ok "remnanode started"
}

show_install_node_logs() {
  if ! have_cmd docker; then
    return 0
  fi
  if ! docker ps -a --format '{{.Names}}' | grep -qx "$REMNANODE_CONTAINER_NAME"; then
    return 0
  fi

  log "Saving remnanode startup Docker logs to $INSTALL_LOG_FILE"
  docker logs --tail=200 --timestamps "$REMNANODE_CONTAINER_NAME" >>"$INSTALL_LOG_FILE" 2>&1 || true
}

print_fail2ban_hints() {
  cat <<'EOT'

Useful fail2ban commands:
  fail2ban-status
  fail2ban-sshd
  fail2ban-nginx
  sudo fail2ban-client status
  sudo fail2ban-client status sshd
  sudo fail2ban-client status remnanode-nginx-botsearch
EOT
}

print_node_hints() {
  local installed_script="$BASE_DIR/install.sh"
  cat <<EOT

Useful commands:
  status
  start-node
  stop-node
  restart-node
  logs-node
  logs-node-live
  logs-node-error
  logs-node-access
  logs-node-xray-out
  logs-node-xray-err
  issue
  renew
  install-logs
  install-logs -f

Fallback with explicit script path:
  sudo bash ${installed_script} status
  sudo bash ${installed_script} start-node
  sudo bash ${installed_script} stop-node
  sudo bash ${installed_script} restart-node
  sudo bash ${installed_script} logs-node
  sudo bash ${installed_script} logs-node-live
  sudo bash ${installed_script} logs-node-error
  sudo bash ${installed_script} logs-node-access
  sudo bash ${installed_script} logs-node-xray-out
  sudo bash ${installed_script} logs-node-xray-err
  sudo bash ${installed_script} issue
  sudo bash ${installed_script} renew
  sudo bash ${installed_script} install-logs

Full install log file:
  ${INSTALL_LOG_FILE}
EOT
}

print_node_help() {
  local installed_script="$BASE_DIR/install.sh"
  cat <<EOT
Commands:
  status
  start-node
  stop-node
  restart-node
  logs-node
  logs-node-live
  logs-node-error
  logs-node-access
  logs-node-xray-out
  logs-node-xray-err
  issue
  renew
  open80
  close80
  lockdown80
  install-logs
  install-logs -f
  fail2ban-status
  fail2ban-sshd
  fail2ban-nginx

Fallback with explicit script path:
  sudo bash ${installed_script} status
  sudo bash ${installed_script} start-node
  sudo bash ${installed_script} stop-node
  sudo bash ${installed_script} restart-node
  sudo bash ${installed_script} logs-node
  sudo bash ${installed_script} logs-node-live
  sudo bash ${installed_script} logs-node-error
  sudo bash ${installed_script} logs-node-access
  sudo bash ${installed_script} logs-node-xray-out
  sudo bash ${installed_script} logs-node-xray-err
  sudo bash ${installed_script} issue
  sudo bash ${installed_script} renew
  sudo bash ${installed_script} install-logs

First install:
  cd ~/installer_ssl_node && sudo bash ./install.sh de1.example.site
EOT
}

usage() {
  cat <<EOT
Usage:
  $SCRIPT_NAME install [domains...]
  $SCRIPT_NAME install-node
  $SCRIPT_NAME start-node
  $SCRIPT_NAME stop-node
  $SCRIPT_NAME restart-node
  $SCRIPT_NAME logs-node
  $SCRIPT_NAME logs-node-live
  $SCRIPT_NAME logs-node-error
  $SCRIPT_NAME logs-node-access
  $SCRIPT_NAME logs-node-xray-out
  $SCRIPT_NAME logs-node-xray-err
  $SCRIPT_NAME issue
  $SCRIPT_NAME renew
  $SCRIPT_NAME open80
  $SCRIPT_NAME close80
  $SCRIPT_NAME lockdown80
  $SCRIPT_NAME status
  $SCRIPT_NAME install-logs [lines|-f]
  $SCRIPT_NAME node-help
EOT
}

main() {
  init_colors

  local cmd="${1:-install}"
  case "$cmd" in
    install|install-node|start-node|stop-node|restart-node|logs-node|logs-node-live|logs-node-error|logs-node-access|logs-node-xray-out|logs-node-xray-err|issue|renew|open80|close80|lockdown80|status|install-logs|node-help|help|-h|--help)
      shift || true
      ;;
    *)
      cmd="install"
      ;;
  esac

  if [[ "$cmd" == "install" && $# -gt 0 ]]; then
    EXTRA_INSTALL_DOMAINS="$*"
  fi

  case "$cmd" in
    node-help|help|-h|--help|install-logs)
      ;;
    *)
      setup_command_logging
      ;;
  esac

  if [[ "${EUID:-$(id -u)}" -eq 0 && -f "$BASE_DIR/install.sh" ]]; then
    case "$cmd" in
      install)
        ;;
      *)
        install_global_node_help >/dev/null 2>&1 || true
        ;;
    esac
  fi

  log "Running install.sh: command=${cmd}, dir=${SCRIPT_DIR}"

  case "$cmd" in
    install)
      install_all
      ;;
    install-node)
      install_node_only
      ;;
    start-node)
      require_root
      load_runtime_or_die
      check_prereqs
      start_remnanode
      ;;
    stop-node)
      require_root
      check_prereqs
      load_runtime_or_die
      stop_remnanode
      ;;
    restart-node)
      require_root
      check_prereqs
      load_runtime_or_die
      restart_remnanode
      ;;
    logs-node)
      require_root
      check_prereqs
      load_runtime_or_die
      show_recent_node_logs
      ;;
    logs-node-live)
      require_root
      check_prereqs
      load_runtime_or_die
      show_live_node_logs
      ;;
    logs-node-error)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_error_log
      ;;
    logs-node-access)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_access_log
      ;;
    logs-node-xray-out)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_xray_out_log
      ;;
    logs-node-xray-err)
      require_root
      check_prereqs
      load_runtime_or_die
      show_node_xray_err_log
      ;;
    issue)
      require_root
      check_prereqs
      load_runtime_or_die
      issue_all_certs
      ;;
    renew)
      require_root
      check_prereqs
      load_runtime_or_die
      renew_cert
      ;;
    open80)
      require_root
      open80
      ;;
    close80)
      require_root
      close80
      ;;
    lockdown80)
      require_root
      lockdown80
      ;;
    status)
      require_root
      load_runtime_or_die
      status
      ;;
    install-logs)
      require_root
      show_install_logs "$@"
      ;;
    node-help|help|-h|--help)
      print_node_help
      ;;
  esac
}

install_packages() {
  log "Checking and installing system dependencies"
  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt_get_retry update -y
    apt_get_retry install -y curl jq ca-certificates openssl socat iptables iproute2 logrotate fail2ban tar
  elif have_cmd dnf; then
    run_install_detail dnf install -y curl jq ca-certificates openssl socat iptables iproute logrotate fail2ban tar
  elif have_cmd yum; then
    run_install_detail yum install -y curl jq ca-certificates openssl socat iptables iproute logrotate fail2ban tar
  else
    die "Unsupported package manager. Supported: apt, dnf, yum"
  fi
  ok "System dependencies are ready"
}

install_node_only() {
  require_root
  require_installer_env
  load_runtime_or_die
  log "Starting remnanode install/update"
  prompt_node_settings
  [[ "$AUTO_INSTALL_NODE" =~ ^(1|yes|true)$ ]] || return 0
  save_config
  install_packages
  check_prereqs
  install_self_copy
  install_global_node_help
  enable_fail2ban
  start_remnanode
  show_install_node_logs 6
  print_fail2ban_hints
  print_node_hints
  ok "remnanode install/update completed"
}

install_all() {
  require_root
  require_installer_env
  load_saved_config
  prompt_install_docker_if_missing
  if [[ -n "$EXTRA_INSTALL_DOMAINS" ]]; then
    prepare_domains_from_runtime
  else
    prompt_if_needed_for_install
  fi
  apply_domain_defaults
  ACME_EMAIL="${ACME_EMAIL:-admin@${DOMAINS_ARR[0]}}"
  log "Starting full install for domains: ${DOMAINS}"
  prompt_node_settings
  save_config
  install_packages
  check_prereqs
  ensure_dirs
  install_site_assets
  write_compose
  write_nginx_conf
  write_reload_helper
  install_self_copy
  install_global_node_help
  enable_fail2ban
  issue_all_certs
  write_systemd_units
  start_remnanode
  print_tls_hints
  print_fail2ban_hints
  print_node_hints
  show_install_node_logs 6
  ok "Installation completed"
}

main "$@"
