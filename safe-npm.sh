#!/usr/bin/env bash
# =============================================================================
# safe-npm — lightweight npm/yarn/pnpm wrapper
#
# Implements the core protections from Aikido Safe Chain without the binary:
#   1. Blocks known-malicious packages (static + live Aikido Intel feed)
#   2. Blocks packages published within the last 48 hours (configurable)
#
# Install (add to shell profile):
#   source /path/to/safe-npm.sh
#
# This creates shell functions: npm, yarn, pnpm, npx
# The real binaries are called as 'command npm ...' to bypass the wrappers.
#
# To skip for one command:  SAFE_NPM_SKIP=1 npm install ...
# To change age limit:      SAFE_NPM_MIN_AGE_HOURS=24 npm install ...
# =============================================================================

SAFE_NPM_MIN_AGE_HOURS="${SAFE_NPM_MIN_AGE_HOURS:-48}"

# ── static malware blocklist ──────────────────────────────────────────────────
# Format: "package@version" or "package" to block all versions
SAFE_NPM_BLOCKLIST=(
  "plain-crypto-js@4.2.1"
  "axios@1.14.1"
  "axios@0.30.4"
)

# ── colours ───────────────────────────────────────────────────────────────────
_snpm_red()    { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
_snpm_yellow() { printf '\033[1;33m%s\033[0m\n' "$*" >&2; }
_snpm_green()  { printf '\033[0;32m%s\033[0m\n' "$*" >&2; }
_snpm_cyan()   { printf '\033[0;36m%s\033[0m\n' "$*" >&2; }

# ── fetch Aikido Intel live malware feed ──────────────────────────────────────
# Returns a newline-separated list of "package@version" strings
_snpm_live_blocklist() {
  if ! command -v curl &>/dev/null; then return; fi
  # Aikido Intel public API — returns JSON array of malware reports
  curl -fsSL --max-time 5 \
    "https://intel.aikido.dev/api/public/malware?ecosystem=npm&page_size=200" \
    2>/dev/null \
  | python3 -c "
import json,sys
try:
  data=json.load(sys.stdin)
  for entry in data.get('results',[]) or data if isinstance(data,list) else []:
    pkg=entry.get('package_name','') or entry.get('name','')
    ver=entry.get('package_version','') or entry.get('version','')
    if pkg:
      print(f'{pkg}@{ver}' if ver else pkg)
except: pass
" 2>/dev/null || true
}

# ── check if a package@version is in the blocklist ───────────────────────────
_snpm_is_blocked() {
  local spec="$1"   # e.g. "axios@1.14.1" or "axios"
  local pkg="${spec%%@*}"
  local ver="${spec#*@}"; [[ "$ver" == "$pkg" ]] && ver=""

  # Check static blocklist
  for entry in "${SAFE_NPM_BLOCKLIST[@]}"; do
    local bpkg="${entry%%@*}"
    local bver="${entry#*@}"; [[ "$bver" == "$bpkg" ]] && bver=""
    if [[ "$pkg" == "$bpkg" ]]; then
      if [[ -z "$bver" || -z "$ver" || "$ver" == "$bver" ]]; then
        echo "static blocklist"
        return 0
      fi
    fi
  done

  # Check live feed (cached for 1h in /tmp)
  local cache="/tmp/safe-npm-live-blocklist.txt"
  if [[ ! -f "$cache" ]] || \
     python3 -c "import os,time; exit(0 if time.time()-os.path.getmtime('$cache')<3600 else 1)" 2>/dev/null; then
    _snpm_live_blocklist > "$cache" 2>/dev/null || true
  fi
  if [[ -f "$cache" ]] && grep -qxF "${pkg}${ver:+@$ver}" "$cache" 2>/dev/null; then
    echo "live Aikido Intel feed"
    return 0
  fi

  return 1
}

# ── check package publication age via npm registry ────────────────────────────
# Returns 0 (ok) or 1 (too new)
_snpm_check_age() {
  local pkg="$1"   # package name, no version
  local ver="$2"   # version string, may be empty (→ check latest)

  command -v curl &>/dev/null || return 0   # can't check, allow
  command -v python3 &>/dev/null || return 0

  local min_hours="$SAFE_NPM_MIN_AGE_HOURS"

  python3 - "$pkg" "$ver" "$min_hours" <<'PYEOF' 2>/dev/null
import sys, json, urllib.request, urllib.error
from datetime import datetime, timezone

pkg, ver, min_hours = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    url = f"https://registry.npmjs.org/{pkg}"
    req = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as r:
        data = json.load(r)
    times = data.get('time', {})
    # Resolve 'latest' if no version given
    if not ver or ver in ('latest', '*', ''):
        ver = data.get('dist-tags', {}).get('latest', '')
    pub_str = times.get(ver, '')
    if not pub_str:
        sys.exit(0)  # unknown version, allow
    pub = datetime.fromisoformat(pub_str.replace('Z', '+00:00'))
    age_hours = (datetime.now(timezone.utc) - pub).total_seconds() / 3600
    if age_hours < min_hours:
        print(f'{age_hours:.1f}h old (min: {min_hours}h) published {pub_str}')
        sys.exit(1)
    sys.exit(0)
except Exception:
    sys.exit(0)  # network/parse error → allow (fail open)
PYEOF
}

# ── extract package specs from install command arguments ─────────────────────
# Handles: npm install pkg, npm install pkg@ver, npm i pkg@ver, --save etc.
_snpm_extract_packages() {
  local -a args=("$@")
  local -a pkgs=()
  local capture=0

  for arg in "${args[@]}"; do
    # Skip flags
    [[ "$arg" == --* || "$arg" == -* ]] && continue
    # Sub-commands that take package arguments
    case "$arg" in
      install|i|add|isntall) capture=1; continue ;;
      uninstall|remove|rm|un|r|update|up|upgrade|outdated|info|view|show|run|exec)
        capture=0; continue ;;
    esac
    [[ $capture -eq 1 && -n "$arg" ]] && pkgs+=("$arg")
  done
  printf '%s\n' "${pkgs[@]}"
}

# ── core wrapper logic ────────────────────────────────────────────────────────
_snpm_run() {
  local real_cmd="$1"; shift
  local -a original_args=("$@")

  # Allow bypass
  if [[ "${SAFE_NPM_SKIP:-}" == "1" ]]; then
    command "$real_cmd" "${original_args[@]}"
    return $?
  fi

  # Only inspect install/add commands
  local subcmd="${1:-}"
  case "$subcmd" in
    install|i|add|isntall) ;;
    *) command "$real_cmd" "${original_args[@]}"; return $? ;;
  esac

  _snpm_cyan "safe-npm: checking packages before install..."

  local blocked=0
  local too_new=()

  while IFS= read -r spec; do
    [[ -z "$spec" ]] && continue
    local pkg="${spec%%@*}"
    local ver="${spec#*@}"; [[ "$ver" == "$pkg" ]] && ver=""

    # Blocklist check
    local reason
    reason=$(_snpm_is_blocked "$spec") && {
      _snpm_red "safe-npm: BLOCKED — $spec is on the malware blocklist ($reason)"
      blocked=$((blocked+1))
    }

    # Age check (only for explicit installs, not bare 'npm install')
    if [[ -n "$pkg" ]]; then
      local age_info
      age_info=$(_snpm_check_age "$pkg" "$ver") && true || {
        too_new+=("$spec ($age_info)")
      }
    fi
  done < <(_snpm_extract_packages "${original_args[@]}")

  if [[ $blocked -gt 0 ]]; then
    _snpm_red "safe-npm: Installation aborted — $blocked malicious package(s) detected."
    return 1
  fi

  if [[ ${#too_new[@]} -gt 0 ]]; then
    _snpm_yellow "safe-npm: WARNING — the following packages were published within ${SAFE_NPM_MIN_AGE_HOURS}h:"
    for p in "${too_new[@]}"; do
      _snpm_yellow "  • $p"
    done
    _snpm_yellow "safe-npm: Newly published packages are high-risk (supply chain attacks)."
    printf '\033[1;33msafe-npm: Proceed anyway? [y/N]: \033[0m' >&2
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]] || { _snpm_red "safe-npm: Aborted."; return 1; }
  fi

  _snpm_green "safe-npm: OK — proceeding"
  command "$real_cmd" "${original_args[@]}"
}

# ── shell function wrappers ───────────────────────────────────────────────────
npm()  { _snpm_run npm  "$@"; }
npx()  { _snpm_run npx  "$@"; }
yarn() { _snpm_run yarn "$@"; }
pnpm() { _snpm_run pnpm "$@"; }

export -f npm npx yarn pnpm _snpm_run _snpm_is_blocked _snpm_check_age \
          _snpm_extract_packages _snpm_live_blocklist \
          _snpm_red _snpm_yellow _snpm_green _snpm_cyan 2>/dev/null || true

_snpm_cyan "safe-npm loaded — npm/yarn/pnpm/npx are now protected (min package age: ${SAFE_NPM_MIN_AGE_HOURS}h)"
_snpm_cyan "To skip: SAFE_NPM_SKIP=1 npm install ...    To add to shell: echo 'source $(realpath "${BASH_SOURCE[0]:-$0}")' >> ~/.zshrc"
