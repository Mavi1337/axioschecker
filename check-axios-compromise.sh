#!/usr/bin/env bash
# =============================================================================
# Axios Supply Chain Attack — Compromise Detection & Remediation Script
# CVE / Incident: axios@1.14.1 + axios@0.30.4 / plain-crypto-js@4.2.1 RAT
# C2: sfrclak.com:8000 / 142.11.206.73
# Refs: https://socket.dev/blog/axios-npm-package-compromised
#       https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
# Date: 2026-03-31
#
# IMPORTANT: The malware self-destructs after execution and removes evidence
# from node_modules. If the package was installed and run (npm install /
# postinstall executed), assume compromise even if node_modules looks clean.
# Lockfiles are the reliable indicator — they cannot self-delete.
# =============================================================================

set -uo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

flag()    { echo -e "${RED}[COMPROMISED]${RESET} $*"; FINDINGS=$((FINDINGS+1)); }
at_risk() { echo -e "${MAGENTA}[AT-RISK]${RESET}     $*"; AT_RISKS=$((AT_RISKS+1)); }
warn()    { echo -e "${YELLOW}[WARN]${RESET}        $*"; WARNINGS=$((WARNINGS+1)); }
ok()      { echo -e "${GREEN}[OK]${RESET}          $*"; }
info()    { echo -e "${CYAN}[INFO]${RESET}        $*"; }
title()   { echo; echo -e "${BOLD}━━━  $*  ━━━${RESET}"; }

FINDINGS=0
AT_RISKS=0
WARNINGS=0

# Remediation queue — parallel arrays: file path, fix type, description
REMED_FILES=()
REMED_TYPES=()
REMED_DESCS=()
REMED_SAFE_VERS=()   # safe version to pin to

add_remediation() {   # usage: add_remediation <file> <type> <description> <safe_version>
  REMED_FILES+=("$1")
  REMED_TYPES+=("$2")
  REMED_DESCS+=("$3")
  REMED_SAFE_VERS+=("$4")
}

# ── malicious / safe versions ─────────────────────────────────────────────────
BAD_VERS=("1.14.1" "0.30.4")   # both affected branches
# Returns the safe pinned version for a given bad version
safe_ver_for() {
  case "$1" in
    1.14.1) echo "1.14.0" ;;
    0.30.4) echo "0.30.3" ;;
    *)      echo "1.14.0" ;;
  esac
}

is_bad_ver() {   # usage: is_bad_ver <version_string>   returns 0 if bad
  local v="$1"
  for bad in "${BAD_VERS[@]}"; do [[ "$v" == "$bad" ]] && return 0; done
  return 1
}

# ── check whether a bad axios version is installed in node_modules ────────────
# Returns 0 (true) if a malicious version is installed; sets INSTALLED_BAD_VER
INSTALLED_BAD_VER=""
axios_installed_at() {   # arg: lockfile or package.json path
  local dir; dir="$(dirname "$1")"
  local pkg="$dir/node_modules/axios/package.json"
  [[ -f "$pkg" ]] || return 1
  local ver
  ver=$(python3 -c "import json,sys; print(json.load(open('$pkg')).get('version',''))" 2>/dev/null) || return 1
  if is_bad_ver "$ver"; then
    INSTALLED_BAD_VER="$ver"
    return 0
  fi
  return 1
}

# ── detect OS ────────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Darwin) PLATFORM="macOS" ;;
  Linux)  PLATFORM="Linux" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo -e "${BOLD}"
echo "============================================================"
echo " Axios Supply Chain Attack — Compromise Checker"
echo " Platform : $PLATFORM  |  Host: $(hostname)"
echo " Date     : $(date)"
echo "============================================================"
echo -e "${RESET}"
echo -e "${YELLOW}NOTE: The malware self-destructs after install. Lockfiles are${RESET}"
echo -e "${YELLOW}      the reliable source of truth — check section 5 carefully.${RESET}"

# ── collect all home directories ─────────────────────────────────────────────
HOMEDIRS=()
if [[ "$PLATFORM" == "macOS" ]]; then
  while IFS= read -r d; do
    [[ -d "$d" ]] && HOMEDIRS+=("$d")
  done < <(dscl . -list /Users HomeDirectory 2>/dev/null | awk '{print $2}' | grep -v '^/var/empty')
else
  while IFS=: read -r _ _ uid _ _ homedir _; do
    [[ $uid -ge 1000 && -d "$homedir" ]] && HOMEDIRS+=("$homedir")
  done < /etc/passwd
fi
[[ ${#HOMEDIRS[@]} -eq 0 ]] && HOMEDIRS=("$HOME")

info "Checking home directories: ${HOMEDIRS[*]}"

# =============================================================================
title "1. Malware Dropper Files (IoC Files)"
# =============================================================================

if [[ "$PLATFORM" == "Linux" ]]; then
  if [[ -f /tmp/ld.py ]]; then
    flag "/tmp/ld.py EXISTS — RAT dropper found (system actively compromised)"
    ls -la /tmp/ld.py
  else
    ok "/tmp/ld.py — not found"
  fi
fi

if [[ "$PLATFORM" == "macOS" ]]; then
  if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
    flag "/Library/Caches/com.apple.act.mond EXISTS — RAT dropper found (system actively compromised)"
    ls -la "/Library/Caches/com.apple.act.mond"
  else
    ok "/Library/Caches/com.apple.act.mond — not found"
  fi
fi

for tmpdir in /tmp /var/tmp /dev/shm; do
  if [[ -f "$tmpdir/ld.py" ]]; then
    flag "$tmpdir/ld.py EXISTS"
    ls -la "$tmpdir/ld.py"
  fi
done

# =============================================================================
title "2. Network — Active Connections to C2"
# =============================================================================

C2_IP="142.11.206.73"
C2_HOST="sfrclak.com"

if command -v ss &>/dev/null; then
  if ss -tnp 2>/dev/null | grep -qE "$C2_IP|$C2_HOST"; then
    flag "Active network connection to C2 detected"
    ss -tnp | grep -E "$C2_IP|$C2_HOST"
  else
    ok "No active connections to $C2_IP / $C2_HOST"
  fi
elif command -v netstat &>/dev/null; then
  if netstat -an 2>/dev/null | grep -qE "$C2_IP"; then
    flag "Active network connection to C2 IP detected"
    netstat -an | grep "$C2_IP"
  else
    ok "No active connections to $C2_IP"
  fi
fi

if command -v lsof &>/dev/null; then
  if lsof -i 2>/dev/null | grep -qE "$C2_IP|$C2_HOST"; then
    flag "lsof: open connection to C2"
    lsof -i 2>/dev/null | grep -E "$C2_IP|$C2_HOST"
  fi
fi

# =============================================================================
title "3. Network — DNS / Hosts / Resolver History"
# =============================================================================

if grep -qE "$C2_HOST|$C2_IP" /etc/hosts 2>/dev/null; then
  HOSTS_LINE=$(grep -E "$C2_HOST|$C2_IP" /etc/hosts)
  if echo "$HOSTS_LINE" | grep -q "^127\."; then
    warn "/etc/hosts blocks $C2_HOST → $(echo "$HOSTS_LINE" | head -1) (good if defensive; verify if unexpected)"
  else
    flag "/etc/hosts redirects $C2_HOST to non-localhost: $HOSTS_LINE"
  fi
else
  ok "$C2_HOST not in /etc/hosts"
fi

if [[ "$PLATFORM" == "macOS" ]]; then
  if log show --predicate 'process == "mDNSResponder"' --last 24h 2>/dev/null | grep -qi "$C2_HOST"; then
    warn "mDNSResponder logs: recent DNS query for $C2_HOST"
  else
    ok "No mDNSResponder DNS history for $C2_HOST"
  fi
fi

if command -v journalctl &>/dev/null; then
  if journalctl -n 5000 --no-pager 2>/dev/null | grep -qiE "$C2_HOST|$C2_IP"; then
    flag "System journal contains C2 references"
    journalctl -n 5000 --no-pager 2>/dev/null | grep -iE "$C2_HOST|$C2_IP" | head -20
  else
    ok "No C2 references in system journal"
  fi
fi

# =============================================================================
title "4. Malicious npm Packages Installed"
# =============================================================================
# NOTE: The malware postinstall hook self-destructs — absence here does NOT
# mean safe if npm install was run. Lockfile check (section 5) is more reliable.

check_npm_dir() {
  local base="$1"
  local axios_pkg="$base/node_modules/axios/package.json"
  if [[ -f "$axios_pkg" ]]; then
    local ver
    ver=$(python3 -c "import json; print(json.load(open('$axios_pkg')).get('version','?'))" 2>/dev/null \
       || grep -m1 '"version"' "$axios_pkg" | tr -d ' ",' | cut -d: -f2)
    if is_bad_ver "$ver"; then
      flag "axios@$ver (malicious) installed at $base"
      warn "The malware may have already executed its postinstall hook. Treat as active compromise."
    else
      ok "axios@$ver at $base"
    fi
  fi
  local pcjs="$base/node_modules/plain-crypto-js"
  if [[ -d "$pcjs" ]]; then
    local pcver
    pcver=$(python3 -c "import json; print(json.load(open('$pcjs/package.json')).get('version','?'))" 2>/dev/null || echo "?")
    flag "plain-crypto-js@$pcver (malicious dependency) present at $pcjs"
  fi
}

for npmroot in \
  "$(npm root -g 2>/dev/null || true)" \
  "/usr/lib/node_modules" \
  "/usr/local/lib/node_modules"; do
  [[ -d "$npmroot" ]] && check_npm_dir "$(dirname "$npmroot")"
done

for homedir in "${HOMEDIRS[@]}"; do
  while IFS= read -r d; do
    check_npm_dir "$(dirname "$d")"
  done < <(find "$homedir/.nvm" -maxdepth 5 -name "node_modules" -type d 2>/dev/null | head -20)

  while IFS= read -r d; do
    check_npm_dir "$d"
  done < <(find "$homedir" -maxdepth 6 -name "node_modules" -type d \
            -not -path "*/.nvm/*" -not -path "*/node_modules/*/node_modules" 2>/dev/null | head -100)
done

for homedir in "${HOMEDIRS[@]}"; do
  for cachedir in "$homedir/.npm" "$homedir/Library/Caches/node-gyp"; do
    if [[ -d "$cachedir" ]] && find "$cachedir" -name "plain-crypto-js*" 2>/dev/null | grep -q .; then
      warn "plain-crypto-js found in npm cache $cachedir — package may have been installed previously"
      find "$cachedir" -name "plain-crypto-js*" 2>/dev/null
    fi
  done
done

# =============================================================================
title "5. Lockfiles & package.json — Malicious axios References"
# =============================================================================
# Lockfiles are the MOST RELIABLE indicator. The malware deletes itself from
# node_modules but cannot alter your checked-in lockfiles.

check_lockfile_bad_ver() {   # args: <file>   sets LOCKFILE_BAD_VER if found
  local f="$1"
  LOCKFILE_BAD_VER=""
  if [[ "$f" == *package-lock.json ]]; then
    LOCKFILE_BAD_VER=$(python3 -c "
import json,sys
try:
  d=json.load(open('$f'))
  for k,v in d.get('packages',{}).items():
    ver=v.get('version','')
    if 'axios'==k.split('/')[-1] and ver in ('1.14.1','0.30.4'):
      print(ver); sys.exit(0)
  dep=d.get('dependencies',{}).get('axios',{})
  ver=dep.get('version','')
  if ver in ('1.14.1','0.30.4'):
    print(ver); sys.exit(0)
  sys.exit(1)
except: sys.exit(1)
" 2>/dev/null) || true

  elif [[ "$f" == *yarn.lock ]]; then
    for bad in "${BAD_VERS[@]}"; do
      # Reset 'found' on blank lines so version matches stay inside the axios stanza
      if awk -v bv="$bad" '
          /^"?axios@/ { found=1 }
          /^[[:space:]]*$/ { found=0 }
          found && $0 ~ ("version \"" bv "\"") { rc=1; exit }
          END { exit !rc }
        ' "$f" 2>/dev/null; then
        LOCKFILE_BAD_VER="$bad"
        break
      fi
    done

  elif [[ "$f" == *pnpm-lock.yaml ]]; then
    for bad in "${BAD_VERS[@]}"; do
      if grep -A3 "^  /axios@" "$f" 2>/dev/null | grep -q "version: $bad"; then
        LOCKFILE_BAD_VER="$bad"
        break
      fi
    done
  fi
  [[ -n "$LOCKFILE_BAD_VER" ]]
}

for homedir in "${HOMEDIRS[@]}"; do

  # ── package.json ─────────────────────────────────────────────────────────
  while IFS= read -r f; do
    ver=$(python3 -c "
import json,sys
try:
  d=json.load(open('$f'))
  deps={**d.get('dependencies',{}),**d.get('devDependencies',{})}
  print(deps.get('axios',''))
except: pass
" 2>/dev/null)
    # strip semver prefix (^, ~, =, >=)
    bare_ver="${ver#[^~=>]*}"
    bare_ver="${ver//[^0-9.]/}"
    # just check substring match for simplicity
    for bad in "${BAD_VERS[@]}"; do
      if [[ "$ver" == *"$bad"* ]]; then
        safe=$(safe_ver_for "$bad")
        if axios_installed_at "$f"; then
          flag "$f specifies axios $ver AND is installed — treat as active compromise"
        else
          at_risk "$f specifies axios $ver — not yet installed"
          add_remediation "$f" "package_json" \
            "Pin axios $ver → $safe in $(basename "$f")" "$safe"
        fi
        break
      fi
    done
  done < <(find "$homedir" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | head -200)

  # ── lockfiles ─────────────────────────────────────────────────────────────
  while IFS= read -r f; do

    # plain-crypto-js in any lockfile
    if grep -q 'plain-crypto-js' "$f" 2>/dev/null; then
      if axios_installed_at "$f"; then
        flag "$f contains plain-crypto-js AND node_modules installed — active compromise"
      else
        # Malware self-destructs: lockfile reference means npm install was run
        flag "$f contains plain-crypto-js — postinstall hook likely executed, treat as compromised"
        warn "The malware self-destructs. If this project was ever installed, rotate credentials."
        add_remediation "$f" "lockfile_pcjs" \
          "Remove plain-crypto-js from $(basename "$f")" ""
      fi
    fi

    # malicious axios version in lockfile
    if check_lockfile_bad_ver "$f"; then
      bad="$LOCKFILE_BAD_VER"
      safe=$(safe_ver_for "$bad")
      if axios_installed_at "$f"; then
        # Installed AND bad version in lockfile — but malware may have self-destructed
        flag "$f resolves axios@$bad AND node_modules present — ran postinstall, assume compromised"
      else
        # Lockfile references bad version but node_modules not installed (or cleaned)
        # Could be: (a) never installed, (b) installed + malware self-destructed
        at_risk "$f resolves axios@$bad — no matching node_modules found"
        warn "If 'npm/yarn install' was ever run in this directory, the postinstall hook may have fired."
        if [[ "$f" == *yarn.lock ]]; then
          add_remediation "$f" "yarn_lock" \
            "Remove axios@$bad stanza from yarn.lock → safe re-resolve on next install" "$safe"
        elif [[ "$f" == *package-lock.json ]]; then
          add_remediation "$f" "package_lock" \
            "Remove axios@$bad entry from package-lock.json" "$safe"
        elif [[ "$f" == *pnpm-lock.yaml ]]; then
          add_remediation "$f" "pnpm_lock" \
            "Remove axios@$bad entry from pnpm-lock.yaml" "$safe"
        fi
      fi
    fi

  done < <(find "$homedir" \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
           -not -path "*/node_modules/*" 2>/dev/null | head -100)
done

# =============================================================================
title "6. Shell Profile Tampering (Persistence)"
# =============================================================================

SUSPICIOUS_PATTERNS=("plain-crypto" "sfrclak" "142\.11\.206\.73" "ld\.py" "act\.mond" "wt\.exe")

for homedir in "${HOMEDIRS[@]}"; do
  for profile in \
    "$homedir/.bashrc" "$homedir/.bash_profile" "$homedir/.profile" \
    "$homedir/.zshrc"  "$homedir/.zprofile"     "$homedir/.config/fish/config.fish"; do
    [[ -f "$profile" ]] || continue
    for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
      if grep -qE "$pat" "$profile" 2>/dev/null; then
        flag "$profile contains suspicious pattern: $pat"
        grep -nE "$pat" "$profile"
      fi
    done
  done
done

if [[ "$PLATFORM" == "macOS" ]]; then
  for homedir in "${HOMEDIRS[@]}"; do
    for plist in \
      "$homedir/Library/LaunchAgents/"*.plist \
      "/Library/LaunchAgents/"*.plist \
      "/Library/LaunchDaemons/"*.plist; do
      [[ -f "$plist" ]] || continue
      for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -qE "$pat" "$plist" 2>/dev/null; then
          flag "$plist contains suspicious pattern: $pat"
          grep -nE "$pat" "$plist"
        fi
      done
    done
  done
fi

if [[ "$PLATFORM" == "Linux" ]]; then
  for homedir in "${HOMEDIRS[@]}"; do
    for unit in \
      "$homedir/.config/systemd/user/"*.service \
      "$homedir/.config/systemd/user/"*.timer; do
      [[ -f "$unit" ]] || continue
      for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
        grep -qE "$pat" "$unit" 2>/dev/null && flag "$unit contains suspicious pattern: $pat"
      done
    done
  done
fi

for homedir in "${HOMEDIRS[@]}"; do
  username=$(basename "$homedir")
  crontab_content=$(crontab -u "$username" -l 2>/dev/null || true)
  if [[ -n "$crontab_content" ]]; then
    for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
      if echo "$crontab_content" | grep -qE "$pat"; then
        flag "crontab for $username contains suspicious pattern: $pat"
        echo "$crontab_content" | grep -E "$pat"
      fi
    done
  fi
done

# =============================================================================
title "7. Credential Directory Modifications"
# =============================================================================

for homedir in "${HOMEDIRS[@]}"; do
  for creddir in "$homedir/.ssh" "$homedir/.aws" "$homedir/.gnupg"; do
    [[ -d "$creddir" ]] || continue
    recent=$(find "$creddir" -newer /proc/1 -not -name "known_hosts*" 2>/dev/null | head -5)
    if [[ -n "$recent" ]]; then
      warn "Recently modified files in $creddir:"
      echo "$recent" | while IFS= read -r mf; do ls -la "$mf"; done
    else
      ok "$creddir — no unexpected recent modifications"
    fi
  done
done

# =============================================================================
title "8. Process Scan"
# =============================================================================

for pat in "ld.py" "plain-crypto" "act.mond" "wt.exe"; do
  if ps aux 2>/dev/null | grep -v grep | grep -qE "$pat"; then
    flag "Suspicious process running: $pat"
    ps aux | grep -v grep | grep -E "$pat"
  else
    ok "No running process matching: $pat"
  fi
done

# =============================================================================
title "9. Compromise Window — File Timestamp Analysis"
# =============================================================================
# Malicious packages were live between:
#   plain-crypto-js@4.2.1  published  2026-03-30 23:59 UTC
#   axios@1.14.1            published  2026-03-31 00:21 UTC
#   axios@0.30.4            published  2026-03-31 01:00 UTC
#   npm takedown (est.)                2026-03-31 ~08:00 UTC
#
# Any npm install run in that window against a project with a loose axios
# version constraint would have pulled the malicious version.
# =============================================================================

WIN_START=1743379140   # 2026-03-30 23:59:00 UTC
WIN_END=1743408000     # 2026-03-31 08:00:00 UTC (conservative)

in_window() {  # args: <file_or_dir>
  python3 -c "
import os,sys
try:
  m=os.path.getmtime('$1')
  sys.exit(0 if ${WIN_START}<=m<=${WIN_END} else 1)
except: sys.exit(1)
" 2>/dev/null
}

fmt_mtime() {  # print human mtime of a path
  python3 -c "
import os,datetime,timezone
try:
  from datetime import timezone
  m=os.path.getmtime('$1')
  print(datetime.datetime.fromtimestamp(m,tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
except: print('?')
" 2>/dev/null
}

# ── IoC files ────────────────────────────────────────────────────────────────
for ioc_file in /tmp/ld.py /var/tmp/ld.py "/Library/Caches/com.apple.act.mond"; do
  if [[ -f "$ioc_file" ]]; then
    if in_window "$ioc_file"; then
      flag "IoC $ioc_file was created during the compromise window ($(fmt_mtime "$ioc_file"))"
    else
      warn "IoC $ioc_file exists but mtime $(fmt_mtime "$ioc_file") is outside window — investigate"
    fi
  fi
done

# ── node_modules installed during window ─────────────────────────────────────
for homedir in "${HOMEDIRS[@]}"; do
  while IFS= read -r axios_dir; do
    if in_window "$axios_dir"; then
      ver=$(python3 -c "import json; print(json.load(open('$axios_dir/package.json')).get('version','?'))" 2>/dev/null || echo "?")
      if is_bad_ver "$ver"; then
        flag "axios@$ver at $axios_dir was installed during the compromise window ($(fmt_mtime "$axios_dir"))"
      else
        warn "axios@$ver at $axios_dir was installed during the compromise window ($(fmt_mtime "$axios_dir")) — verify it wasn't later cleaned"
      fi
    fi
  done < <(find "$homedir" -maxdepth 8 -type d -name "axios" -path "*/node_modules/axios" 2>/dev/null | head -50)

  while IFS= read -r pcjs_dir; do
    if in_window "$pcjs_dir"; then
      flag "plain-crypto-js at $pcjs_dir was installed during the compromise window ($(fmt_mtime "$pcjs_dir"))"
    else
      warn "plain-crypto-js at $pcjs_dir exists outside window ($(fmt_mtime "$pcjs_dir")) — still suspicious"
    fi
  done < <(find "$homedir" -maxdepth 8 -type d -name "plain-crypto-js" -path "*/node_modules/*" 2>/dev/null)
done

# ── npm / yarn log files during window ───────────────────────────────────────
for homedir in "${HOMEDIRS[@]}"; do
  # npm debug logs contain timestamps
  while IFS= read -r logfile; do
    if in_window "$logfile"; then
      warn "npm log created during compromise window: $logfile"
      # Check if log mentions axios or plain-crypto-js
      if grep -qiE "axios|plain-crypto" "$logfile" 2>/dev/null; then
        flag "npm log $logfile (in window) references axios or plain-crypto-js"
        grep -iE "axios|plain-crypto" "$logfile" | head -5
      fi
    fi
  done < <(find "$homedir/.npm/_logs" -name "*.log" 2>/dev/null | head -50)

  # yarn-error.log
  while IFS= read -r logfile; do
    if in_window "$logfile"; then
      warn "yarn error log created during compromise window: $logfile"
    fi
  done < <(find "$homedir" -maxdepth 6 -name "yarn-error.log" -not -path "*/node_modules/*" 2>/dev/null | head -20)
done

# ── shell history timestamps ──────────────────────────────────────────────────
for homedir in "${HOMEDIRS[@]}"; do
  # zsh extended history format: ': <epoch>:<elapsed>;<command>'
  for hist in "$homedir/.zsh_history" "$homedir/.zsh_history_ext"; do
    [[ -f "$hist" ]] || continue
    python3 - "$hist" <<'PYEOF' 2>/dev/null
import sys, re
WIN_START, WIN_END = 1743379140, 1743408000
hist = open(sys.argv[1], 'rb').read().decode('utf-8', errors='replace')
# zsh extended format: ': epoch:elapsed;command'
for m in re.finditer(r'^: (\d+):\d+;(.+)', hist, re.MULTILINE):
    ts, cmd = int(m.group(1)), m.group(2)
    if WIN_START <= ts <= WIN_END:
        if re.search(r'npm|yarn|pnpm|bun|install|add ', cmd, re.I):
            from datetime import datetime, timezone
            t = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            print(f'  WINDOW [{t}]: {cmd.strip()}')
PYEOF
    # if output was produced, flag it
    output=$(python3 - "$hist" <<'PYEOF' 2>/dev/null
import sys, re
WIN_START, WIN_END = 1743379140, 1743408000
hist = open(sys.argv[1], 'rb').read().decode('utf-8', errors='replace')
found = []
for m in re.finditer(r'^: (\d+):\d+;(.+)', hist, re.MULTILINE):
    ts, cmd = int(m.group(1)), m.group(2)
    if WIN_START <= ts <= WIN_END:
        if re.search(r'npm|yarn|pnpm|bun|install|add ', cmd, re.I):
            from datetime import datetime, timezone
            t = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M UTC')
            found.append(f'{t}: {cmd.strip()}')
for f in found: print(f)
PYEOF
)
    if [[ -n "$output" ]]; then
      warn "Package manager commands run during the compromise window (from $hist):"
      echo "$output" | while IFS= read -r line; do echo "       $line"; done
      if echo "$output" | grep -qiE "axios|wallet|airgap|keepkey|bitbox|electrum"; then
        flag "Package install during window touched a suspicious project — correlate with lockfiles"
      fi
    else
      ok "$hist — no package manager commands found in compromise window"
    fi
  done

  # bash history with HISTTIMEFORMAT (format: '#epoch\ncommand')
  for hist in "$homedir/.bash_history"; do
    [[ -f "$hist" ]] || continue
    output=$(python3 - "$hist" <<'PYEOF' 2>/dev/null
import sys, re
WIN_START, WIN_END = 1743379140, 1743408000
lines = open(sys.argv[1], 'rb').read().decode('utf-8', errors='replace').splitlines()
found = []
ts = None
for line in lines:
    m = re.match(r'^#(\d+)$', line)
    if m:
        ts = int(m.group(1))
    elif ts and WIN_START <= ts <= WIN_END:
        if re.search(r'npm|yarn|pnpm|bun|install|add ', line, re.I):
            from datetime import datetime, timezone
            t = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M UTC')
            found.append(f'{t}: {line.strip()}')
        ts = None
    else:
        ts = None
for f in found: print(f)
PYEOF
)
    if [[ -n "$output" ]]; then
      warn "Package manager commands run during compromise window (from $hist):"
      echo "$output" | while IFS= read -r line; do echo "       $line"; done
    else
      ok "$hist — no timestamped package manager commands in compromise window"
    fi
  done
done

# ── credential files modified during window ───────────────────────────────────
for homedir in "${HOMEDIRS[@]}"; do
  for creddir in "$homedir/.ssh" "$homedir/.aws" "$homedir/.gnupg" "$homedir/.npmrc"; do
    [[ -e "$creddir" ]] || continue
    if [[ -d "$creddir" ]]; then
      while IFS= read -r f; do
        if in_window "$f"; then
          flag "Credential file $f was modified during the compromise window ($(fmt_mtime "$f"))"
        fi
      done < <(find "$creddir" -type f 2>/dev/null)
    elif in_window "$creddir"; then
      flag "Credential file $creddir was modified during the compromise window ($(fmt_mtime "$creddir"))"
    fi
  done
done

# =============================================================================
title "10. Remediation"
# =============================================================================

if [[ ${#REMED_FILES[@]} -eq 0 ]]; then
  ok "No at-risk items requiring remediation"
else
  echo
  echo -e "${MAGENTA}${BOLD}The following files reference a malicious axios version.${RESET}"
  echo -e "${MAGENTA}No matching node_modules found — packages may not have been installed yet.${RESET}"
  echo -e "${YELLOW}⚠ If 'npm/yarn install' was already run, the postinstall hook may have fired.${RESET}"
  echo -e "${YELLOW}  In that case, also rotate credentials after applying these fixes.${RESET}"
  echo
  for i in "${!REMED_FILES[@]}"; do
    echo -e "  ${BOLD}[$((i+1))]${RESET} ${REMED_DESCS[$i]}"
    echo    "       ${REMED_FILES[$i]}"
  done
  echo
  echo -ne "${BOLD}Press ENTER to apply all fixes, or Ctrl+C to skip: ${RESET}"
  read -r _

  TS=$(date +%Y%m%d%H%M%S)

  for i in "${!REMED_FILES[@]}"; do
    f="${REMED_FILES[$i]}"
    t="${REMED_TYPES[$i]}"
    safe="${REMED_SAFE_VERS[$i]}"
    backup="${f}.bak.${TS}"
    echo
    echo -e "${CYAN}[$((i+1))] $f${RESET}"

    if ! cp "$f" "$backup"; then
      echo "  ERROR: could not create backup — skipping"
      continue
    fi
    echo "  Backed up → $backup"

    case "$t" in

      package_json)
        PKGJSON="$f" SAFE_VER="$safe" python3 - <<'PYEOF' || echo "  ERROR: patch failed"
import os, json, re
path, safe = os.environ['PKGJSON'], os.environ['SAFE_VER']
with open(path) as fh:
    raw = fh.read()
data = json.loads(raw)
changed = False
for section in ('dependencies', 'devDependencies'):
    if 'axios' in data.get(section, {}):
        ver = data[section]['axios']
        # Replace only the version number, preserve prefix (^, ~, etc.)
        new_ver = re.sub(r'(1\.14\.1|0\.30\.4)', safe, ver)
        if new_ver != ver:
            data[section]['axios'] = new_ver
            changed = True
if changed:
    indent = 2
    for line in raw.split('\n'):
        stripped = line.lstrip()
        if stripped and line != stripped:
            indent = len(line) - len(stripped)
            if indent in (2, 4):
                break
    with open(path, 'w') as fh:
        json.dump(data, fh, indent=indent, ensure_ascii=False)
        fh.write('\n')
    print(f'  Done — axios pinned to {safe}')
else:
    print('  Nothing changed')
PYEOF
        ;;

      yarn_lock)
        LOCKFILE="$f" python3 - <<'PYEOF' || echo "  ERROR: patch failed"
import os, re
lockfile = os.environ['LOCKFILE']
with open(lockfile) as fh:
    lines = fh.readlines()
out = []
i = 0
removed = 0
while i < len(lines):
    line = lines[i]
    if re.match(r'^"?axios@', line):
        stanza = [line]
        i += 1
        while i < len(lines) and lines[i].strip():
            stanza.append(lines[i])
            i += 1
        stanza_text = ''.join(stanza)
        if re.search(r'version "(1\.14\.1|0\.30\.4)"', stanza_text):
            removed += 1
            # skip blank separator
            if i < len(lines) and not lines[i].strip():
                i += 1
            continue
        out.extend(stanza)
    else:
        out.append(line)
        i += 1
with open(lockfile, 'w') as fh:
    fh.writelines(out)
print(f'  Done — removed {removed} malicious axios stanza(s)')
PYEOF
        ;;

      package_lock)
        LOCKFILE="$f" python3 - <<'PYEOF' || echo "  ERROR: patch failed"
import os, json
lockfile = os.environ['LOCKFILE']
BAD = {'1.14.1', '0.30.4'}
with open(lockfile) as fh:
    data = json.load(fh)
removed = []
for key in list(data.get('packages', {}).keys()):
    last = key.split('/')[-1]
    if last == 'axios' and data['packages'][key].get('version') in BAD:
        del data['packages'][key]; removed.append(key)
    elif 'plain-crypto-js' in key:
        del data['packages'][key]; removed.append(key)
for key in list(data.get('dependencies', {}).keys()):
    if key == 'axios' and data['dependencies'][key].get('version') in BAD:
        del data['dependencies'][key]; removed.append(key)
    elif key == 'plain-crypto-js':
        del data['dependencies'][key]; removed.append(key)
with open(lockfile, 'w') as fh:
    json.dump(data, fh, indent=2); fh.write('\n')
print(f'  Done — removed: {removed}')
PYEOF
        ;;

      pnpm_lock)
        LOCKFILE="$f" python3 - <<'PYEOF' || echo "  ERROR: patch failed"
import os, re
lockfile = os.environ['LOCKFILE']
with open(lockfile) as fh:
    content = fh.read()
cleaned = re.sub(r'\n  /axios@(1\.14\.1|0\.30\.4):(?:\n(?:    |\n).*)*', '', content)
cleaned = re.sub(r'\n  /plain-crypto-js@[^\n]+:(?:\n(?:    |\n).*)*', '', cleaned)
with open(lockfile, 'w') as fh:
    fh.write(cleaned)
print('  Done — removed malicious axios and plain-crypto-js entries')
PYEOF
        ;;

      lockfile_pcjs)
        if [[ "$f" == *yarn.lock ]]; then
          LOCKFILE="$f" python3 - <<'PYEOF' || echo "  ERROR: patch failed"
import os, re
lockfile = os.environ['LOCKFILE']
with open(lockfile) as fh:
    lines = fh.readlines()
out = []
i = 0
removed = 0
while i < len(lines):
    line = lines[i]
    if re.match(r'^"?plain-crypto-js@', line):
        stanza = [line]
        i += 1
        while i < len(lines) and lines[i].strip():
            stanza.append(lines[i]); i += 1
        removed += 1
        if i < len(lines) and not lines[i].strip():
            i += 1
        continue
    out.append(line); i += 1
with open(lockfile, 'w') as fh:
    fh.writelines(out)
print(f'  Done — removed {removed} plain-crypto-js stanza(s)')
PYEOF
        elif [[ "$f" == *package-lock.json ]]; then
          LOCKFILE="$f" python3 - <<'PYEOF' || echo "  ERROR: patch failed"
import os, json
lockfile = os.environ['LOCKFILE']
with open(lockfile) as fh:
    data = json.load(fh)
removed = []
for key in list(data.get('packages', {}).keys()):
    if 'plain-crypto-js' in key:
        del data['packages'][key]; removed.append(key)
data.get('dependencies', {}).pop('plain-crypto-js', None)
with open(lockfile, 'w') as fh:
    json.dump(data, fh, indent=2); fh.write('\n')
print(f'  Done — removed: {removed}')
PYEOF
        fi
        ;;

    esac
    echo -e "  ${GREEN}✔ Fixed${RESET}"
  done

  echo
  echo -e "${CYAN}Run this script again to verify all fixes were applied correctly.${RESET}"
fi

# =============================================================================
title "Summary"
# =============================================================================

echo
if [[ $FINDINGS -gt 0 && $AT_RISKS -gt 0 ]]; then
  echo -e "${RED}${BOLD}  ✖ COMPROMISED — $FINDINGS active indicator(s) found${RESET}"
  echo -e "${MAGENTA}${BOLD}  ⚠ AT-RISK    — $AT_RISKS lockfile reference(s) patched${RESET}"
  echo
  echo -e "${RED}  Immediate actions (active compromise):${RESET}"
  echo "  1. Isolate machine from network"
  echo "  2. Rotate ALL credentials: SSH keys, AWS/GCP/Azure keys, npm tokens, GitHub PATs, CI/CD secrets"
  echo "  3. Audit CI/CD logs for pipeline runs that installed affected axios versions"
  echo "  4. Run: npm cache clean --force && rm -rf node_modules"
  echo "  5. Check ~/.ssh/authorized_keys and cloud provider IAM for unknown entries"
  echo "  6. Do NOT try to clean in place — rebuild from a known-good state"
elif [[ $FINDINGS -gt 0 ]]; then
  echo -e "${RED}${BOLD}  ✖ COMPROMISED — $FINDINGS active indicator(s) of compromise found${RESET}"
  echo
  echo -e "${RED}  Immediate actions:${RESET}"
  echo "  1. Isolate machine from network"
  echo "  2. Rotate ALL credentials: SSH keys, AWS/GCP/Azure keys, npm tokens, GitHub PATs, CI/CD secrets"
  echo "  3. Audit CI/CD logs for pipeline runs that installed affected axios versions"
  echo "  4. Run: npm cache clean --force && rm -rf node_modules"
  echo "  5. Check ~/.ssh/authorized_keys and cloud provider IAM for unknown entries"
  echo "  6. Do NOT try to clean in place — rebuild from a known-good state"
elif [[ $AT_RISKS -gt 0 ]]; then
  if [[ ${#REMED_FILES[@]} -gt 0 ]]; then
    echo -e "${GREEN}${BOLD}  ✔ System was AT-RISK — fixes applied${RESET}"
    echo -e "${YELLOW}  Run this script again to confirm. If npm install was ever run in${RESET}"
    echo -e "${YELLOW}  the affected directories, rotate credentials as a precaution.${RESET}"
  else
    echo -e "${MAGENTA}${BOLD}  ⚠ AT-RISK — $AT_RISKS item(s) found, fixes skipped (run again to apply)${RESET}"
  fi
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "${YELLOW}${BOLD}  ⚠ $WARNINGS warning(s) — manual review recommended${RESET}"
else
  echo -e "${GREEN}${BOLD}  ✔ No indicators of compromise found${RESET}"
fi

echo
echo -e "${CYAN}  Malicious versions : axios@1.14.1 (1.x branch), axios@0.30.4 (0.x branch)${RESET}"
echo -e "${CYAN}  Malicious dep      : plain-crypto-js@4.2.1${RESET}"
echo -e "${CYAN}  Safe versions      : axios@1.14.0 (1.x), axios@0.30.3 (0.x)${RESET}"
echo -e "${CYAN}  C2 infrastructure  : sfrclak.com:8000 / 142.11.206.73${RESET}"
echo -e "${CYAN}  Attacker accounts  : ifstap@proton.me, nrwise@proton.me${RESET}"
echo
