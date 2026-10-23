#!/bin/bash
# SlopBro security fork. Derived from throwaway96/slopbro.
# AGPL-3.0-or-later; see COPYING.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
readonly HBC_SHA256='d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c'
readonly ORIGINAL_STARTUP_SHA256='c8b5093eca9a78ef70b2742f60ab7b1a04e7c9331359f234bd40a0065238815b'
readonly PREF='/var/luna/preferences/devmode_enabled'
readonly STARTUP='/var/lib/webosbrew/startup.sh'
readonly SERVICE='/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service'
phase='preflight'
success=0
tempdir=''
preference_changed=0
preference_was_file=0
install_started=0
lock_owned=0
startup_temp=''

log() { printf '[SlopBro] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
digest() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
verify_devmode_script() {
    local script='/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service/start-devmode.sh'
    local signature='/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service/start-devmode.sig'
    local public_key='/usr/palm/services/com.palm.service.devmode/pub.pem'
    [[ -e "$script" || -L "$script" ]] || return 0
    for file in "$script" "$signature" "$public_key"; do
        [[ -f "$file" && ! -L "$file" ]] || die 'existing Developer Mode script needs manual signature review; do not reboot'
    done
    timeout -k 2 5 openssl dgst -sha512 -verify "$public_key" -signature "$signature" "$script" >/dev/null || die 'Developer Mode script signature failed; no automatic renaming is performed; do not reboot'
}
state() {
    phase="$1"
    printf '{"phase":"%s","success":false}\n' "$phase" > "$SCRIPT_DIR/install-state.json"
}

finish() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if [[ "$success" != 1 ]]; then
        # Revert the marker only if no package installation has begun.
        # A partially installed application needs the secure startup policy;
        # restoring old startup/flags could reopen Telnet.
        if [[ "$install_started" == 0 && "$preference_changed" == 1 ]]; then
            rmdir -- "$PREF" 2>/dev/null || true
            if [[ "$preference_was_file" == 1 ]]; then
                cp -p -- "$tempdir/devmode.backup" "$PREF" || true
            fi
        fi
        log "Installation stopped in phase '$phase'. Secure network defaults are retained; inspect state before retrying or rebooting." >&2
    fi
    [[ -z "$tempdir" ]] || rm -rf -- "$tempdir"
    [[ -z "$startup_temp" ]] || rm -f -- "$startup_temp"
    [[ "$lock_owned" == 0 ]] || rmdir -- /tmp/slopbro-autoroot.lockdir
    exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

[[ "${1:-}" == '' || "${1:-}" == '--debug' ]] || die 'unsupported installer option'
[[ "$(id -u)" == 0 ]] || die 'root privileges were not obtained'
for cmd in node openssl awk mktemp luna-send cp mv mkdir rm rmdir chmod touch sync timeout; do
    command -v "$cmd" >/dev/null || die "missing required command: $cmd"
done
mkdir -- /tmp/slopbro-autoroot.lockdir || die 'installer lock exists; inspect any prior installation before removing a stale lock'
lock_owned=1
tempdir="$(mktemp -d -- /tmp/slopbro-autoroot.XXXXXXXX)"

ipk="$SCRIPT_DIR/hbchannel.ipk"
[[ -f "$ipk" && ! -L "$ipk" ]] || die 'verified package is missing'
[[ "$(digest "$ipk")" == "$HBC_SHA256" ]] || die 'package SHA-256 mismatch'
[[ -f "$SCRIPT_DIR/hbchannel-startup.sh" && ! -L "$SCRIPT_DIR/hbchannel-startup.sh" ]] || die 'hardened startup is missing'

# No persistent changes before package, dependencies and app state pass.
node "$SCRIPT_DIR/luna-helper.js" check-devmode
verify_devmode_script
for parent in /var/luna /var/luna/preferences /var/lib /var/lib/webosbrew; do
    [[ ! -L "$parent" ]] || die "refusing symlink parent: $parent"
done
for path in "$PREF" "$STARTUP" /var/luna/preferences/webosbrew_telnet_disabled /var/luna/preferences/webosbrew_sshd_enabled; do
    [[ ! -L "$path" ]] || die "refusing symlink: $path"
done
if [[ -e "$STARTUP" ]]; then
    [[ -f "$STARTUP" ]] || die 'existing startup is not a regular file'
    existing="$(digest "$STARTUP")"
    expected="$(digest "$SCRIPT_DIR/hbchannel-startup.sh")"
    [[ "$existing" == "$ORIGINAL_STARTUP_SHA256" || "$existing" == "$expected" ]] || die 'existing customized startup needs manual review; no persistent changes made'
fi
if [[ -e "$PREF" && ! -d "$PREF" ]]; then
    [[ -f "$PREF" ]] || die 'unsupported developer-mode marker'
    cp -p -- "$PREF" "$tempdir/devmode.backup"
    preference_was_file=1
fi

state preparing
mkdir -p -- /var/lib/webosbrew
# Predeploy the reviewed policy before HBC can be elevated or autostarted.
startup_temp="$(mktemp -- /var/lib/webosbrew/.slopbro-startup.XXXXXXXX)"
cp -- "$SCRIPT_DIR/hbchannel-startup.sh" "$startup_temp"
chmod 755 "$startup_temp"
mv -f -- "$startup_temp" "$STARTUP"
startup_temp=''
touch /var/luna/preferences/webosbrew_telnet_disabled
rm -f -- /var/luna/preferences/webosbrew_sshd_enabled
if [[ ! -d "$PREF" ]]; then
    preference_changed=1
    rm -f -- "$PREF"
    mkdir -- "$PREF"
fi

restart_installer() {
    if command -v systemctl >/dev/null; then
        timeout -k 5 15 systemctl restart appinstalld || log 'appinstalld restart failed; installer result will be checked'
    elif command -v restart >/dev/null; then
        timeout -k 5 15 restart appinstalld || log 'appinstalld restart failed; installer result will be checked'
    fi
}
restart_installer
state installing
install_started=1
node "$SCRIPT_DIR/luna-helper.js" install "$ipk"
state elevating
[[ -x "$SERVICE/elevate-service" && ! -L "$SERVICE/elevate-service" ]] || die 'installed elevation helper is missing'
timeout -k 5 30 "$SERVICE/elevate-service"
node "$SCRIPT_DIR/luna-helper.js" verify-root
verify_devmode_script
timeout -k 5 10 sync
printf '{"phase":"complete","success":true,"root_verified":true,"reboot_verified":false}\n' > "$SCRIPT_DIR/install-state.json"
success=1
log 'Homebrew Channel installed and current root verified. Startup will not enable Telnet or SSH. Reboot persistence has not been tested.'
