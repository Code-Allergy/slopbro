#!/bin/bash
# Derived from webosbrew/webos-homebrew-channel v0.7.3, services/startup.sh.
# MIT License
# 
# Copyright (c) 2021 webOS Brew
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Security policy: no Telnet, no default password, SSH public keys only.

# This script does some early-boot initialization of rooted webOS devices. It's
# meant to be copied over to suitable path (eg. start-devmode.sh) to keep it
# safe from accidental homebrew channel app removal.

# Ensure that startup script runs only once per boot
once=/tmp/webosbrew_startup
exec 200>"${once}.lock"

if ! flock -x -n 200; then
    echo "[!] Startup script already running" >&2
    exit 1
fi

trap "rm -f ${once}.lock" EXIT

if test -f "${once}"; then
    echo "[!] Startup script finished already" >&2
    exit 2
fi

touch "${once}"

# Use default directory if SERVICE_DIR is not provided.
SERVICE_DIR="${SERVICE_DIR-/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service}"

start_key_ssh() {
    [[ -e /var/luna/preferences/webosbrew_sshd_enabled ]] || return 0
    local keys=/home/root/.ssh/authorized_keys
    if [[ -L /home/root/.ssh || ! -s "$keys" || ! -f "$keys" || -L "$keys" ]]; then
        echo "[!] Refusing SSH: provision a regular nonempty authorized_keys file" >&2
        return 1
    fi
    chmod 700 /home/root/.ssh
    chmod 600 "$keys"
    chown 0:0 /home/root/.ssh "$keys"
    mkdir -p /var/lib/webosbrew/sshd
    # -s disables every password login, including root passwords.
    "${SERVICE_DIR}/bin/dropbear" -R -s 200>&-
}

if [[ -e /var/luna/preferences/webosbrew_failsafe ]]; then
    # In case a reboot occured during last startup - offer pre-provisioned key-only SSH
    # recovery and nag user to actually fix this. (since further reboots could
    # lead to devmode removal, etc...)

    # Recovery follows the same key-only SSH policy as normal startup.
    start_key_ssh
    sleep 1

    luna-send -a webosbrew -f -n 1 luna://com.webos.notification/createToast '{"sourceId":"webosbrew","message": "<b>Failsafe mode!</b><br/>A crash has occured during startup. Fix any causes and reboot."}'
    sleep 15;
    rm -rf /var/luna/preferences/webosbrew_failsafe
    sync -f /var/luna/preferences
    luna-send -a com.webos.service.secondscreen.gateway -f -n 1 luna://com.webos.notification/createAlert '{"sourceId":"webosbrew","message":"<b>Homebrew Channel</b> - Failsafe mode<br />A crash has occured during previous startup - root-related system customizations have been temporarily disabled.<br /><br /> System should go back to normal after a reboot.<br />Would you like to reboot now?","buttons":[{"label":"Reboot now","onclick":"luna://com.webos.service.sleep/shutdown/machineReboot","params":{"reason":"remoteKey"}},{"label":"Reboot later"}]}'
else
    # Set a failsafe flag and sync filesystem to make sure it actually gets
    # tripped...
    touch /var/luna/preferences/webosbrew_failsafe
    sync -f /var/luna/preferences/webosbrew_failsafe
    sleep 2

    # Close fds to avoid leaking Luna socket
    fds="$(ls -1 "/proc/$$/fd")"
    for fd in $fds; do
        case $fd in
        # Don't close stdin, stdout, stderr, or lock
        0|1|2|200) ;;
        *) eval "exec $fd>&-" ;;
        esac
    done

    # Reset devmode reboot counter
    rm -f /var/luna/preferences/dc*

    # Block software update servers
    if [[ -e /var/luna/preferences/webosbrew_block_updates ]]; then
        cp /etc/hosts /tmp/hosts
        mount --bind /tmp/hosts /etc/hosts

        echo '' >> /etc/hosts
        echo '# This file is dynamically regenerated on boot by webosbrew startup script' >> /etc/hosts
        echo '127.0.0.1 snu.lge.com su-dev.lge.com su.lge.com su-ssl.lge.com' >> /etc/hosts
        echo '::1 snu.lge.com su-dev.lge.com su.lge.com su-ssl.lge.com' >> /etc/hosts
    fi

    # Telnet is intentionally unsupported in this security fork.
    touch /var/luna/preferences/webosbrew_telnet_disabled
    start_key_ssh

    printf "\033[1;91mNEVER EVER OVERWRITE SYSTEM PARTITIONS LIKE KERNEL, ROOTFS, TVSERVICE.\nYour TV will be bricked, guaranteed! See https://rootmy.tv/warning for more info.\033[0m\n" > /tmp/motd
    mount --bind /tmp/motd /etc/motd

    # Never rewrite passwd/shadow or install a shared default root password.

    # Do our best to neuter telemetry
    mkdir -p /tmp/.unwritable
    for path in /tmp/rdxd /tmp/uploadd /var/spool/rdxd /var/spool/uploadd/pending /var/spool/uploadd/uploaded; do
        mkdir -p $path
        mount -o bind,ro /tmp/.unwritable $path

        # Some older mount (webOS 3.x) does not support direct ro bind mount, so
        # this needs to be remounted after initial bind...
        mount -o bind,remount,ro /tmp/.unwritable $path
    done

    # Deprecate old path
    if [[ -d /home/root/unwritable ]]; then
      chattr -i /home/root/unwritable
      rm -rf /home/root/unwritable
    fi

    # Automatically elevate Homebrew Channel service
    elevate_script="${SERVICE_DIR}/elevate-service"
    if [[ -z "${SKIP_ELEVATION}" && -x "${elevate_script}" ]]; then
        "${elevate_script}"
    fi

    # Run user startup hooks
    mkdir -p /var/lib/webosbrew/init.d
    run-parts /var/lib/webosbrew/init.d 200>&-

    # Reset failsafe flag after a while
    sleep 10
    rm -rf /var/luna/preferences/webosbrew_failsafe
    sync -f /var/luna/preferences
fi
