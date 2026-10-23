# SlopBro security hardening fork

This fork hardens the launcher and installer from
[throwaway96/slopbro](https://github.com/throwaway96/slopbro) at commit
21023d56ca424607bb03d2939609cc658c655fc7. SlopBro uses a webOS jsserver
vulnerability to install and elevate Homebrew Channel on an owned TV.

**Experimental: the changes have offline regression coverage, but have not been
tested on a TV. No firmware/model combination is certified by this fork.**
LG firmware numbers such as 33.53.22 are different from internal webOS versions;
do not infer compatibility from that number alone.

## Security changes

- All executable assets, the page, manifest, and installer receipts use trusted
  HTTPS. There is no insecure payload mode or certificate-validation bypass.
- The SSAP connection requires an independently verified SHA-256 pin for the
  TV's certificate before sending any saved pairing key or pairing request.
- Homebrew Channel v0.7.3 is downloaded on the computer over validated HTTPS
  (or supplied locally) and its pinned SHA-256 is checked on both devices.
- Payload URLs use a random 256-bit session capability and an exact TV IPv4
  source restriction. Files are snapshotted before serving.
- A reviewed Homebrew Channel startup policy is installed before elevation.
  It never starts Telnet, including in failsafe mode. SSH is disabled initially;
  later opt-in requires a nonempty regular authorized_keys file and uses
  Dropbear with password authentication disabled. No shared root password is set.
- Explicit package-install failures take priority over success text. Success
  requires the expected package identity, a zero installer exit status, and
  Homebrew Channel's current-root check. Download requests and HEAD requests
  never establish installation success.
- Downloads, connections, Luna requests, installer subprocesses and the launcher
  wait are bounded. Failure leaves a nonzero launcher exit and diagnostic state.

See [SECURITY.md](SECURITY.md) for the trust assumptions and remaining risks.

## Requirements

On the computer: Python 3.12+, a trusted local checkout, and a TLS certificate
chain/private key for a hostname that resolves to the computer from the TV.
The chain must validate on the computer, TV browser, download service, and TV
Node runtime. The hostname must match the certificate. Use a certificate from
a CA already trusted by those clients, or a CA deliberately provisioned through
a trusted administrative channel. The launcher validates its server locally
before pairing. TLS 1.2 or newer is required.

The TV must have a correct clock, support the existing upstream entry point,
and have the required Bash, Node, OpenSSL, timeout, and Luna tools. Missing
requirements stop the installation. The download service must support creating
the per-session target directory. These TV-specific requirements need hardware
validation. The LG Developer Mode app must be absent; unknown app state is
rejected. Existing custom startup scripts or unsigned Developer Mode scripts
require manual review before this installer will proceed.

Obtain the TV certificate pin through an independently trusted channel. Merely
copying a certificate fingerprint from an unauthenticated LAN connection does
not establish the TV's identity. Do not disable validation if a certificate
check fails.

## Running

The following is a template; substitute your independently verified values:

~~~sh
python3 slopbro.py TV_IP \
  --webos-version INTERNAL_WEBOS_VERSION \
  --tv-cert-sha256 VERIFIED_64_HEX_DIGIT_FINGERPRINT \
  --payload-host payload.example.net \
  --tls-cert /path/to/fullchain.pem \
  --tls-key /path/to/privkey.pem
~~~

The certificate private key stays on the computer and is never served.
The listener binds to the selected local interface, usually port 8080; a busy
port causes an ephemeral port to be selected. The TV needs access to that
port and the computer needs access to SSAP TLS port 3001. Keep session URLs
private. Pairing keys are stored in mode-0600 files in the current directory.

Use --local-ip to select the listening interface, and --hbchannel-ipk to
provide the exact v0.7.3 package locally. The required package SHA-256 is:

~~~text
d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c
~~~

The pin identifies one release artifact; it does not certify the entire
Homebrew Channel implementation. A different release needs a deliberate
dependency review and code change.

--operation-timeout controls the launcher's result wait (default 180 seconds,
range 1–600). A timeout does not roll back the TV or prove the TV stopped.
--fake-service-path and --no-fake-service-path retain the existing upstream
entry-point options. --asset-source selects dir, embedded, or auto; auto
prefers embedded assets. python3 slopbro.py --help lists all options.

The TV page shows download/startup status. The computer prints a final JSON
result only after receiving a successful installer receipt. reboot_verified
is always false: this fork never automatically reboots or claims reboot
persistence was tested. On error, inspect the session's install-state.json
and private installer-*.log files before retrying or rebooting.

For a fixed-text connectivity check with no pairing or payload:

~~~sh
python3 slopbro.py --test-server simple --local-ip COMPUTER_IP TV_IP
~~~

--test-server payload requires the HTTPS prerequisites and serves the real
payload without pairing or launching an app. Opening it in a privileged TV
context can still execute the installer.

## Recovery and remote access

The hardened startup is /var/lib/webosbrew/startup.sh. Do not overwrite it with
the stock Homebrew Channel startup script: doing so can restore stock Telnet
behavior. Review Homebrew Channel upgrades and any replacement startup hooks.

SSH stays disabled on installation. If you later enable the Homebrew Channel
SSH flag, first provision your own authorized_keys at
/home/root/.ssh/authorized_keys through a trusted channel. Startup checks for
a regular nonempty file, secures its permissions, and passes -s to Dropbear
to disable password login. The same policy applies in failsafe mode.
Telnet is unsupported even if its Homebrew Channel UI setting is changed.

This installer does not terminate preexisting SSH/Telnet listeners or audit
user-created boot hooks. It does not undo an existing root compromise.
After package installation begins, a failure may leave partial app/service
changes. Secure startup defaults are retained; automatic unroot/rollback is
not provided. Before installation begins, a changed developer-mode marker
is restored on ordinary failure where possible. Forced power loss or SIGKILL
can bypass cleanup and leave a stale installer lock.

## Building and testing

~~~sh
make test dist
~~~

Tests are offline: loopback TLS fixtures, inert Luna/elevation stubs, temporary
filesystem mappings for TV scripts, and browser/Node harnesses. No test contacts
a TV or runs the real installer against the host filesystem. CI uses a pinned
checkout action with read-only repository permissions and no persisted token.

The packed file is dist/slopbro_packed.py. It embeds all six static payload
assets, including the hardened startup and Luna helper. It still requires the
same certificate/pin options and separately validates the Homebrew Channel
package. Do not replace a reviewed source checkout with an unverified packed
download.

## Credits and license

Original SlopBro: throwaway96. The original project credits dangbro for the
dangbei-overlay entry and jsbro-autoroot for the public jsserver disclosure.
The launcher/installer changes remain AGPL-3.0-or-later; see COPYING.
The derived webOS Brew startup is MIT licensed, with the full notice embedded
in the script and reproduced in THIRD_PARTY_LICENSES.txt. No warranty.
