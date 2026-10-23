# Security scope and validation

Base: throwaway96/slopbro commit 21023d56ca424607bb03d2939609cc658c655fc7.
Dependency: webosbrew/webos-homebrew-channel v0.7.3, source commit
92fcf9fef7ce08dbeae3b0616df8d0c75c11f0b3. Release package SHA-256:
d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c.

## Findings addressed

| Finding | Change | Validation |
| --- | --- | --- |
| Unauthenticated root Telnet on normal/failsafe boot; shared password setup | Predeploy derived startup with no Telnet path or password edits; initially disable SSH; later SSH requires keys and disables password login | Both boot branches executed with inert system stubs, with SSH off, missing keys, and provisioned keys |
| HTTP executable delivery, unpinned package, insecure curl option | Mandatory trusted HTTPS in launcher/page/download/receipt clients; independently supplied TV certificate pin; exact package hash checked on computer, root wrapper and shell | Loopback certificate trust/hostname tests, downgrade/error-page/tampering tests, pin-before-handshake test |
| Transfer activity reported as successful rooting | Transfer diagnostics separated from a correlated terminal receipt and current-root check | HEAD/GET-only, incomplete, negative, duplicate and malformed receipt tests |
| False install success and suppressed child errors | Structured statusValue 30 and package identity; explicit error fields win; child exit/root-check failures retained | Parser fixtures, failed shell install/root check and wrapper exit-status tests |
| Unbounded waits, unhandled browser bridge and fragmented frames | Absolute connection/message deadlines, worker/output/size bounds, process-group watchdog, fail-closed page state | Stalled client, timeout, fragmentation, size limit and missing-bridge tests |
| Partial-state handling | App/script/dependency preflight; refuse unknown custom startup; retain secure policy on partial install; restore marker before install where possible | Custom/unsigned script rejection, marker restoration and partial-install failure tests |
| Pairing-key file creation race | Create private temporary file before writing, atomically replace destination | Mode and symlink replacement test |

## Trust boundaries

HTTPS is mandatory because a checksum sent with executable code over the same
unauthenticated HTTP connection cannot establish authenticity. A random URL or
IP allowlist is an additional access restriction, not a replacement for TLS.

Trust the computer, checkout, supplied TLS private key, CA validation, selected
TV identity and TV operating system. The TV certificate pin must be established
independently; first-use observation over an untrusted LAN is insufficient.
A device certificate shared across units would not establish unique identity.
The result receipt reports what the selected TV says its installer/root check
observed; it is not remote cryptographic attestation.

The pinned IPK is an external privileged dependency. Its hash prevents silent
artifact substitution; this change is not a full audit of its app, service,
bundled binaries, or future updates. Homebrew Channel intentionally exposes
privileged Luna APIs after elevation. The LG vulnerability remains present:
installing this fork does not patch LG firmware or protect other vulnerable
services. No exploit-resistance claim is made for the TV as a whole.

## Remaining validation

No physical TV was accessed or modified while preparing this change. Before
calling the fork production-ready, validate on a disposable/owned test unit:

1. All TV HTTPS clients reject an untrusted/expired/wrong-host certificate and
   accept the configured trusted chain. Some older TV download services may
   not enforce TLS correctly; this remains a release-blocking hardware check.
2. The download service creates the unique session directory and preserves the
   expected filenames; jsserver's existing argument contract loads the wrapper.
3. The installed release emits the expected structured installer events and its
   root check is reachable after service elevation.
4. The predeployed policy survives app autostart and a reboot. Confirm the actual
   network has no newly opened Telnet or password-authenticated SSH listener,
   including during failsafe recovery. Test SSH key-only login separately.
5. Verify reboot persistence and recovery after failures/power loss. An immediate
   root check does not prove persistence or a safe reboot.

The fork deliberately fails when dependencies, app state, an existing
Developer Mode signature, TLS trust or a custom startup cannot be established.
It never automatically renames an invalid Developer Mode script, flashes
firmware, or reboots. Existing remote daemons/user hooks are not removed.

Rollback is partial. Retaining the hardened startup and disabled remote-access
flags is safer than restoring an insecure policy after a failed package
install. Package/service elevation changes may need manual repair; do not
blindly rerun the installer or reboot after a timeout. A forced termination
can bypass the shell EXIT trap. Inspect the last recorded phase and logs.

These changes address the audited issues in the launcher/installer design.
Passing offline tests does not certify compatibility with a Canadian C2,
firmware 33.53.22, or any other TV/firmware.
