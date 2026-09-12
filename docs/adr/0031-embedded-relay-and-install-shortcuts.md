<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0031: Embedded relay and installer shortcuts

Status: implementation, 2026-09-12. Native/physical acceptance remains separate.

## Decision

The Windows product owns its opaque relay inside the already installed service.
It starts after the full SCM readiness handshake, survives closing the desktop
window, and follows the service's AutoStart/Stop lifecycle. No extra server
executable, terminal command or hosted-account registration is needed for LAN use.
This explicitly supersedes ADR0027's outbound-only service transport boundary.
The safe Rust relay receives no key, registry, signer or approval capability.
It retains existing connection/room/timeout limits, cancellation, and inner
mutually pinned TLS at the endpoints. Untrusted relay registration is not identity.

An absent protected relay configuration, or the exact `embedded\n` marker, means
the embedded mode. Existing canonical numeric external endpoint files retain
their meaning. A new fixed `relay-auto` administrator action writes the marker;
the authenticated management pipe requires the same elevated CLI provenance as
SetRelay. No renderer administrator flag or arbitrary program path is accepted.
Mode changes drain old dialers and the embedded listener before replacement.
Shutdown counts and joins the embedded worker before releasing the session.

The embedded IPv4 listener uses TCP7443. A local routing-table selection supplies
the QR's LAN endpoint; it sends no UDP payload and queries no public IP service.
Port collisions and unavailable network addressing leave pairing unavailable and
retry every five seconds rather than failing TPM/service initialization. A
service-scoped, exact-program inbound private-profile firewall rule is installed;
there is no global firewall disable, public-profile allowance, UPnP or router edit.
LAN source-address discovery and a listening socket do not establish physical
phone reachability. A changed LAN address can require reconnect/re-pairing; mobile
networks still need a routable path to the PC or the existing external relay mode.
This release does not claim NAT traversal or physical 4G acceptance.

The installer asks separately for desktop/Start-menu shortcuts and a taskbar
suggestion. New-install defaults are checked; upgrades/repair defaults are not.
Unchecked upgrades retain existing shortcuts. Taskbar selection is a presentation
preference in the fixed HKLM64 uninstall key, not authority to perform pinning.
The app reads the choice for the actual logged-in user's dismissible suggestion.
Only an explicit foreground app-button action invokes Windows TaskbarManager.
Unsupported/older token-restricted Windows versions provide manual pin guidance;
no borrowed LAF token, shell-verb bypass or elevated installer app launch exists.

Reference: [Microsoft taskbar integration](https://learn.microsoft.com/en-us/windows/apps/develop/windows-integration/pin-to-taskbar).
