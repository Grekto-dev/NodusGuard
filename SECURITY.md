# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **NodusGuard**, please **do not open a public issue** with exploit details.

Instead, report it privately via GitHub Security Advisories:
- Go to the repository's **Security → Advisories → Report a vulnerability** page on GitHub (`https://github.com/Grekto-dev/NodusGuard/security/advisories/new`).

Please include:
- A clear description of the vulnerability and affected component (UI, Python core services, Polkit policy, D-Bus services, Rust session agent, or C11 helpers).
- Reproduction steps or a minimal proof of concept.
- Potential impact and any suggested mitigation.

## Security Design Guarantees

NodusGuard enforces several structural safeguards:
- **Strict Polkit Authorization**: Destructive actions (such as overwriting files during incident recovery or erasing removable media) require non-cached administrator authorization (`auth_admin`, no retention).
- **Minimal Privilege Boundaries**: File scanning (`clamscan`), the GTK 3 desktop panel, and the Rust session agent run unprivileged. Native C11 helpers are compiled with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`, and `-Wl,-z,relro,-z,now`.
- **Safe Recovery & Deactivation**: Disabling any module preserves existing user backups, quarantine archives, and firewall rules created outside NodusGuard.
- **Resilient Input Validation**: Symlink traversal checks, path-chain root-ownership verification, strict package-name/domain regex validation, and hardware identity (`Serial`/`WWN`/capacity) re-checks before block writes.
- **No Unattended Containment Without Explicit Consent**: Automatic process containment remains disabled unless explicitly selected by the user and requires canary modification, corroborating activity, and proven exclusive `cgroup v2` isolation.

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.0` | Yes |
