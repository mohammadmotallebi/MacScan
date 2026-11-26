# Changelog

All notable changes to MacScan are listed here. Versions follow [Semantic Versioning](https://semver.org).

## [1.0] - 2026-11-26

First public release.

### Scanning
- ClamAV signature scanning and YARA rules, including Apple's XProtect rules from your own macOS.
- App integrity and signer checks: code signature, Gatekeeper/notarization, self-signed apps, and apps
  that impersonate well-known publishers.
- Running Processes, Browser Extensions and Startup Items scans.
- Full Check, with a summary of what changed since the last check and a trend chart.

### Your Mac
- Security check (SIP, Gatekeeper, FileVault, firewall, updates, signs of tampering), Privacy
  permissions, Network, Disk Usage, Battery and Install sections.
- Quarantine, a complete uninstaller, and leftovers of removed apps.

### Optional
- Background scans (scheduled, new downloads, new startup items, new apps) and a menu bar icon.
- VirusTotal hash lookup with your own API key.

### Look
- Liquid Glass design.
- Universal build (Apple Silicon and Intel).

[1.0]: https://github.com/mohammadmotallebi/MacScan/releases/tag/v1.0
