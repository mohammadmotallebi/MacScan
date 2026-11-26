# Security Policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **don't** open a public issue for security problems. Report them privately through
[GitHub's private vulnerability reporting](../../security/advisories/new) instead.
Include steps to reproduce and the affected version.

Relevant reports include:
- ways a malicious file, rule or app could make MacScan run code, delete or move files, or crash
- ways to hide malware from MacScan's checks
- problems with how MacScan handles the VirusTotal API key or sends data to VirusTotal
- problems in the background scan agents or the uninstaller's administrator step

## Missed malware

Malware that MacScan doesn't detect is usually a detection gap, not a vulnerability. Open a regular
issue with the sample's SHA-256 hash and a VirusTotal link. **Never attach live malware.**
