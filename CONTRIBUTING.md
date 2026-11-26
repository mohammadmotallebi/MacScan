# Contributing to MacScan

Thanks for your interest in improving MacScan! Bug reports, false-positive reports, ideas and pull
requests are all welcome.

## Reporting bugs and false positives

Open an [issue](../../issues/new/choose) and pick a form. Please include your macOS version, your Mac
(Apple Silicon or Intel), the MacScan version (shown in Settings) and the steps to reproduce.
For a false positive, include the app or file name, where it came from, and the exact reason MacScan showed.

Logs are in `~/Library/Logs/MacScan` (Settings › Privacy shows the location). Look through them before
attaching them: they contain file paths from your Mac.

## Development setup

Requirements: macOS 26 and Xcode 27 or newer (the menu bar code uses the macOS 27 SDK). [Homebrew](https://brew.sh) with `clamav` and `yara` is
needed for the engine tests; those tests skip themselves when the tools are missing.

```sh
git clone https://github.com/mohammadmotallebi/MacScan.git
cd MacScan
open MacScan.xcodeproj               # pick your team under Signing & Capabilities, then ⌘R
cd Packages/MacScanCore && swift test # run the test suite
```

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Keep changes focused: one feature or fix per pull request.
3. Put scanning logic in `Packages/MacScanCore` and add tests there. The app target is a thin UI layer.
4. Make sure `swift test` passes and the app builds.
5. Describe what you changed and how you tested it.

### Ground rules

- **MacScan never deletes, moves or changes anything on its own.** Every destructive action must go
  through an explicit user confirmation.
- Engines report findings and never modify files (see "Adding an engine" in the README).
- Nothing leaves the Mac without the user turning it on. VirusTotal sends hashes only, never files.
- Keep the code easy to follow and the UI text short and plain.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
