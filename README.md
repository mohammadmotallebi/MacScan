# MacScan

An **on-demand** malware scanner for your own Mac. By default it runs only when you open it and press a scan button: no launch agents, daemons, login items, menu bar helpers or system extensions. When you quit MacScan, every scan and helper process stops. Scheduled scans and scanning new downloads are optional and off by default (see [Background scans](#background-scans)).

- **ClamAV** signature scanning (via Homebrew's `clamscan`)
- **YARA** rules (via Homebrew's `yara`): a small sample macOS ruleset, your own rules, and **Apple's XProtect rules** that ship with macOS
- **App integrity**: `codesign --verify --deep --strict`, Gatekeeper/notarization (`spctl`), unsigned/ad-hoc executables, quarantine info
- **Signer checks**: flags **self-signed** apps and binaries (certificates Apple didn't issue, typical of cracked or repackaged software) and apps that **impersonate** a well-known publisher's bundle ID
- **Running Processes scan**: lists the programs running right now and flags untrusted ones (unsigned, self-signed, running as root, deleted program file, temporary or hidden location)
- **Startup Items scan**: lists everything set to start automatically (launch agents and daemons, privileged helpers, shell startup files, plug-ins, cron) and flags risky ones
- **Optional VirusTotal hash lookup** with *your own* API key. Only SHA-256 hashes are sent, files are never uploaded.
- Results with severity filter, Reveal in Finder, Move to Trash (always asks first), Ignore
- Scan history with JSON and CSV export
- **Optional background scans**: a scheduled scan, and a scan of each new item in your Downloads folder, with a notification when something is found. macOS starts MacScan for each scan and MacScan exits afterwards, so nothing stays running.
- **Complete uninstaller**: removes an app together with its startup items, helpers, settings, caches, containers, logs and package-installed files, after you review a checklist. Everything goes to the Trash.

MacScan **never deletes or moves anything on its own.**

---

## Requirements

- macOS 14 Sonoma or later, Apple Silicon
- Xcode 16 or later (tested with Xcode 27.1)
- [Homebrew](https://brew.sh) for ClamAV and YARA (optional; the other engines work without them)

## 1. Install ClamAV and YARA

```sh
brew install clamav yara
```

You do **not** need to configure Homebrew's `freshclam.conf`. MacScan keeps its own database in
`~/Library/Application Support/MacScan/ClamAV` and downloads it only when you click
**Update virus database** (about 300 MB the first time). If you already maintain a database at
`/opt/homebrew/var/lib/clamav`, MacScan uses it automatically.

MacScan looks for the tools in `/opt/homebrew/bin`, `/usr/local/bin` and `/opt/local/bin`. You can set
custom paths in **Settings › Engines**.

## 2. Build and sign with your free personal team

1. Open `MacScan.xcodeproj` in Xcode.
2. Select the **MacScan** target › **Signing & Capabilities**.
3. Keep **Automatically manage signing** on and choose your **Personal Team** under *Team*.
4. If Xcode says the bundle identifier is unavailable, change `com.local.MacScan` to something unique,
   e.g. `com.<yourname>.MacScan`.
5. Press **⌘R** to build and run.

MacScan uses **no App Sandbox and no restricted entitlements** (only the Hardened Runtime), so a free
personal team is enough.

### Install a copy in /Applications (recommended)

Full Disk Access is granted per app, and the copy Xcode runs lives deep inside DerivedData. To get a
stable copy, use **Product › Show Build Folder in Finder** › `Products/Debug/MacScan.app` and drag it to
`/Applications`. Or build Release from the command line:

```sh
xcodebuild -project MacScan.xcodeproj -scheme MacScan -configuration Release \
  -derivedDataPath build DEVELOPMENT_TEAM=<YOUR_TEAM_ID> build
cp -R build/Build/Products/Release/MacScan.app /Applications/
```

(Your team ID is shown in Xcode › Settings › Accounts, or in the *Team* field of the project.)

Keep signing with the same team and bundle identifier. macOS then recognizes rebuilt copies as the
same app, and Full Disk Access and the Keychain item keep working.

## 3. Grant Full Disk Access

Without it, MacScan can still scan your Applications and most of your files, but macOS blocks
protected locations (Mail, Messages, Safari, other apps' containers). When that happens MacScan lists
the unreadable paths and walks you through this:

1. Open **System Settings › Privacy & Security › Full Disk Access**.
   (MacScan's *Open System Settings* button goes straight there.)
2. Click **+** and choose `/Applications/MacScan.app` (or drag it into the list).
3. Turn the switch **on**.
4. **Quit and reopen** MacScan.

Child processes MacScan starts (`clamscan`, `yara`, `codesign`) inherit its access.
For Desktop, Documents and Downloads, macOS may instead show a one-time consent prompt the first time you scan them.

## 4. First run

1. Click **Update virus database** (first download takes a few minutes).
2. Click **Scan Applications**, add folders and click **Scan Folders**, or drop any file or folder
   onto the window.
3. Review the results. Select a row for details. Right-click for Reveal in Finder, VirusTotal lookup,
   Ignore, or Move to Trash.

Expect some **Warnings** for legitimate software: ad-hoc signed open-source apps, older apps with an
obsolete signature format, apps whose bundle was modified by an updater, and so on. Each warning
explains what codesign or Gatekeeper actually reported, so you can judge it. Use **Ignore** to hide
a result you've reviewed. It reappears if the file's contents change.

---

## Settings

| Tab | What you can change |
| --- | --- |
| General | Max file size, skip symlinks, "executables only" for Applications scans, excluded paths |
| Engines | Turn engines on/off, paths to `clamscan`/`freshclam`/`yara`/`yarac`, ClamAV DB folder, YARA rules folder |
| Background | Scheduled scan (daily or weekly, time), scan new downloads, notification status and test |
| VirusTotal | Your API key (stored in the login Keychain), auto-lookup of flagged files |
| Privacy | Full Disk Access status and instructions, log location |
| Ignored | Review and un-ignore hidden results |

### YARA rules

By default MacScan uses its bundled sample ruleset (Settings › Engines › *Show Sample Rules*).
These rules are deliberately small and heuristic, a starting point rather than a complete ruleset.
Point MacScan at your own folder to use more rules. Every `.yar`/`.yara` file in it (recursively) is
compiled together once per scan. MacScan reads two optional meta fields:

```yara
rule Example {
    meta:
        description = "Shown as the reason in the results list"
        severity    = "threat"   // or "warning" (default)
    strings:
        $a = "something"
    condition:
        $a
}
```

### Apple XProtect rules

macOS keeps its own malware YARA rules up to date at
`/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara`.
MacScan reads that file in place, in its own namespace, alongside your rules. A match is reported as a
**Threat** ("Apple XProtect: MACOS.xxxxxxx"). You can turn it off in Settings › Engines.

### Signer checks

Every app, and every Mach-O file inside it, is classified as Apple-issued, ad-hoc, **self-signed** or
unsigned. "Self-signed" means the certificate doesn't chain to Apple (`anchor apple generic`). Legitimate
developers don't ship that way; modified or cracked copies do, so it's reported as a **Threat**.

MacScan also knows the Team IDs of a few well-known publishers (Google, Microsoft, Zoom, Slack, Docker,
WhatsApp, Telegram, OpenAI, Valve, VideoLAN). An app that uses their bundle ID but is signed
by anyone else is reported as impersonation. The list is in `KnownPublishers` (`CodeSigning.swift`). Only
add Team IDs you've verified with `codesign -dv /Applications/<App>.app`.

Homebrew and MacPorts binaries are ad-hoc signed by design, so ad-hoc signing under `/opt/homebrew`,
`/usr/local/Cellar` and `/opt/local` isn't flagged. Self-signed binaries there still are.

### Startup Items scan

**Scan Startup Items** (⇧⌘L) lists and checks:

| Location | What it is |
| --- | --- |
| `~/Library/LaunchAgents`, `/Library/LaunchAgents` | Programs started at login |
| `/Library/LaunchDaemons` | Programs started at boot **as root** |
| `/Library/PrivilegedHelperTools` | Root helpers (orphans included) |
| `~/.zshrc`, `~/.zprofile`, `~/.bash_profile`, … | Commands run in every Terminal shell |
| Quick Look, Spotlight, scripting additions, authorization plug-ins, input managers, kexts | Code macOS loads automatically |
| Your `crontab` | Scheduled jobs |

Each item gets a row (Clean if nothing's wrong). Each referenced program also goes through ClamAV, YARA and
the integrity checks. Items are flagged when they:
- run as root with an unsigned or self-signed program (**Threat**), or with an ad-hoc one
- point to a missing program, or one in `/tmp`, `/Users/Shared` or a hidden folder
- download-and-run, decode base64, open raw sockets, run inline AppleScript/Python, or strip quarantine
- impersonate a known publisher

Nothing is disabled or deleted. Use **Reveal in Finder** and remove items yourself if you decide to.

**What changed since the last scan.** Every Startup Items scan (including the scheduled one) is compared
with the previous one. Items that were added, or that now start a different program, use different
arguments, have a different signer or (for scripts and shell files) different contents, get a **NEW** or
**CHANGED** badge, and the details say what changed. A **New or changed** checkbox above the results shows
only those, and the scan notes also list removed items. An app update that replaces a program with one from
the same signer doesn't count as a change. The first scan only saves the baseline. A scheduled scan sends a
notification when items were added or changed, even if nothing about them is flagged.
Login items you manage in System Settings › General › Login Items, and configuration profiles, need admin
rights to list. Review them in System Settings.

### Running Processes scan

**Scan Running Processes** (⇧⌘P) looks at every process that is running right now and lists one row per
program (a browser's twenty helper processes are one row), with its process IDs, user, parent and signature.

Programs are flagged when they:
- run as root without a trusted signature (**Threat**), or with an ad-hoc one
- are self-signed (**Threat**) or not signed at all
- have no Apple-issued signature and run from `/tmp`, `/Users/Shared`, Downloads or a hidden folder
- were started from a file that has since been deleted (an app updated while running is recognised and
  shown as Clean)
- impersonate a known publisher

Each program file also goes through ClamAV, YARA and the integrity checks, like any scanned file. Apple
system software on the sealed system volume is counted in the scan notes but not listed. Signed programs
aren't flagged for their location, because macOS itself runs signed apps from temporary folders (App
Translocation, code-sign clones, iPhone app wrappers).

Nothing is stopped, suspended or changed. Quit a program yourself in Activity Monitor if you don't trust it.
This is a snapshot of the moment you scan, not live monitoring.

### Uninstall

**Uninstall** in the sidebar (⇧⌘U), or **Uninstall App…** on any scan result inside an app:

1. Pick an app from the list, choose one, or drop a `.app` onto the window.
2. MacScan lists everything that belongs to it, grouped by type, with sizes:
   - the app bundle
   - LaunchAgents/LaunchDaemons that are named after the app, declare it as owner, or start a program inside it
   - privileged helpers those items start
   - `~/Library` and `/Library` items named after the app's bundle ID, or a helper/extension ID inside it: Application Support, Caches, Preferences (incl. ByHost), Containers, Group Containers, Logs, Saved State, HTTPStorages/WebKit/Cookies, Application Scripts
   - folders with exactly the app's name (marked **name match**; check them)
   - files its `.pkg` installer put elsewhere (from `pkgutil` receipts)
   - its running processes
   - its **registered background items** from macOS's Background Task Management database (`sfltool dumpbtm`):
     helpers and login items embedded in the bundle (SMAppService), and legacy agents/daemons, even when
     they're named differently (e.g. Steam's `com.valvesoftware.steamclean`)
   - launch items that start a program from one of the app's support folders
3. Untick anything you want to keep. Items shared with the same developer's other apps (e.g. a common
   updater) are marked **shared?** and are *not* ticked by default. Then click **Uninstall…** and confirm.

MacScan then:
- quits the app
- stops **and unregisters** its background items (`launchctl bootout`, by plist and by label, which also
  covers helpers embedded in the bundle)
- moves the selected items to the **Trash**
- forgets its installer receipts

System-owned items need your administrator password: macOS asks once for all of them. Those items also go to your Trash, but without Finder's "Put Back". Nothing is permanently deleted until you empty the Trash. Apps that are part of macOS, protected by SIP, or MacScan itself can't be uninstalled.

**Trash vs. permanent:** macOS keeps listing an app's background items in System Settings › General ›
Login Items & Extensions **while the app is still in the Trash**. To make them disappear:
- tick **Delete permanently** before uninstalling, or
- use the **In the Trash** group in the app list to finish off apps you've already moved to the Trash.
  Items already in the Trash are deleted permanently, and the confirmation says so.

Whatever the list says, MacScan refuses to remove top-level or system locations (`/Applications`, `/Library`,
`~/Library/…` roots, `/System`, `/usr`, …).

### Background scans

Both options are in *Settings › Background* and are off by default.

- **Scan on a schedule** runs a scan of Applications, Startup Items and your scan folders every day or
  every week at the time you pick.
- **Scan new downloads** scans each new item that arrives in `~/Downloads`. Items that were already there
  when you turned it on are not scanned, and unfinished downloads (`.crdownload`, `.download`, `.part`)
  wait until they are complete.

How it works: MacScan installs its own per-user launch agents in `~/Library/LaunchAgents`
(`com.local.MacScan.scheduled-scan.plist`, `com.local.MacScan.downloads-watcher.plist`). launchd starts the
MacScan executable in a headless mode (`--macscan-background-scan`) when a scan is due, and it exits when
the scan ends. No MacScan process stays running in between. Turning an option off unloads and deletes
its agent.

- Every background scan is saved in History, marked *Scheduled* or *New downloads*. Of the background
  scans that found nothing, only the 10 newest per kind are kept.
- You get a notification only when something new is flagged. A scheduled scan doesn't notify again about
  results its previous run already had. Click the notification to open the scan in History.
- Background scans never run as administrator and never move or delete anything.
- Scheduled scans run while you're logged in. A scan missed while the Mac was asleep runs after it wakes;
  one missed while the Mac was off or you were logged out is skipped.
- While an option is on, MacScan appears in System Settings › General › Login Items and in its own
  Startup Items scan (labelled as MacScan's own agent).
- The agents point at the copy of MacScan that turned them on. If you move the app, open it once and
  MacScan repairs them.

### VirusTotal

Free keys allow 4 lookups per minute and 500 per day, so MacScan spaces requests 15 s apart.
By default nothing is looked up automatically. Use the per-result *Look Up Hash on VirusTotal* action,
or turn on auto-lookup for flagged files only.

## Where MacScan keeps things

| What | Where |
| --- | --- |
| Log | `~/Library/Logs/MacScan/MacScan.log` (rotated at 5 MB) |
| Scan history (JSON, last 100 scans) | `~/Library/Application Support/MacScan/History/` |
| Ignore list | `~/Library/Application Support/MacScan/ignored.json` |
| Downloads already seen (only with "Scan new downloads") | `~/Library/Application Support/MacScan/downloads-seen.json` |
| Startup items of the last scan (to report changes) | `~/Library/Application Support/MacScan/startup-baseline.json` |
| Launch agents (only while background scans are on) | `~/Library/LaunchAgents/com.local.MacScan.*.plist` |
| ClamAV database + `freshclam.conf` | `~/Library/Application Support/MacScan/` |
| Settings and folder list | `defaults read com.local.MacScan` |
| VirusTotal key | Login Keychain, service `MacScan.VirusTotal` |

**Uninstall:** delete `MacScan.app`, the two folders above, run
`defaults delete com.local.MacScan`, and remove the `MacScan.VirusTotal` Keychain item.
If background scans are on, turn them off in *Settings › Background* first so MacScan removes its launch
agents. Otherwise there is nothing else to remove.

---

## Development

### Project layout

```
MacScan.xcodeproj
MacScan/                      SwiftUI app (thin UI layer)
  MacScanApp.swift            Window + Settings scenes; kills child processes on quit
  AppState.swift              @Observable state, user actions (scan, trash, ignore, export…)
  BackgroundNotifications.swift  Notification Center delivery and click handling for background scans
  Views/                      Main screen, results, history, settings, sheets
Config/MacScan.entitlements   App Sandbox explicitly OFF
Packages/MacScanCore/         All scanning logic (Swift package, testable with `swift test`)
  Sources/MacScanCore/
    Engines/                  ScanEngine protocol, ClamAV, YARA (+XProtect), AppIntegrity, VirusTotal, CodeSigning/KnownPublishers
    Scanning/                 FileEnumerator, Persistence (startup items), RunningProcesses, Mach-O detection, ScanCoordinator
    Background/               BackgroundAgent (launchd plists), DownloadsTracker, BackgroundScanWorker (headless mode)
    Support/                  ProcessRunner (cancellable), ToolLocator, FileLogger, Keychain, hashing
    Persistence/              History, ignore list, folder bookmarks, Full Disk Access helpers
    Export/                   JSON / CSV export
    Uninstall/                InstalledApp, LeftoverFinder (what belongs to an app), Uninstaller (quit, bootout, Trash, admin step)
    Resources/SampleRules/    Bundled YARA rules
  Tests/MacScanCoreTests/     Swift Testing unit tests
```

### Running the tests

```sh
cd Packages/MacScanCore
swift test
```

Or select the **MacScanCore** scheme in Xcode and press **⌘U**.

- ClamAV tests use the **EICAR** test string against a tiny generated signature database, so they
  don't need the official download. An extra test also checks EICAR against the official database
  once you've clicked *Update virus database*. ClamAV/YARA tests skip themselves if the tools are missing.
- The VirusTotal tests use a mocked network layer and never contact VirusTotal.
- Signer tests create a throwaway self-signed identity in a private temporary keychain (never added to
  your keychain search list).
- Opt-in smoke tests against your real system (read-only):
  `MACSCAN_REAL_PROBE=/tmp/probe.txt swift test --filter realApplicationsProbe`
  `MACSCAN_STARTUP_PROBE=/tmp/startup.txt swift test --filter realStartupItemsProbe`
  `MACSCAN_UNINSTALL_PROBE=/Applications/Foo.app swift test --filter realUninstallProbe` (lists, never removes)
- Uninstall tests use a fake Trash and run the "admin" script as you (no password), so they never touch
  your real Trash or system.

### Adding an engine

Conform to `ScanEngine` (`Packages/MacScanCore/Sources/MacScanCore/Engines/ScanEngine.swift`):

```swift
public protocol ScanEngine: Sendable {
    var id: EngineID { get }
    var displayName: String { get }
    func availability() async -> EngineAvailability
    func handles(_ item: ScanItem) -> Bool
    func scan(_ items: [ScanItem], context: ScanContext, events: @escaping EngineEventSink) async throws
}
```

Report `.itemFinished` and `.finding` events, check for cancellation, and never modify files. Then
add a case to `EngineID` and register the engine in `EngineFactory.makeEngines`.

### How a scan works

1. `FileEnumerator` walks the targets. It skips exclusions, files over the size limit and (optionally)
   symlinks, records permission errors, and marks Mach-O code and enclosing `.app` bundles.
2. `ScanCoordinator` runs all available engines **concurrently**. ClamAV starts a single `clamscan`
   over a file list (loading the database once). YARA compiles the rules once with `yarac` and scans
   in chunks with `--scan-list`. Integrity checks run up to 4 bundles in parallel.
3. A file counts as scanned once every engine that handles it is done. Cancelling terminates the child
   processes and keeps partial results.
4. Flagged results get a SHA-256 fingerprint. The ignore list is applied, optional VirusTotal lookups
   run, and the session is saved to history.

## Limitations

- This is an on-demand scanner, not real-time protection. Keep macOS (XProtect) up to date as well.
  The Downloads option scans a file after it arrives; it does not block it from being opened.
- ClamAV's macOS coverage is limited, and the bundled YARA rules are heuristics. A clean result is
  not a guarantee.
- `clamscan` loads the full signature database into memory (≈1 GB+) for the duration of a scan.
- `codesign --deep` on very large apps (e.g. Xcode) can take minutes.
