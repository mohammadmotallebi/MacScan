/*
    MacScan sample YARA rules for macOS.

    These are small, generic, heuristic rules meant as a starting point and as a
    working example of the rule format MacScan understands. They are NOT a
    replacement for a maintained ruleset. Point MacScan at your own rules folder
    in Settings > Engines to use more comprehensive rules.

    MacScan reads these optional meta fields:
        description  - shown as the reason in the results list
        severity     - "threat" or "warning" (default: warning)

    Script rules require a "#!" shebang at offset 0 so that documentation,
    READMEs and this rules file itself don't match.
*/

rule MacScan_EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless test string)"
        severity = "threat"
    strings:
        // "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" as hex, so this file doesn't match itself.
        $eicar = { 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 }
    condition:
        filesize < 256 and $eicar
}

rule MacOS_Script_Fake_Password_Prompt
{
    meta:
        description = "Script shows a fake password dialog via osascript (common in macOS info-stealers)"
        severity = "threat"
    strings:
        $osa = "osascript" nocase
        $dialog = "display dialog" nocase
        $hidden = "hidden answer" nocase
        $pw1 = "password" nocase
        $exfil1 = "curl " nocase
        $exfil2 = "dscl . authonly" nocase
    condition:
        uint16(0) == 0x2123 and filesize < 2MB and
        $osa and $dialog and $hidden and $pw1 and any of ($exfil*)
}

rule MacOS_Script_Browser_And_Keychain_Harvest
{
    meta:
        description = "Script collects browser data and the login keychain, then uploads it"
        severity = "threat"
    strings:
        $kc = "login.keychain-db"
        $b1 = "Google/Chrome" nocase
        $b2 = "BraveSoftware" nocase
        $b3 = "Firefox/Profiles" nocase
        $b4 = "Microsoft Edge" nocase
        $b5 = "Library/Cookies" nocase
        $d1 = "Login Data"
        $d2 = "Cookies"
        $d3 = "Web Data"
        $up1 = "curl " nocase
        $up2 = "ditto -c -k" nocase
        $up3 = "zip -r" nocase
    condition:
        uint16(0) == 0x2123 and filesize < 2MB and
        $kc and 2 of ($b*) and any of ($d*) and any of ($up*)
}

rule MacOS_Script_LaunchAgent_Persistence_Dropper
{
    meta:
        description = "Script downloads a payload and installs it as a LaunchAgent/LaunchDaemon"
        severity = "warning"
    strings:
        $la1 = "Library/LaunchAgents" nocase
        $la2 = "Library/LaunchDaemons" nocase
        $load1 = "launchctl load" nocase
        $load2 = "launchctl bootstrap" nocase
        $dl1 = "curl " nocase
        $dl2 = "wget " nocase
        $b64 = "base64 -d" nocase
        $b64b = "base64 --decode" nocase
    condition:
        uint16(0) == 0x2123 and filesize < 1MB and
        any of ($la*) and any of ($load*) and (any of ($dl*) or $b64 or $b64b)
}

rule MacOS_Script_Gatekeeper_Bypass_Download
{
    meta:
        description = "Script downloads a file, strips the quarantine attribute and makes it executable"
        severity = "warning"
    strings:
        $xq1 = "xattr -d com.apple.quarantine" nocase
        $xq2 = "xattr -c" nocase
        $xq3 = "xattr -cr" nocase
        $chmod = "chmod +x" nocase
        $dl1 = "curl " nocase
        $dl2 = "wget " nocase
    condition:
        uint16(0) == 0x2123 and filesize < 1MB and
        any of ($xq*) and $chmod and any of ($dl*)
}

rule MacOS_Script_Reverse_Shell
{
    meta:
        description = "Script contains a classic reverse-shell pattern"
        severity = "threat"
    strings:
        $r1 = /bash\s+-i\s+>&\s*\/dev\/tcp\//
        $r2 = /\/bin\/(ba|z)?sh\s+-i\s+[0-9]?>&\s*\/dev\/tcp\//
        $r3 = /nc\s+(-[a-z]+\s+)*-e\s+\/bin\/(ba|z)?sh/
        $r4 = "socket.socket(socket.AF_INET" nocase
        $r4b = "os.dup2(" nocase
        $r4c = "pty.spawn(" nocase
    condition:
        uint16(0) == 0x2123 and filesize < 1MB and
        (any of ($r1, $r2, $r3) or ($r4 and $r4b and $r4c))
}

rule MacOS_Script_Encoded_Payload_Exec
{
    meta:
        description = "Script decodes and executes an embedded base64 payload"
        severity = "warning"
    strings:
        $py = /exec\s*\(\s*base64\.b64decode\s*\(/
        $sh1 = /base64\s+(-d|-D|--decode)[^\n|]{0,80}\|\s*(\/bin\/)?(ba|z)?sh/
        $sh2 = /echo\s+['"]?[A-Za-z0-9+\/=]{200,}['"]?\s*\|\s*base64/
        $osa = /osascript\s+-e\s+[^\n]{0,40}base64/
    condition:
        uint16(0) == 0x2123 and filesize < 5MB and any of them
}

rule MacOS_MachO_Stealer_Strings
{
    meta:
        description = "Mach-O binary combines keychain access, browser credential paths and crypto-wallet paths"
        severity = "warning"
    strings:
        $kc1 = "login.keychain-db"
        $kc2 = "security find-generic-password"
        $br1 = "Library/Application Support/Google/Chrome"
        $br2 = "Library/Application Support/BraveSoftware"
        $br3 = "Library/Application Support/Firefox"
        $w1 = "Exodus" nocase
        $w2 = "Electrum" nocase
        $w3 = "atomic/Local Storage" nocase
        $w4 = "Coinomi" nocase
        $w5 = "nkbihfbeogaeaoehlefnkodbefgpgknn"   // MetaMask extension ID
        $osa = "osascript"
        $pw = "display dialog"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca) and
        filesize < 50MB and
        any of ($kc*) and 2 of ($br*) and 2 of ($w*) and ($osa and $pw)
}
