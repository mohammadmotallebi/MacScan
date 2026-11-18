import Foundation
import Testing
@testable import MacScanCore

@Suite struct ProcessRunnerTests {
    @Test func capturesStdoutStderrAndExitCode() async throws {
        let r = try await ProcessRunner.run(
            URL(fileURLWithPath: "/bin/sh"),
            ["-c", "echo hello; echo world; echo oops >&2; exit 3"]
        )
        #expect(r.exitCode == 3)
        #expect(r.stdout == "hello\nworld\n")
        #expect(r.stderr.contains("oops"))
    }

    @Test func streamsLines() async throws {
        let lines = LineCollector()
        _ = try await ProcessRunner.run(URL(fileURLWithPath: "/bin/sh"), ["-c", "printf 'a\\nb\\nc\\n'"]) { line in
            await lines.add(line)
        }
        #expect(await lines.lines == ["a", "b", "c"])
    }

    @Test func cancellationTerminatesChild() async throws {
        let start = ContinuousClock.now
        let task = Task {
            try await ProcessRunner.run(URL(fileURLWithPath: "/bin/sleep"), ["30"])
        }
        try await Task.sleep(for: .milliseconds(300))
        task.cancel()
        let result = await task.result
        #expect(throws: CancellationError.self) { try result.get() }
        #expect(ContinuousClock.now - start < .seconds(5))
    }

    @Test func launchFailureThrows() async {
        await #expect(throws: ProcessRunnerError.self) {
            try await ProcessRunner.run(URL(fileURLWithPath: "/nonexistent/tool"), [])
        }
    }
}

actor LineCollector {
    var lines: [String] = []
    func add(_ l: String) { lines.append(l) }
}

@Suite struct SettingsTests {
    @Test func exclusionMatchesPrefixesOnly() {
        var s = ScanSettings()
        s.excludedPaths = ["/Users/me/Projects/", "~/Movies"]
        #expect(s.isExcluded("/Users/me/Projects"))
        #expect(s.isExcluded("/Users/me/Projects/a/b.txt"))
        #expect(!s.isExcluded("/Users/me/ProjectsOld/x"))
        #expect(s.isExcluded(NSHomeDirectory() + "/Movies/clip.mov"))
    }

    @Test func decodingToleratesMissingKeys() throws {
        let data = Data(#"{"maxFileSizeMB": 42}"#.utf8)
        let s = try JSONDecoder().decode(ScanSettings.self, from: data)
        #expect(s.maxFileSizeMB == 42)
        #expect(s.skipSymlinks == true)
        #expect(s.enableClamAV == true)
    }

    @Test func roundTripsThroughUserDefaults() throws {
        let defaults = try #require(UserDefaults(suiteName: "MacScanTests-\(UUID())"))
        var s = ScanSettings()
        s.maxFileSizeMB = 7
        s.excludedPaths = ["/tmp"]
        SettingsStore.save(s, to: defaults)
        #expect(SettingsStore.load(from: defaults) == s)
    }
}

@Suite struct LoggerTests {
    @Test func writesToFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("MacScanLogTest-\(UUID())")
        let logger = FileLogger(directory: dir)
        logger.info("hello log")
        logger.flush()
        let text = try String(contentsOf: logger.fileURL, encoding: .utf8)
        #expect(text.contains("[INFO] hello log"))
        try? FileManager.default.removeItem(at: dir)
    }
}

@Suite struct ToolLocatorTests {
    @Test func overrideMustBeExecutable() {
        #expect(ToolLocator.locate(.yara, override: "/bin/ls")?.path == "/bin/ls")
        #expect(ToolLocator.locate(.yara, override: "/nonexistent/yara") == nil)
    }
}
