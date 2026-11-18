import Foundation
import os

public struct ProcessResult: Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
}

public enum ProcessRunnerError: Error, LocalizedError {
    case launchFailed(path: String, underlying: String)

    public var errorDescription: String? {
        switch self {
        case .launchFailed(let path, let underlying):
            "Could not launch \(path): \(underlying)"
        }
    }
}

/// Keeps track of every child process MacScan starts, so they can all be terminated when the app quits.
/// (macOS does not kill children when the parent exits.)
public final class ProcessRegistry: Sendable {
    public static let shared = ProcessRegistry()

    private let processes = OSAllocatedUnfairLock<[ObjectIdentifier: ProcessBox]>(initialState: [:])

    fileprivate func add(_ box: ProcessBox) {
        processes.withLock { $0[ObjectIdentifier(box)] = box }
    }

    fileprivate func remove(_ box: ProcessBox) {
        _ = processes.withLock { $0.removeValue(forKey: ObjectIdentifier(box)) }
    }

    public var runningCount: Int { processes.withLock { $0.count } }

    /// Sends SIGTERM to every running child process.
    public func terminateAll() {
        let boxes = processes.withLock { Array($0.values) }
        boxes.forEach { $0.terminate() }
    }
}

/// Wraps `Process` so it can be terminated safely from a cancellation handler on another thread.
final class ProcessBox: @unchecked Sendable {
    private struct State {
        var started = false
        var cancelled = false
    }

    let process: Process
    private let state = OSAllocatedUnfairLock(initialState: State())

    init(_ process: Process) { self.process = process }

    /// Marks the box as started. Returns false if cancellation already happened (caller should terminate).
    func markStarted() -> Bool {
        state.withLock { s in
            s.started = true
            return !s.cancelled
        }
    }

    func terminate() {
        let shouldTerminate = state.withLock { s -> Bool in
            s.cancelled = true
            return s.started
        }
        if shouldTerminate, process.isRunning {
            process.terminate()
        }
    }
}

/// Resumes waiters once a process has exited.
private final class ExitWaiter: Sendable {
    private struct State {
        var status: Int32?
        var continuation: CheckedContinuation<Int32, Never>?
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    func signal(_ status: Int32) {
        let cont = state.withLock { s -> CheckedContinuation<Int32, Never>? in
            if let c = s.continuation {
                s.continuation = nil
                return c
            }
            s.status = status
            return nil
        }
        cont?.resume(returning: status)
    }

    func wait() async -> Int32 {
        await withCheckedContinuation { (c: CheckedContinuation<Int32, Never>) in
            let ready = state.withLock { s -> Int32? in
                if let status = s.status { return status }
                s.continuation = c
                return nil
            }
            if let ready { c.resume(returning: ready) }
        }
    }
}

public enum ProcessRunner {
    /// Runs an executable and waits for it to exit.
    ///
    /// - Parameters:
    ///   - onStdoutLine: called for every non-empty stdout line as it arrives.
    ///   - collectStdout: set to false for very chatty tools when only `onStdoutLine` is needed.
    /// - Throws: `CancellationError` if the surrounding Task is cancelled (the child is terminated),
    ///           `ProcessRunnerError.launchFailed` if it cannot start.
    public static func run(
        _ executable: URL,
        _ arguments: [String],
        collectStdout: Bool = true,
        onStdoutLine: (@Sendable (String) async -> Void)? = nil
    ) async throws -> ProcessResult {
        try Task.checkCancellation()

        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        let box = ProcessBox(process)
        let waiter = ExitWaiter()
        process.terminationHandler = { p in waiter.signal(p.terminationStatus) }

        return try await withTaskCancellationHandler {
            do {
                try process.run()
            } catch {
                throw ProcessRunnerError.launchFailed(path: executable.path, underlying: error.localizedDescription)
            }
            ProcessRegistry.shared.add(box)
            defer { ProcessRegistry.shared.remove(box) }
            if !box.markStarted() { box.terminate() }

            let errHandle = errPipe.fileHandleForReading
            let errTask = Task.detached { errHandle.readDataToEndOfFile() }

            var stdout = ""
            do {
                for try await line in outPipe.fileHandleForReading.bytes.lines {
                    if collectStdout {
                        stdout += line
                        stdout += "\n"
                    }
                    if let onStdoutLine { await onStdoutLine(line) }
                }
            } catch is CancellationError {
                box.terminate()
            }

            let errData = await errTask.value
            let status = await waiter.wait()
            try Task.checkCancellation()
            return ProcessResult(
                exitCode: status,
                stdout: stdout,
                stderr: String(decoding: errData, as: UTF8.self)
            )
        } onCancel: {
            box.terminate()
        }
    }
}
