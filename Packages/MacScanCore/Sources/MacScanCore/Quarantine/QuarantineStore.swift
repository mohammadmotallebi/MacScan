import Foundation

/// A file or folder the user moved into MacScan's quarantine.
public struct QuarantinedItem: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    /// Where it was, and where Restore puts it back.
    public var originalPath: String
    public var date: Date
    /// Why it was flagged (the result's reason), for the list.
    public var reason: String
    public var engine: EngineID?
    public var sha256: String?
    /// Size of a file; nil for folders and apps.
    public var size: Int64?
    public var isDirectory: Bool
    /// The permission bits it had, restored with it.
    public var originalMode: UInt16

    public var name: String { (originalPath as NSString).lastPathComponent }
}

public enum QuarantineError: Error, LocalizedError, Equatable {
    case protectedLocation(String)
    case notFound(String)
    case permissionDenied(String)
    case restoreTargetExists(String)
    case restoreFolderMissing(String)
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .protectedLocation(let path):
            "\(path) is a system or top-level location. MacScan never moves those."
        case .notFound(let path):
            "\(path) no longer exists."
        case .permissionDenied(let path):
            "macOS didn't allow moving \(path). It may be owned by another user or protected by macOS. You can move it to the Trash yourself in Finder."
        case .restoreTargetExists(let path):
            "Something else is now at \(path). Move or rename it first, then restore again."
        case .restoreFolderMissing(let path):
            "The folder it came from no longer exists: \(path). Create that folder first, then restore again."
        case .failed(let message):
            message
        }
    }
}

/// MacScan's quarantine: flagged items are moved into a private folder and locked (no permissions), so
/// they can't run or be opened by accident, and can be put back exactly where they were. Every move is
/// started by the user; nothing is quarantined, restored or deleted automatically.
///
/// Layout: `<directory>/<id>/payload` (the item) and `<directory>/<id>/info.json` (where it came from).
public struct QuarantineStore: Sendable {
    public let directory: URL

    public init(directory: URL = AppPaths.quarantine) {
        self.directory = directory
    }

    static let payloadName = "payload"
    static let infoName = "info.json"

    private func folder(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString, isDirectory: true) }
    private func payload(_ id: UUID) -> URL { folder(id).appendingPathComponent(Self.payloadName) }

    /// Everything in quarantine, newest first. Folders without readable info are skipped.
    public func list() -> [QuarantinedItem] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        var items: [QuarantinedItem] = []
        for name in names {
            let info = directory.appendingPathComponent(name).appendingPathComponent(Self.infoName)
            guard let data = try? Data(contentsOf: info),
                  let item = try? JSONDecoder.macScan.decode(QuarantinedItem.self, from: data) else { continue }
            items.append(item)
        }
        return items.sorted { $0.date > $1.date }
    }

    /// Moves the item into quarantine and locks it. The original location is left empty.
    @discardableResult
    public func quarantine(path: String, reason: String, engine: EngineID? = nil, sha256: String? = nil) throws -> QuarantinedItem {
        // Resolve the folder it is in (so /var/… and /private/var/… compare equal) but not the item
        // itself: a symlink is moved as a link.
        let given = URL(fileURLWithPath: path)
        let url = Paths.canonical(given.deletingLastPathComponent()).appendingPathComponent(given.lastPathComponent)
        let home = Paths.canonical(directory).path
        let inside = url.path == home || url.path.hasPrefix(home + "/")
        guard Uninstaller.isSafeToRemove(url.path), !inside else { throw QuarantineError.protectedLocation(path) }

        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw QuarantineError.notFound(path) }
        let kind = info.st_mode & S_IFMT
        let isDirectory = kind == S_IFDIR
        let item = QuarantinedItem(
            id: UUID(), originalPath: url.path, date: Date(), reason: reason, engine: engine,
            sha256: sha256 ?? (kind == S_IFREG || isDirectory ? FileHasher.fingerprint(for: url.path) : nil),
            size: kind == S_IFREG ? Int64(info.st_size) : nil,
            isDirectory: isDirectory,
            originalMode: UInt16(info.st_mode & 0o7777))

        let fm = FileManager.default
        let folder = folder(item.id)
        do {
            try fm.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try fm.moveItem(at: url, to: payload(item.id))
        } catch {
            try? fm.removeItem(at: folder)
            throw PermissionErrors.isPermissionDenied(error) ? QuarantineError.permissionDenied(path) : QuarantineError.failed(error.localizedDescription)
        }
        do {
            try JSONEncoder.macScan.encode(item).write(to: folder.appendingPathComponent(Self.infoName), options: .atomic)
        } catch {
            // Without its info the item couldn't be restored: put it back rather than strand it.
            try? fm.moveItem(at: payload(item.id), to: url)
            try? fm.removeItem(at: folder)
            throw QuarantineError.failed("Could not record the quarantined item: \(error.localizedDescription)")
        }
        // Lock it: no read, write or execute for anyone (a symlink has no permissions of its own).
        if kind != S_IFLNK { chmod(payload(item.id).path, 0) }
        return item
    }

    /// Puts the item back where it was, with its original permissions.
    public func restore(_ item: QuarantinedItem) throws {
        let fm = FileManager.default
        let source = payload(item.id)
        let target = URL(fileURLWithPath: item.originalPath)
        var info = stat()
        guard lstat(source.path, &info) == 0 else { throw QuarantineError.notFound(source.path) }
        guard lstat(target.path, &info) != 0 else { throw QuarantineError.restoreTargetExists(item.originalPath) }
        let parent = target.deletingLastPathComponent()
        guard fm.fileExists(atPath: parent.path) else { throw QuarantineError.restoreFolderMissing(parent.path) }

        unlock(item)
        do {
            try fm.moveItem(at: source, to: target)
        } catch {
            lock(item)
            throw PermissionErrors.isPermissionDenied(error) ? QuarantineError.permissionDenied(item.originalPath) : QuarantineError.failed(error.localizedDescription)
        }
        try? fm.removeItem(at: folder(item.id))
    }

    /// Deletes the quarantined item for good. There is no undo.
    public func delete(_ item: QuarantinedItem) throws {
        chmod(payload(item.id).path, 0o700)   // a locked folder can't be emptied
        do {
            try FileManager.default.removeItem(at: folder(item.id))
        } catch {
            lock(item)
            throw QuarantineError.failed(error.localizedDescription)
        }
    }

    private func isSymlink(_ item: QuarantinedItem) -> Bool {
        var info = stat()
        return lstat(payload(item.id).path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }

    private func unlock(_ item: QuarantinedItem) {
        if !isSymlink(item) { chmod(payload(item.id).path, mode_t(item.originalMode)) }
    }

    private func lock(_ item: QuarantinedItem) {
        if !isSymlink(item) { chmod(payload(item.id).path, 0) }
    }
}
