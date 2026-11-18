import Foundation

/// Minimal Mach-O header inspection (no dependencies), used to find executable code.
public enum MachO {
    public enum Inspection: Equatable, Sendable {
        /// Executable code: MH_EXECUTE, MH_DYLIB, MH_BUNDLE, MH_DYLINKER, MH_KEXT_BUNDLE.
        case executableCode
        /// Mach-O but not runnable code (object files, dSYMs, core dumps…).
        case otherMachO
        case notMachO
        case unreadable(errno: Int32)
    }

    private static let thinMagics: Set<UInt32> = [0xFEED_FACE, 0xFEED_FACF]       // native byte order
    private static let thinMagicsSwapped: Set<UInt32> = [0xCEFA_EDFE, 0xCFFA_EDFE]
    private static let fatMagicBE: UInt32 = 0xCAFE_BABE
    private static let fatMagic64BE: UInt32 = 0xCAFE_BABF
    private static let codeFileTypes: Set<UInt32> = [0x2, 0x6, 0x7, 0x8, 0xB]

    public static func inspect(path: String) -> Inspection {
        let fd = open(path, O_RDONLY | O_NONBLOCK)
        if fd < 0 { return .unreadable(errno: errno) }
        defer { close(fd) }

        var header = [UInt8](repeating: 0, count: 32)
        let n = header.withUnsafeMutableBytes { read(fd, $0.baseAddress, 32) }
        guard n >= 8 else { return .notMachO }

        let magicLE = le32(header, 0)
        let magicBE = be32(header, 0)

        if thinMagics.contains(magicLE) {
            guard n >= 16 else { return .otherMachO }
            return codeFileTypes.contains(le32(header, 12)) ? .executableCode : .otherMachO
        }
        if thinMagicsSwapped.contains(magicLE) {
            guard n >= 16 else { return .otherMachO }
            return codeFileTypes.contains(be32(header, 12)) ? .executableCode : .otherMachO
        }
        if magicBE == fatMagicBE || magicBE == fatMagic64BE {
            // 0xCAFEBABE is also the Java class magic; Java versions (>= 45) are far larger than arch counts.
            let nArch = be32(header, 4)
            guard nArch > 0, nArch < 30 else { return .notMachO }
            // Inspect the first slice's header.
            let is64 = magicBE == fatMagic64BE
            let offset: UInt64 = is64 ? be64(header, 8 + 8) : UInt64(be32(header, 8 + 8))
            var slice = [UInt8](repeating: 0, count: 16)
            let m = slice.withUnsafeMutableBytes { pread(fd, $0.baseAddress, 16, off_t(offset)) }
            guard m == 16 else { return .otherMachO }
            let sliceMagic = le32(slice, 0)
            if thinMagics.contains(sliceMagic) {
                return codeFileTypes.contains(le32(slice, 12)) ? .executableCode : .otherMachO
            }
            if thinMagicsSwapped.contains(sliceMagic) {
                return codeFileTypes.contains(be32(slice, 12)) ? .executableCode : .otherMachO
            }
            return .otherMachO
        }
        return .notMachO
    }

    private static func le32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
    }

    private static func be32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) << 24 | UInt32(b[o + 1]) << 16 | UInt32(b[o + 2]) << 8 | UInt32(b[o + 3])
    }

    private static func be64(_ b: [UInt8], _ o: Int) -> UInt64 {
        UInt64(be32(b, o)) << 32 | UInt64(be32(b, o + 4))
    }
}
