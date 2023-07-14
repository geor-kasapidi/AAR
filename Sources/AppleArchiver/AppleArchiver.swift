import AppleArchive
import CryptoKit
import Foundation
import System

// https://developer.apple.com/documentation/applearchive

extension ArchiveStream: Closable {}
extension ArchiveByteStream: Closable {}

public enum AppleArchiver {
    // MARK: Public

    public static func encryptDirectory(path: FilePath, output: FilePath, key: SymmetricKey) throws {
        try withClosables(error: ArchiveError.ioError) { closables in
            guard key.bitCount == 256 else {
                throw ArchiveError.invalidValue
            }

            let context = try Self.makeEncryptionContext(key: key)

            let fileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: output,
                    mode: .writeOnly,
                    options: [.create, .truncate],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            let encryptionStream = try closables.new {
                ArchiveByteStream.encryptionStream(
                    writingTo: fileStream,
                    encryptionContext: context
                )
            }

            let encodeStream = try closables.new {
                ArchiveStream.encodeStream(writingTo: encryptionStream)
            }

            try encodeStream.writeDirectoryContents(
                archiveFrom: path,
                keySet: .init("TYP,PAT,DAT")!
            )
        }
    }

    @discardableResult
    public static func decryptDirectory(path: FilePath, output: FilePath, key: SymmetricKey) throws -> Int {
        try withClosables(error: ArchiveError.ioError) { closables in
            guard key.bitCount == 256 else {
                throw ArchiveError.invalidValue
            }

            let fileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: path,
                    mode: .readOnly,
                    options: [],
                    permissions: []
                )
            }

            guard let context = ArchiveEncryptionContext(from: fileStream) else {
                throw ArchiveError.ioError
            }

            try context.setSymmetricKey(key)

            let decryptionStream = try closables.new {
                ArchiveByteStream.decryptionStream(
                    readingFrom: fileStream,
                    encryptionContext: context
                )
            }

            let decodeStream = try closables.new {
                ArchiveStream.decodeStream(readingFrom: decryptionStream)
            }

            let extractStream = try closables.new {
                ArchiveStream.extractStream(extractingTo: output)
            }

            let count = try ArchiveStream.process(readingFrom: decodeStream, writingTo: extractStream)

            return count
        }
    }

    @discardableResult
    public static func encryptFile(source: FilePath, destination: FilePath, key: SymmetricKey) throws -> Int64 {
        try withClosables(error: ArchiveError.ioError) { closables in
            guard key.bitCount == 256 else {
                throw ArchiveError.invalidValue
            }

            let context = try Self.makeEncryptionContext(key: key)

            let sourceFileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: source,
                    mode: .readOnly,
                    options: [],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            let destinationFileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: destination,
                    mode: .writeOnly,
                    options: [.create, .truncate],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            let encryptionStream = try closables.new {
                ArchiveByteStream.encryptionStream(
                    writingTo: destinationFileStream,
                    encryptionContext: context
                )
            }

            let result = try ArchiveByteStream.process(
                readingFrom: sourceFileStream,
                writingTo: encryptionStream
            )

            return result
        }
    }

    @discardableResult
    public static func decryptFile(source: FilePath, destination: FilePath, key: SymmetricKey) throws -> Int64 {
        try withClosables(error: ArchiveError.ioError) { closables in
            guard key.bitCount == 256 else {
                throw ArchiveError.invalidValue
            }

            let sourceFileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: source,
                    mode: .readOnly,
                    options: [],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            guard let context = ArchiveEncryptionContext(from: sourceFileStream) else {
                throw ArchiveError.ioError
            }

            try context.setSymmetricKey(key)

            let decryptionStream = try closables.new {
                ArchiveByteStream.decryptionStream(
                    readingFrom: sourceFileStream,
                    encryptionContext: context
                )
            }

            let destinationFileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: destination,
                    mode: .writeOnly,
                    options: [.create, .truncate],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            let result = try ArchiveByteStream.process(
                readingFrom: decryptionStream,
                writingTo: destinationFileStream
            )

            return result
        }
    }

    public static func encryptData(_ data: Data, destination: FilePath, key: SymmetricKey) throws {
        try withClosables(error: ArchiveError.ioError) { closables in
            guard key.bitCount == 256 else {
                throw ArchiveError.invalidValue
            }

            let context = try Self.makeEncryptionContext(key: key)

            let destinationFileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: destination,
                    mode: .writeOnly,
                    options: [.create, .truncate],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            let encryptionStream = try closables.new {
                ArchiveByteStream.encryptionStream(
                    writingTo: destinationFileStream,
                    encryptionContext: context
                )
            }

            let encodeStream = try closables.new {
                ArchiveStream.encodeStream(writingTo: encryptionStream)
            }

            let header = ArchiveHeader()

            header.append(.string(key: ArchiveHeader.FieldKey("PAT"), value: "data"))
            header.append(.uint(key: ArchiveHeader.FieldKey("TYP"), value: UInt64(ArchiveHeader.EntryType.regularFile.rawValue)))
            header.append(.blob(key: ArchiveHeader.FieldKey("DAT"), size: UInt64(data.count)))

            try encodeStream.writeHeader(header)

            try data.withUnsafeBytes {
                try encodeStream.writeBlob(key: ArchiveHeader.FieldKey("DAT"), from: $0)
            }
        }
    }

    public static func decryptData(source: FilePath, key: SymmetricKey) throws -> Data {
        try withClosables(error: ArchiveError.ioError) { closables in
            guard key.bitCount == 256 else {
                throw ArchiveError.invalidValue
            }

            let fileStream = try closables.new {
                ArchiveByteStream.fileStream(
                    path: source,
                    mode: .readOnly,
                    options: [],
                    permissions: FilePermissions(rawValue: 0o644)
                )
            }

            guard let context = ArchiveEncryptionContext(from: fileStream) else {
                throw ArchiveError.ioError
            }

            try context.setSymmetricKey(key)

            let decryptionStream = try closables.new {
                ArchiveByteStream.decryptionStream(
                    readingFrom: fileStream,
                    encryptionContext: context
                )
            }

            let decodeStream = try closables.new {
                ArchiveStream.decodeStream(readingFrom: decryptionStream)
            }

            guard let header = try decodeStream.readHeader(),
                  let dat = header.field(forKey: ArchiveHeader.FieldKey("DAT"))
            else {
                throw ArchiveError.invalidValue
            }

            let byteCount: UInt64

            switch dat {
            case let .blob(_, size, _) where size > 0:
                byteCount = size
            default:
                throw ArchiveError.invalidValue
            }

            var data = Data(count: Int(byteCount))

            try data.withUnsafeMutableBytes {
                try decodeStream.readBlob(key: ArchiveHeader.FieldKey("DAT"), into: $0)
            }

            return data
        }
    }

    // MARK: Private

    private static func makeEncryptionContext(key: SymmetricKey) throws -> ArchiveEncryptionContext {
        let context = ArchiveEncryptionContext(
            profile: .hkdf_sha256_aesctr_hmac__symmetric__none,
            compressionAlgorithm: .lzfse
        )
        try context.setSymmetricKey(key)
        return context
    }
}
