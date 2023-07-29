# AAR

AppleArchive high level Swift API

``` swift
public enum AppleArchiver {
    public static func encryptDirectory(path: String, output: String, key: SymmetricKey) throws

    @discardableResult
    public static func decryptDirectory(path: String, output: String, key: SymmetricKey) throws -> Int

    @discardableResult
    public static func encryptFile(source: String, destination: String, key: SymmetricKey) throws -> Int64

    @discardableResult
    public static func decryptFile(source: String, destination: String, key: SymmetricKey) throws -> Int64

    public static func encryptData(_ data: Data, destination: String, key: SymmetricKey) throws

    public static func decryptData(source: String, key: SymmetricKey) throws -> Data
}
```
