//
//  KeychainPassphrase.swift
//
//  Generates a strong random passphrase on first launch, stores it in the
//  Keychain, and returns the same value thereafter. Works on iOS and macOS.
//
//  The item is protected with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
//  so it is available to background work after the first unlock but never
//  leaves the device (not synced, not included in encrypted backups restored to
//  another device).
//

import Foundation
import Security

enum KeychainPassphrase {

    /// Errors surfaced by the helper. Keychain failures are generally fatal for
    /// an encrypted store (without the key, the data is unreadable), so callers
    /// usually treat these as unrecoverable.
    enum KeychainError: Error {
        case unexpectedStatus(OSStatus)
        case randomGenerationFailed
    }

    /// Returns the persistent database passphrase, creating and storing one on
    /// first use.
    ///
    /// - Parameters:
    ///   - service: Keychain service identifier (defaults to the bundle id).
    ///   - account: Logical key name within the service.
    static func passphrase(service: String? = nil,
                           account: String = "EncryptedStore.databaseKey") throws -> String {
        let service = service ?? (Bundle.main.bundleIdentifier ?? "EncryptedCoreDataSwift")

        if let existing = try read(service: service, account: account) {
            return existing
        }

        let generated = try makeRandomPassphrase()
        try store(generated, service: service, account: account)
        return generated
    }

    // MARK: - Private

    private static func makeRandomPassphrase(byteCount: Int = 32) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        guard status == errSecSuccess else { throw KeychainError.randomGenerationFailed }
        // Base64 keeps it printable for SQLCipher's PRAGMA key.
        return Data(bytes).base64EncodedString()
    }

    private static func baseQuery(service: String, account: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private static func read(service: String, account: String) throws -> String? {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data,
                  let string = String(data: data, encoding: .utf8) else {
                return nil
            }
            return string
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private static func store(_ passphrase: String, service: String, account: String) throws {
        var query = baseQuery(service: service, account: account)
        query[kSecValueData as String] = Data(passphrase.utf8)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Removes the stored passphrase. Useful for tests or a "reset" action.
    /// ⚠️ After this, the existing encrypted database can no longer be opened.
    static func reset(service: String? = nil,
                      account: String = "EncryptedStore.databaseKey") throws {
        let service = service ?? (Bundle.main.bundleIdentifier ?? "EncryptedCoreDataSwift")
        let status = SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}
