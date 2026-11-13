// WebScarab (Swift) - the local certificate authority used to intercept HTTPS
// (plugin.proxy.SSLSocketFactoryFactory / util.SunCertificateUtils).
//
// A CA key pair and one host key pair are kept in the login keychain; the CA
// certificate is written to Application Support so it can be exported and trusted.
// Each intercepted host gets a certificate signed by the CA, made on demand.

import Foundation
import Security
import CryptoKit

/// Minimal DER encoding for X.509 certificates.
public enum DER {
    public static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 { bytes.insert(UInt8(value & 0xff), at: 0); value >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    public static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { [tag] + length(content.count) + content }
    public static func sequence(_ items: [[UInt8]]) -> [UInt8] { tlv(0x30, items.flatMap { $0 }) }
    public static func set(_ items: [[UInt8]]) -> [UInt8] { tlv(0x31, items.flatMap { $0 }) }
    public static func explicit(_ number: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0xA0 | number, content) }
    public static let null: [UInt8] = [0x05, 0x00]
    public static let trueValue: [UInt8] = [0x01, 0x01, 0xFF]

    public static func integer(_ bytes: [UInt8]) -> [UInt8] {
        var content = Array(bytes.drop(while: { $0 == 0 }))
        if content.isEmpty { content = [0] }
        if content[0] & 0x80 != 0 { content.insert(0, at: 0) }
        return tlv(0x02, content)
    }

    public static func integer(_ value: Int) -> [UInt8] {
        var bytes: [UInt8] = []
        var v = value
        repeat { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 } while v > 0
        return integer(bytes)
    }

    public static func oid(_ dotted: String) -> [UInt8] {
        let parts = dotted.split(separator: ".").compactMap { UInt64($0) }
        guard parts.count >= 2 else { return tlv(0x06, []) }
        var content: [UInt8] = [UInt8(parts[0] * 40 + parts[1])]
        for var part in parts.dropFirst(2) {
            var chunk: [UInt8] = [UInt8(part & 0x7f)]
            part >>= 7
            while part > 0 { chunk.insert(UInt8(part & 0x7f) | 0x80, at: 0); part >>= 7 }
            content += chunk
        }
        return tlv(0x06, content)
    }

    public static func utf8String(_ text: String) -> [UInt8] { tlv(0x0C, Array(text.utf8)) }
    public static func octetString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x04, bytes) }
    public static func bitString(_ bytes: [UInt8], unusedBits: UInt8 = 0) -> [UInt8] { tlv(0x03, [unusedBits] + bytes) }

    public static func time(_ date: Date) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        let year = Calendar(identifier: .gregorian).dateComponents(in: TimeZone(identifier: "UTC")!, from: date).year ?? 2000
        if year < 2050 {
            formatter.dateFormat = "yyMMddHHmmss'Z'"
            return tlv(0x17, Array(formatter.string(from: date).utf8))
        }
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        return tlv(0x18, Array(formatter.string(from: date).utf8))
    }

    public static func name(commonName: String, organizationalUnit: String = "WebScarab", organization: String = "OWASP") -> [UInt8] {
        func rdn(_ oid: String, _ value: String) -> [UInt8] { set([sequence([DER.oid(oid), utf8String(value)])]) }
        return sequence([rdn("2.5.4.10", organization), rdn("2.5.4.11", organizationalUnit), rdn("2.5.4.3", commonName)])
    }

    /// The elements inside a constructed DER value.
    public static func children(_ bytes: [UInt8]) -> [[UInt8]] {
        guard bytes.count >= 2 else { return [] }
        guard let (headerLength, contentLength) = header(bytes, at: 0) else { return [] }
        var result: [[UInt8]] = []
        var offset = headerLength
        let end = min(bytes.count, headerLength + contentLength)
        while offset < end, let (h, c) = header(bytes, at: offset), offset + h + c <= end {
            result.append(Array(bytes[offset..<(offset + h + c)]))
            offset += h + c
        }
        return result
    }

    static func header(_ bytes: [UInt8], at offset: Int) -> (Int, Int)? {
        guard offset + 1 < bytes.count else { return nil }
        let first = bytes[offset + 1]
        if first < 0x80 { return (2, Int(first)) }
        let count = Int(first & 0x7f)
        guard count > 0, count <= 4, offset + 2 + count <= bytes.count else { return nil }
        var length = 0
        for i in 0..<count { length = length << 8 | Int(bytes[offset + 2 + i]) }
        return (2 + count, length)
    }

    /// The subject Name of a DER certificate, byte for byte.
    public static func subject(ofCertificate der: [UInt8]) -> [UInt8]? {
        guard let tbs = children(der).first else { return nil }
        let fields = children(tbs)
        let offset = fields.first?.first == 0xA0 ? 1 : 0
        guard fields.count > offset + 4 else { return nil }
        return fields[offset + 4]
    }

    public static func extensionField(_ oid: String, critical: Bool, _ value: [UInt8]) -> [UInt8] {
        sequence([DER.oid(oid)] + (critical ? [trueValue] : []) + [octetString(value)])
    }
}

public enum CertificateError: Error, CustomStringConvertible {
    case keychain(OSStatus, String)
    case signing(String)
    case invalidCertificate

    public var description: String {
        switch self {
        case .keychain(let status, let what): return "Keychain error \(status) while \(what)"
        case .signing(let what): return "Could not sign certificate: \(what)"
        case .invalidCertificate: return "The generated certificate was not accepted"
        }
    }
}

public enum CertificateBuilder {
    static let sha256WithRSA = DER.sequence([DER.oid("1.2.840.113549.1.1.11"), DER.null])

    public static func subjectPublicKeyInfo(_ publicKey: SecKey) throws -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CertificateError.signing(error?.takeRetainedValue().localizedDescription ?? "no public key")
        }
        return DER.sequence([DER.sequence([DER.oid("1.2.840.113549.1.1.1"), DER.null]), DER.bitString(Array(raw))])
    }

    static func keyIdentifier(_ publicKey: SecKey) -> [UInt8] {
        let raw = (SecKeyCopyExternalRepresentation(publicKey, nil) as Data?) ?? Data()
        return Array(Insecure.SHA1.hash(data: raw))
    }

    static func randomSerial() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        bytes[0] &= 0x7f
        bytes[0] |= 0x01
        return bytes
    }

    /// Builds and signs an X.509 v3 certificate.
    public static func certificate(subject: [UInt8], issuer: [UInt8], subjectKey: SecKey, issuerKey: SecKey, issuerPublicKey: SecKey,
                                   isCA: Bool, hostName: String?, validDays: Int) throws -> Data {
        let now = Date()
        var extensions: [[UInt8]] = []
        if isCA {
            extensions.append(DER.extensionField("2.5.29.19", critical: true, DER.sequence([DER.trueValue])))
            extensions.append(DER.extensionField("2.5.29.15", critical: true, [0x03, 0x02, 0x01, 0x06])) // keyCertSign, cRLSign
        } else {
            extensions.append(DER.extensionField("2.5.29.19", critical: true, DER.sequence([])))
            extensions.append(DER.extensionField("2.5.29.15", critical: true, [0x03, 0x02, 0x05, 0xA0])) // digitalSignature, keyEncipherment
            extensions.append(DER.extensionField("2.5.29.37", critical: false, DER.sequence([DER.oid("1.3.6.1.5.5.7.3.1")])))
            if let hostName {
                let general: [UInt8]
                if let ip = ipAddressBytes(hostName) {
                    general = DER.tlv(0x87, ip)
                } else {
                    general = DER.tlv(0x82, Array(hostName.utf8))
                }
                extensions.append(DER.extensionField("2.5.29.17", critical: false, DER.sequence([general])))
            }
            extensions.append(DER.extensionField("2.5.29.35", critical: false, DER.sequence([DER.tlv(0x80, keyIdentifier(issuerPublicKey))])))
        }
        guard let subjectPublic = SecKeyCopyPublicKey(subjectKey) else { throw CertificateError.signing("no public key") }
        extensions.append(DER.extensionField("2.5.29.14", critical: false, DER.octetString(keyIdentifier(subjectPublic))))

        let tbs = DER.sequence([
            DER.explicit(0, DER.integer(2)),
            DER.integer(randomSerial()),
            sha256WithRSA,
            issuer,
            DER.sequence([DER.time(now.addingTimeInterval(-86400 * 30)), DER.time(now.addingTimeInterval(Double(validDays) * 86400))]),
            subject,
            try subjectPublicKeyInfo(subjectPublic),
            DER.explicit(3, DER.sequence(extensions)),
        ])
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(issuerKey, .rsaSignatureMessagePKCS1v15SHA256, Data(tbs) as CFData, &error) as Data? else {
            throw CertificateError.signing(error?.takeRetainedValue().localizedDescription ?? "signature failed")
        }
        return Data(DER.sequence([tbs, sha256WithRSA, DER.bitString(Array(signature))]))
    }

    static func ipAddressBytes(_ text: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        var v6 = in6_addr()
        let trimmed = text.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if inet_pton(AF_INET6, trimmed, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
        return nil
    }

    public static func newRSAKey(permanentTag: String?) throws -> SecKey {
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        if let permanentTag {
            attributes[kSecPrivateKeyAttrs as String] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(permanentTag.utf8),
                kSecAttrLabel as String: "WebScarab \(permanentTag.split(separator: ".").last ?? "")",
            ] as [String: Any]
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw CertificateError.signing(error?.takeRetainedValue().localizedDescription ?? "key generation failed")
        }
        return key
    }
}

/// Holds the CA and makes per-host identities. Thread-safe.
public final class CertificateAuthority: @unchecked Sendable {
    public static let shared = CertificateAuthority()
    static let caTag = "org.owasp.webscarab.swift.ca"
    static let hostTag = "org.owasp.webscarab.swift.host"

    private let lock = NSLock()
    private var caKey: SecKey?
    private var hostKey: SecKey?
    private var caCertificate: SecCertificate?
    private var identities: [String: SecIdentity] = [:]

    public var caCertificateURL: URL {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("WebScarab", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent("WebScarab-CA.cer")
    }

    public var caSummary: String? {
        lock.lock(); defer { lock.unlock() }
        guard let caCertificate else { return nil }
        return SecCertificateCopySubjectSummary(caCertificate) as String?
    }

    public var caCertificateData: Data? {
        lock.lock(); defer { lock.unlock() }
        guard let caCertificate else { return try? Data(contentsOf: caCertificateURL) }
        return SecCertificateCopyData(caCertificate) as Data
    }

    static func findKey(tag: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else { return nil }
        return (item as! SecKey)
    }

    static func deleteKey(tag: String) {
        let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: Data(tag.utf8)]
        SecItemDelete(query as CFDictionary)
    }

    /// Loads the CA, creating it the first time.
    public func prepare() throws {
        lock.lock(); defer { lock.unlock() }
        try prepareLocked()
    }

    private func prepareLocked() throws {
        if caKey != nil, caCertificate != nil, hostKey != nil { return }
        if let key = Self.findKey(tag: Self.caTag),
           let data = try? Data(contentsOf: caCertificateURL),
           let certificate = SecCertificateCreateWithData(nil, data as CFData),
           let certKey = SecCertificateCopyKey(certificate), let keyPublic = SecKeyCopyPublicKey(key),
           SecKeyCopyExternalRepresentation(certKey, nil) as Data? == SecKeyCopyExternalRepresentation(keyPublic, nil) as Data? {
            caKey = key
            caCertificate = certificate
        } else {
            try generateCALocked()
        }
        if let key = Self.findKey(tag: Self.hostTag) {
            hostKey = key
        } else {
            hostKey = try CertificateBuilder.newRSAKey(permanentTag: Self.hostTag)
        }
    }

    private func generateCALocked() throws {
        Self.deleteKey(tag: Self.caTag)
        let key = try CertificateBuilder.newRSAKey(permanentTag: Self.caTag)
        guard let publicKey = SecKeyCopyPublicKey(key) else { throw CertificateError.signing("no CA public key") }
        let host = ProcessInfo.processInfo.hostName
        let name = DER.name(commonName: "WebScarab Custom CA for \(host) at \(Date().formatted(date: .abbreviated, time: .shortened))",
                            organizationalUnit: "OWASP Custom CA")
        let der = try CertificateBuilder.certificate(subject: name, issuer: name, subjectKey: key, issuerKey: key, issuerPublicKey: publicKey,
                                                     isCA: true, hostName: nil, validDays: 3650)
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { throw CertificateError.invalidCertificate }
        try der.write(to: caCertificateURL, options: .atomic)
        caKey = key
        caCertificate = certificate
        identities.removeAll()
    }

    /// The CA certificate's SHA-256 fingerprint, as Keychain Access shows it.
    public var fingerprint: String? {
        guard let data = caCertificateData else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    private var currentCertificate: SecCertificate? {
        lock.lock(); defer { lock.unlock() }
        return caCertificate
    }

    /// Whether this Mac's user trust settings already trust the CA.
    public var isTrusted: Bool {
        guard let certificate = currentCertificate else { return false }
        var settings: CFArray?
        return SecTrustSettingsCopyTrustSettings(certificate, .user, &settings) == errSecSuccess
    }

    /// Adds the CA to the login keychain and marks it trusted for this user.
    /// macOS asks for the person's password before it changes trust settings.
    public func trust() throws {
        guard let certificate = currentCertificate else { throw CertificateError.invalidCertificate }
        let add: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecValueRef as String: certificate]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw CertificateError.keychain(addStatus, "adding the certificate to the keychain")
        }
        let status = SecTrustSettingsSetTrustSettings(certificate, .user, nil)
        guard status == errSecSuccess else { throw CertificateError.keychain(status, "trusting the certificate") }
    }

    /// Removes the trust setting and the keychain copy of the CA certificate.
    public func untrust() throws {
        guard let certificate = currentCertificate else { return }
        let status = SecTrustSettingsRemoveTrustSettings(certificate, .user)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw CertificateError.keychain(status, "removing trust") }
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecValueRef as String: certificate]
        SecItemDelete(query as CFDictionary)
    }

    /// Throws away the CA and makes a new one (Tools > Certificates > New CA).
    public func regenerate() throws {
        lock.lock(); defer { lock.unlock() }
        caKey = nil
        caCertificate = nil
        try generateCALocked()
        if hostKey == nil { try prepareLocked() }
    }

    /// The certificate chain the proxy shows the browser for this host.
    public func identity(for host: String) throws -> (SecIdentity, [SecCertificate]) {
        lock.lock(); defer { lock.unlock() }
        try prepareLocked()
        guard let caKey, let caCertificate, let hostKey, let caPublic = SecKeyCopyPublicKey(caKey) else { throw CertificateError.invalidCertificate }
        if let identity = identities[host] { return (identity, [caCertificate]) }
        let caDER = Array(SecCertificateCopyData(caCertificate) as Data)
        let issuerName = DER.subject(ofCertificate: caDER) ?? DER.name(commonName: "WebScarab CA")
        let der = try CertificateBuilder.certificate(subject: DER.name(commonName: host), issuer: issuerName, subjectKey: hostKey,
                                                     issuerKey: caKey, issuerPublicKey: caPublic, isCA: false, hostName: host, validDays: 365)
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { throw CertificateError.invalidCertificate }
        var identity: SecIdentity?
        let status = SecIdentityCreateWithCertificate(nil, certificate, &identity)
        guard status == errSecSuccess, let identity else { throw CertificateError.keychain(status, "pairing the host certificate with its key") }
        identities[host] = identity
        return (identity, [caCertificate])
    }
}
