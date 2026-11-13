// WebScarab (Swift) - async wrapper around Network.framework connections.

import Foundation
import Network
import Security

/// Upstream proxy settings (Tools > Proxies in WebScarab).
public struct UpstreamProxySettings: Codable, Equatable, Sendable {
    public var httpHost = ""
    public var httpPort = 3128
    public var httpsHost = ""
    public var httpsPort = 3128
    public var noProxy = "localhost, 127.0.0.1"

    public init() {}

    func proxy(for url: URL) -> (String, Int)? {
        let host = (url.host(percentEncoded: false) ?? "").lowercased()
        let exempt = noProxy.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        if exempt.contains(where: { !$0.isEmpty && (host == $0 || host.hasSuffix($0.hasPrefix(".") ? $0 : "." + $0)) }) { return nil }
        if url.scheme?.lowercased() == "https" {
            return httpsHost.isEmpty ? nil : (httpsHost, httpsPort)
        }
        return httpHost.isEmpty ? nil : (httpHost, httpPort)
    }
}

final class OnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}

public final class NetConnection: @unchecked Sendable {
    public let connection: NWConnection
    static let queue = DispatchQueue(label: "webscarab.net", attributes: .concurrent)

    public init(_ connection: NWConnection) { self.connection = connection }

    /// TLS client options that accept any server certificate, as WebScarab's own client does,
    /// so that the traffic of sites with broken certificates can still be studied.
    static func clientTLS(serverName: String) -> NWProtocolTLS.Options {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_verify_block(options, { _, _, complete in complete(true) }, queue)
        sec_protocol_options_set_tls_server_name(options, serverName)
        sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
        return tls
    }

    public static func open(host: String, port: Int, tls: Bool, upstream: (String, Int)? = nil, timeout: Int = 20) async throws -> NetConnection {
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = timeout
        tcp.noDelay = true
        let parameters = NWParameters(tls: tls ? clientTLS(serverName: host) : nil, tcp: tcp)
        if let (proxyHost, proxyPort) = upstream, let endpointPort = NWEndpoint.Port(rawValue: UInt16(clamping: proxyPort)) {
            let context = NWParameters.PrivacyContext(description: "WebScarab upstream proxy")
            context.proxyConfigurations = [ProxyConfiguration(httpCONNECTProxy: .hostPort(host: NWEndpoint.Host(proxyHost), port: endpointPort))]
            parameters.setPrivacyContext(context)
        }
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { throw HTTPError.malformed("port \(port)") }
        let connection = NetConnection(NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters))
        try await connection.start(timeout: timeout)
        return connection
    }

    public func start(timeout: Int = 20) async throws {
        let once = OnceFlag()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [connection] state in
                switch state {
                case .ready:
                    if once.claim() { continuation.resume() }
                case .failed(let error):
                    if once.claim() { continuation.resume(throwing: error) }
                case .waiting(let error):
                    if once.claim() { connection.cancel(); continuation.resume(throwing: error) }
                case .cancelled:
                    if once.claim() { continuation.resume(throwing: HTTPError.closed) }
                default: break
                }
            }
            connection.start(queue: Self.queue)
            Self.queue.asyncAfter(deadline: .now() + .seconds(timeout + 5)) { [connection] in
                if once.claim() { connection.cancel(); continuation.resume(throwing: HTTPError.timeout) }
            }
        }
    }

    /// Next chunk of bytes, or nil at the end of the stream.
    public func receive() async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 256 * 1024) { data, _, isComplete, error in
                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if let error {
                    if isComplete { continuation.resume(returning: nil) } else { continuation.resume(throwing: error) }
                } else if isComplete {
                    continuation.resume(returning: nil)
                } else {
                    continuation.resume(returning: Data())
                }
            }
        }
    }

    public func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    public func finishSending() {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
    }

    public func close() { connection.cancel() }

    public var remoteHost: String {
        if case .hostPort(let host, _) = connection.endpoint { return "\(host)" }
        return "unknown"
    }

    public func makeReader() -> ByteReader {
        ByteReader { [self] in
            // Empty chunks are not the end of the stream; keep asking.
            while true {
                guard let data = try await self.receive() else { return nil }
                if !data.isEmpty { return data }
            }
        }
    }
}

/// Copies bytes both ways between two connections until either side closes.
public enum Relay {
    public static func pipe(_ a: NetConnection, _ b: NetConnection, initialToB: Data = Data()) async {
        if !initialToB.isEmpty { try? await b.send(initialToB) }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await copy(from: a, to: b) }
            group.addTask { await copy(from: b, to: a) }
            await group.next()
            a.close()
            b.close()
        }
    }

    static func copy(from: NetConnection, to: NetConnection) async {
        while true {
            guard let data = try? await from.receive() else { break }
            if data.isEmpty { continue }
            do { try await to.send(data) } catch { break }
        }
        to.finishSending()
    }
}
