// WebScarab (Swift) - fetches a request from its server (httpclient.URLFetcher).

import Foundation

public enum HTTPClient {
    /// Sends the request exactly as given and reads the response.
    public static func fetch(_ request: HTTPRequest, upstream: UpstreamProxySettings = Settings.upstreamProxy, timeout: Int = 30) async throws -> HTTPResponse {
        guard let host = request.url.host(percentEncoded: false), !host.isEmpty else { throw HTTPError.malformed("no host in \(request.url)") }
        let tls = request.url.scheme?.lowercased() == "https"
        let connection = try await NetConnection.open(host: host, port: request.url.effectivePort, tls: tls,
                                                      upstream: upstream.proxy(for: request.url), timeout: timeout)
        defer { connection.close() }
        try await connection.send(request.serializedDirect())
        let reader = connection.makeReader()
        var response = try await withTimeout(seconds: timeout * 4) {
            try await HTTPReader.readResponse(reader, requestMethod: request.method)
        }
        HTTPReader.normalizeLength(&response)
        return response
    }

    static func withTimeout<T: Sendable>(seconds: Int, _ work: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await work() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
                throw HTTPError.timeout
            }
            guard let result = try await group.next() else { throw HTTPError.timeout }
            group.cancelAll()
            return result
        }
    }
}

/// Runs requests a few at a time (httpclient.FetcherQueue), used by the Spider, Fuzzer and others.
public actor FetcherQueue {
    private let width: Int
    private let delay: UInt64
    private var running = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init(threads: Int = 4, delayMilliseconds: Int = 0) {
        width = max(1, threads)
        delay = UInt64(max(0, delayMilliseconds)) * 1_000_000
    }

    private func acquire() async {
        if running < width { running += 1; return }
        await withCheckedContinuation { waiters.append($0) }
    }

    private func release() {
        if waiters.isEmpty { running -= 1 } else { waiters.removeFirst().resume() }
    }

    public func fetch(_ request: HTTPRequest) async -> Result<HTTPResponse, Error> {
        await acquire()
        if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
        let result: Result<HTTPResponse, Error>
        do { result = .success(try await HTTPClient.fetch(request)) } catch { result = .failure(error) }
        release()
        return result
    }
}
