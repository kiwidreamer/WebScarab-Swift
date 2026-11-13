// WebScarab (Swift) - the intercepting proxy (plugin.proxy.Proxy, Listener, ConnectionHandler)
// and its built-in proxy plugins: Manual Edit (intercept), Reveal hidden fields,
// Browser cache and Cookie tracker.

import Foundation
import Network
import Security

/// What the proxy plugins should do, read once per request.
public struct ProxyOptions: Sendable {
    var interceptRequests = false
    var interceptResponses = false
    var interceptMethods: [String] = ["GET", "POST"]
    var includeRegex = ".*"
    var excludeRegex = ""
    var responseContentRegex = "text/.*"
    var caseSensitive = false
    var revealHidden = false
    var disableBrowserCache = false
    var injectCookies = false
    var interceptHTTPS = true
    var cookies: [Cookie] = []

    func shouldIntercept(_ request: HTTPRequest) -> Bool {
        guard interceptRequests, interceptMethods.contains(where: { $0.caseInsensitiveCompare(request.method) == .orderedSame }) else { return false }
        let url = request.url.absoluteString
        if !includeRegex.isEmpty && !url.matches(regex: includeRegex, caseSensitive: caseSensitive) { return false }
        if !excludeRegex.isEmpty && url.matches(regex: excludeRegex, caseSensitive: caseSensitive) { return false }
        return true
    }

    func shouldIntercept(_ response: HTTPResponse, for request: HTTPRequest) -> Bool {
        guard interceptResponses else { return false }
        let url = request.url.absoluteString
        if !includeRegex.isEmpty && !url.matches(regex: includeRegex, caseSensitive: caseSensitive) { return false }
        if responseContentRegex.isEmpty { return true }
        return (response.contentType ?? "").matches(regex: responseContentRegex + ".*", caseSensitive: false)
    }
}

/// A message waiting in the Manual Edit window.
public final class InterceptItem: Identifiable, ObservableObject {
    public enum Kind { case request, response }
    public let id = UUID()
    public let kind: Kind
    public let title: String
    public let originalText: String
    @Published public var text: String
    let request: HTTPRequest?
    let response: HTTPResponse?
    private var finish: ((InterceptDecision) -> Void)?

    init(request: HTTPRequest, finish: @escaping (InterceptDecision) -> Void) {
        kind = .request
        title = "Edit Request: \(request.method) \(request.url.absoluteString)"
        originalText = request.rawText
        text = originalText
        self.request = request
        response = nil
        self.finish = finish
    }

    init(response: HTTPResponse, for request: HTTPRequest, finish: @escaping (InterceptDecision) -> Void) {
        kind = .response
        title = "Edit Response: \(response.statusLine) for \(request.url.absoluteString)"
        var shown = response
        if shown.header("Content-Encoding") != nil {
            // decode so the body can be edited as text
            shown.body = shown.decodedBody
            shown.removeHeader("Content-Encoding")
            shown.setHeader("Content-Length", String(shown.body.count))
        }
        originalText = shown.rawText
        text = originalText
        self.request = request
        self.response = shown
        self.finish = finish
    }

    func complete(_ decision: InterceptDecision) {
        finish?(decision)
        finish = nil
    }
}

public enum InterceptDecision {
    case original
    case edited(String)
    case abort
}

@MainActor
public final class ProxyController: ObservableObject {
    public static let shared = ProxyController()
    let defaults = UserDefaults.standard

    @Published public var listeners: [ListenerSpec] = Settings.listeners { didSet { Settings.listeners = listeners } }
    @Published public private(set) var listenerStatus: [String: String] = [:]
    @Published public var interceptRequests = false
    @Published public var interceptResponses = false
    @Published public var interceptMethods: String { didSet { defaults.set(interceptMethods, forKey: "ManualEdit.interceptMethods") } }
    @Published public var includeRegex: String { didSet { defaults.set(includeRegex, forKey: "ManualEdit.includeRegex") } }
    @Published public var excludeRegex: String { didSet { defaults.set(excludeRegex, forKey: "ManualEdit.excludeRegex") } }
    @Published public var responseContentRegex: String { didSet { defaults.set(responseContentRegex, forKey: "ManualEdit.interceptResponseRegex") } }
    @Published public var caseSensitive = false
    @Published public var revealHidden = false
    @Published public var disableBrowserCache = false
    @Published public var injectCookies = false
    @Published public var interceptHTTPS = true
    @Published public private(set) var pending: [InterceptItem] = []
    @Published public private(set) var handledCount = 0

    private var servers: [String: ProxyListener] = [:]

    init() {
        interceptMethods = defaults.string(forKey: "ManualEdit.interceptMethods") ?? "GET, POST"
        includeRegex = defaults.string(forKey: "ManualEdit.includeRegex") ?? ".*"
        excludeRegex = defaults.string(forKey: "ManualEdit.excludeRegex") ?? ".*\\.(gif|jpg|png|css|js|ico|swf|axd.*)$"
        responseContentRegex = defaults.string(forKey: "ManualEdit.interceptResponseRegex") ?? "text/.*"
    }

    var options: ProxyOptions {
        var options = ProxyOptions()
        options.interceptRequests = interceptRequests
        options.interceptResponses = interceptResponses
        options.interceptMethods = interceptMethods.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        options.includeRegex = includeRegex
        options.excludeRegex = excludeRegex
        options.responseContentRegex = responseContentRegex
        options.caseSensitive = caseSensitive
        options.revealHidden = revealHidden
        options.disableBrowserCache = disableBrowserCache
        options.injectCookies = injectCookies
        options.interceptHTTPS = interceptHTTPS
        if injectCookies { options.cookies = Framework.shared.currentCookies }
        return options
    }

    // MARK: listeners

    public func startAll() {
        for spec in listeners where servers[spec.id] == nil { start(spec) }
    }

    public func start(_ spec: ListenerSpec) {
        guard servers[spec.id] == nil else { return }
        let server = ProxyListener(spec: spec)
        servers[spec.id] = server
        listenerStatus[spec.id] = "Starting"
        server.start { [weak self] status in
            Task { @MainActor in
                self?.listenerStatus[spec.id] = status
                if status.hasPrefix("Failed") { self?.servers[spec.id] = nil }
            }
        }
    }

    public func stop(_ spec: ListenerSpec) {
        servers[spec.id]?.stop()
        servers[spec.id] = nil
        listenerStatus[spec.id] = "Stopped"
    }

    public func isRunning(_ spec: ListenerSpec) -> Bool { servers[spec.id] != nil }

    public func addListener(_ spec: ListenerSpec) {
        guard !listeners.contains(where: { $0.id == spec.id }) else { return }
        listeners.append(spec)
        start(spec)
    }

    public func removeListener(_ spec: ListenerSpec) {
        stop(spec)
        listeners.removeAll { $0.id == spec.id }
        listenerStatus[spec.id] = nil
    }

    func counted() { handledCount += 1 }

    // MARK: Manual Edit

    func intercept(request: HTTPRequest) async -> HTTPRequest? {
        let decision: InterceptDecision = await withCheckedContinuation { continuation in
            let item = InterceptItem(request: request) { continuation.resume(returning: $0) }
            pending.append(item)
        }
        switch decision {
        case .original: return request
        case .abort: return nil
        case .edited(let text):
            do { return try HTTPParser.request(fromText: text, base: request.url) }
            catch {
                Framework.shared.log(.warning, "Manual Edit", "Edited request could not be read (\(error)); sending the original")
                return request
            }
        }
    }

    func intercept(response: HTTPResponse, for request: HTTPRequest) async -> HTTPResponse? {
        var item: InterceptItem?
        let decision: InterceptDecision = await withCheckedContinuation { continuation in
            let newItem = InterceptItem(response: response, for: request) { continuation.resume(returning: $0) }
            item = newItem
            pending.append(newItem)
        }
        switch decision {
        case .original: return response
        case .abort: return nil
        case .edited(let text):
            do { return try HTTPParser.response(fromText: text) }
            catch {
                Framework.shared.log(.warning, "Manual Edit", "Edited response could not be read (\(error)); sending the original")
                return item?.response ?? response
            }
        }
    }

    public func resolve(_ item: InterceptItem, _ decision: InterceptDecision) {
        pending.removeAll { $0.id == item.id }
        item.complete(decision)
    }

    /// Lets everything waiting go through unchanged and stops intercepting.
    public func releaseAll() {
        interceptRequests = false
        interceptResponses = false
        let items = pending
        pending.removeAll()
        for item in items { item.complete(.original) }
    }
}

/// Built-in proxy plugins that change messages in flight.
enum ProxyPlugins {
    static func request(_ request: HTTPRequest, _ options: ProxyOptions) -> HTTPRequest {
        var request = request
        if options.disableBrowserCache {
            request.removeHeader("ETag")
            request.removeHeader("If-Modified-Since")
            request.removeHeader("If-None-Match")
        }
        if options.injectCookies {
            let known = options.cookies.filter { $0.applies(to: request.url) }
            if !known.isEmpty {
                var pairs = request.headerValues("Cookie").flatMap { NamedValue.split($0, ";", "=") }
                for cookie in known {
                    if let index = pairs.firstIndex(where: { $0.name == cookie.name }) { pairs[index].value = cookie.value }
                    else { pairs.append(NamedValue(name: cookie.name, value: cookie.value)) }
                }
                request.setHeader("Cookie", pairs.map { "\($0.name)=\($0.value)" }.joined(separator: "; "))
            }
        }
        return request
    }

    static func response(_ response: HTTPResponse, _ options: ProxyOptions) -> HTTPResponse {
        var response = response
        if options.disableBrowserCache {
            response.setHeader("Cache-Control", "no-cache, no-store")
            response.setHeader("Pragma", "no-cache")
            response.setHeader("Expires", "0")
        }
        if options.revealHidden, (response.contentType ?? "").lowercased().contains("html") {
            response = revealHiddenFields(response)
        }
        return response
    }

    static let hiddenInput = try! NSRegularExpression(pattern: "(<input.+?type\\s*=\\s*[\"']{0,1})hidden([\"']{0,1}.+?>)", options: [.caseInsensitive])
    static let nameAttribute = try! NSRegularExpression(pattern: "name=[\"']{0,1}(\\w+)[\"']{0,1}", options: [.caseInsensitive])

    /// plugin.proxy.RevealHidden: hidden fields become visible text fields, labelled with their names.
    static func revealHiddenFields(_ response: HTTPResponse) -> HTTPResponse {
        var response = response
        let text = response.bodyText as NSString
        var output = ""
        var last = 0
        for match in hiddenInput.matches(in: text as String, range: NSRange(location: 0, length: text.length)) {
            output += text.substring(with: NSRange(location: last, length: match.range.location - last))
            let input = text.substring(with: match.range)
            var name = "noname"
            if let nameMatch = nameAttribute.firstMatch(in: input, range: NSRange(location: 0, length: (input as NSString).length)) {
                name = (input as NSString).substring(with: nameMatch.range(at: 1))
            }
            let visible = text.substring(with: match.range(at: 1)) + "text" + text.substring(with: match.range(at: 2))
            output += "<div style=\"background: yellow; color: black\">Hidden field [\(HtmlEncoder.encode(name))]: \(visible)</div>"
            last = match.range.location + match.range.length
        }
        guard last > 0 else { return response }
        output += text.substring(from: last)
        response.removeHeader("Content-Encoding")
        response.body = Data(output.utf8)
        response.setHeader("Content-Length", String(response.body.count))
        return response
    }
}

/// One listening socket.
final class ProxyListener: @unchecked Sendable {
    let spec: ListenerSpec
    private var listener: NWListener?

    init(spec: ListenerSpec) { self.spec = spec }

    func start(status: @escaping @Sendable (String) -> Void) {
        do {
            guard let port = NWEndpoint.Port(rawValue: UInt16(clamping: spec.port)) else { throw HTTPError.malformed("port") }
            let parameters = NWParameters.tcp
            parameters.allowLocalEndpointReuse = true
            if !spec.address.isEmpty && spec.address != "*" && spec.address != "0.0.0.0" {
                parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(spec.address), port: port)
            }
            let listener = parameters.requiredLocalEndpoint == nil ? try NWListener(using: parameters, on: port) : try NWListener(using: parameters)
            let base = spec.baseURL
            listener.newConnectionHandler = { connection in
                Task.detached { await ProxyConnection.serve(NetConnection(connection), base: base) }
            }
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: status("Listening")
                case .failed(let error): status("Failed: \(error.localizedDescription)")
                case .cancelled: status("Stopped")
                default: break
                }
            }
            listener.start(queue: NetConnection.queue)
            self.listener = listener
            webscarabLog(.info, "Proxy", "Listening on \(spec.address):\(spec.port)" + (base.map { " for \($0.absoluteString)" } ?? ""))
        } catch {
            status("Failed: \(error)")
            webscarabLog(.severe, "Proxy", "Could not listen on \(spec.address):\(spec.port): \(error)")
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }
}

/// Local TLS listeners that terminate intercepted HTTPS, one per host:port.
actor InterceptListeners {
    static let shared = InterceptListeners()
    private var ports: [String: (NWListener, Int)] = [:]

    func port(host: String, port remotePort: Int) async throws -> Int {
        let key = "\(host):\(remotePort)"
        if let existing = ports[key] { return existing.1 }
        let (identity, chain) = try CertificateAuthority.shared.identity(for: host)
        guard let secIdentity = sec_identity_create_with_certificates(identity, chain as CFArray) else {
            throw CertificateError.invalidCertificate
        }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, secIdentity)
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let base = URL(string: "https://\(host.contains(":") ? "[\(host)]" : host):\(remotePort)")
        listener.newConnectionHandler = { connection in
            Task.detached {
                let client = NetConnection(connection)
                do {
                    try await client.start()
                } catch {
                    webscarabLog(.warning, "Proxy", "The browser refused the WebScarab certificate for \(host) (\(error)). Trust the WebScarab CA under Tools > Certificates.")
                    client.close()
                    return
                }
                await ProxyConnection.serveReady(client, base: base)
            }
        }
        let once = OnceFlag()
        let localPort: Int = try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { [listener] state in
                switch state {
                case .ready:
                    if once.claim() { continuation.resume(returning: Int(listener.port?.rawValue ?? 0)) }
                case .failed(let error):
                    if once.claim() { continuation.resume(throwing: error) }
                case .cancelled:
                    if once.claim() { continuation.resume(throwing: HTTPError.closed) }
                default: break
                }
            }
            listener.start(queue: NetConnection.queue)
        }
        ports[key] = (listener, localPort)
        return localPort
    }

    func reset() {
        for (listener, _) in ports.values { listener.cancel() }
        ports.removeAll()
    }
}

/// Handles one browser connection (plugin.proxy.ConnectionHandler).
enum ProxyConnection {
    static func serve(_ client: NetConnection, base: URL?) async {
        do { try await client.start() } catch { client.close(); return }
        await serveReady(client, base: base)
    }

    static func serveReady(_ client: NetConnection, base: URL?) async {
        let reader = client.makeReader()
        defer { client.close() }
        while true {
            let request: HTTPRequest
            do {
                guard let next = try await HTTPReader.readRequest(reader, base: base) else { return }
                request = next
            } catch {
                webscarabLog(.fine, "Proxy", "Error reading the request from the browser: \(error)")
                return
            }
            if request.method == "CONNECT" {
                await tunnel(client, reader: reader, request: request)
                return
            }
            guard await handle(request, client: client) else { return }
        }
    }

    static func tunnel(_ client: NetConnection, reader: ByteReader, request: HTTPRequest) async {
        guard let host = request.url.host(percentEncoded: false) else { return }
        let port = request.url.effectivePort
        do { try await client.send(Data("HTTP/1.0 200 Ok\r\n\r\n".utf8)) } catch { return }
        let leftover = reader.takeBuffered()
        let options = await MainActor.run { ProxyController.shared.options }
        if options.interceptHTTPS {
            do {
                let localPort = try await InterceptListeners.shared.port(host: host, port: port)
                let inner = try await NetConnection.open(host: "127.0.0.1", port: localPort, tls: false)
                await Relay.pipe(client, inner, initialToB: leftover)
                return
            } catch {
                webscarabLog(.warning, "Proxy", "HTTPS interception for \(host) is not available (\(error)); passing it through unrecorded")
            }
        }
        do {
            let remote = try await NetConnection.open(host: host, port: port, tls: false, upstream: Settings.upstreamProxy.proxy(for: request.url))
            await Relay.pipe(client, remote, initialToB: leftover)
        } catch {
            webscarabLog(.warning, "Proxy", "Could not reach \(host):\(port): \(error)")
        }
    }

    /// One request/response; returns whether the connection may carry another.
    static func handle(_ incoming: HTTPRequest, client: NetConnection) async -> Bool {
        var request = incoming
        HTTPReader.normalizeLength(&request)
        let options = await MainActor.run { ProxyController.shared.options }
        let id = await MainActor.run { Framework.shared.reserveID() }
        request = ProxyPlugins.request(request, options)

        if options.shouldIntercept(request) {
            guard let edited = await ProxyController.shared.intercept(request: request) else {
                webscarabLog(.info, "Manual Edit", "Request aborted: \(request.url.absoluteString)")
                return false
            }
            request = edited
        }

        var response: HTTPResponse
        var record = true
        do {
            response = try await HTTPClient.fetch(request)
        } catch {
            webscarabLog(.severe, "Proxy", "Error retrieving \(request.url.absoluteString): \(error)")
            response = HTTPResponse.error(for: request, error)
            record = false
        }
        response = ProxyPlugins.response(response, options)

        if record && options.shouldIntercept(response, for: request) {
            guard let edited = await ProxyController.shared.intercept(response: response, for: request) else {
                webscarabLog(.info, "Manual Edit", "Response aborted: \(request.url.absoluteString)")
                return false
            }
            response = edited
        }

        do { try await client.send(response.serialized()) } catch { return false }
        let recorded = request, received = response, shouldRecord = record
        await MainActor.run {
            ProxyController.shared.counted()
            if shouldRecord { Framework.shared.addConversation(request: recorded, response: received, origin: "Proxy", id: id) }
        }
        return keepAlive(request: request, response: response)
    }

    static func keepAlive(request: HTTPRequest, response: HTTPResponse) -> Bool {
        let responseConnection = response.header("Connection")?.lowercased() ?? ""
        let requestConnection = (request.header("Connection") ?? request.header("Proxy-Connection") ?? "").lowercased()
        if responseConnection.contains("close") || requestConnection.contains("close") { return false }
        if response.version == "HTTP/1.0" { return responseConnection.contains("keep-alive") }
        return true
    }
}
