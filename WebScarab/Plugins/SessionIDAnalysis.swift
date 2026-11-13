// WebScarab (Swift) - plugin.sessionid: collects session identifiers and maps them to numbers
// so their predictability can be judged on a chart.

import Foundation

public struct SessionIDSample: Identifiable, Hashable {
    public let id = UUID()
    public var date: Date
    public var value: String
}

/// plugin.sessionid.DefaultCalculator: each position gets the sorted set of characters seen
/// there; a value becomes a number in that mixed radix (rightmost position least significant).
public struct SessionIDCalculator {
    public var pattern: String
    private var charsets: [[Character]] = []

    public init(pattern: String = "^(.+)$") { self.pattern = pattern }

    func extract(_ value: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return value }
        let ns = value as NSString
        guard let match = regex.firstMatch(in: value, range: NSRange(location: 0, length: ns.length)),
              match.range.location == 0, match.range.length == ns.length else { return nil }
        guard match.numberOfRanges > 1, match.range(at: 1).location != NSNotFound else { return value }
        return ns.substring(with: match.range(at: 1))
    }

    public mutating func add(_ value: String) {
        guard let text = extract(value) else { return }
        for (position, character) in text.reversed().enumerated() {
            while charsets.count <= position { charsets.append([]) }
            if !charsets[position].contains(character) {
                charsets[position].append(character)
                charsets[position].sort()
            }
        }
    }

    /// The value as a Double (the Java version used BigInteger; charts only need magnitude).
    public func calculate(_ value: String) -> Double {
        guard let text = extract(value) else { return 0 }
        var total = 0.0
        var radix = 1.0
        for (position, character) in text.reversed().enumerated() where position < charsets.count {
            let set = charsets[position]
            total += Double(set.firstIndex(of: character) ?? 0) * radix
            radix *= Double(max(set.count, 1))
        }
        return total
    }
}

@MainActor
public final class SessionIDAnalysis: ObservableObject {
    @Published public private(set) var samples: [String: [SessionIDSample]] = [:]
    @Published public var patterns: [String: String] = [:]
    @Published public private(set) var status = "Idle"
    @Published public var sampleCount = 10
    private var busy = false

    init(framework: Framework) {
        framework.addAnalyser("SessionID") { [weak self] conversation in
            for header in conversation.response.headerValues("Set-Cookie") + conversation.response.headerValues("Set-Cookie2") {
                if let cookie = Cookie(date: conversation.date, url: conversation.url, setCookie: header), !cookie.value.isEmpty {
                    self?.add(name: cookie.key, value: cookie.value, date: conversation.date)
                }
            }
        }
    }

    public var names: [String] { samples.keys.sorted() }

    func add(name: String, value: String, date: Date) {
        var list = samples[name] ?? []
        if list.last?.value == value { return }
        list.append(SessionIDSample(date: date, value: value))
        samples[name] = list
    }

    public func calculator(for name: String) -> SessionIDCalculator {
        var calculator = SessionIDCalculator(pattern: patterns[name] ?? "^(.+)$")
        for sample in samples[name] ?? [] { calculator.add(sample.value) }
        return calculator
    }

    public func clear(_ name: String) { samples[name] = nil }

    /// Where to find the identifier in each response: a cookie name, or a regex with one group over the whole response.
    public enum Location: Hashable {
        case cookie(String)
        case regex(String)
    }

    public static func find(_ location: Location, in response: HTTPResponse, url: URL) -> (String, String)? {
        switch location {
        case .cookie(let name):
            for header in response.headerValues("Set-Cookie") {
                if let cookie = Cookie(date: Date(), url: url, setCookie: header), name.isEmpty || cookie.name == name {
                    return (cookie.key, cookie.value)
                }
            }
            return nil
        case .regex(let pattern):
            let text = response.headerText + response.bodyText
            return text.firstMatch(regex: pattern).map { ("\(url.shpp) \(pattern)", $0) }
        }
    }

    /// Fetches the request `count` times, collecting an identifier each time.
    public func fetch(_ request: HTTPRequest, location: Location, count: Int) {
        guard !busy else { return }
        busy = true
        status = "Fetching 0 of \(count)"
        Task {
            for index in 0..<count {
                guard busy else { break }
                do {
                    let response = try await HTTPClient.fetch(request)
                    if let (name, value) = Self.find(location, in: response, url: request.url) {
                        add(name: name, value: value, date: Date())
                    } else {
                        Framework.shared.log(.info, "SessionID", "No session identifier in response \(index + 1)")
                    }
                } catch {
                    Framework.shared.log(.warning, "SessionID", "Fetch failed: \(error)")
                    break
                }
                status = "Fetching \(index + 1) of \(count)"
            }
            busy = false
            status = "Idle"
        }
    }

    /// The "Test" button: one fetch, to show what would be collected.
    public func test(_ request: HTTPRequest, location: Location) async -> String {
        do {
            let response = try await HTTPClient.fetch(request)
            if let (name, value) = Self.find(location, in: response, url: request.url) { return "\(name) = \(value)" }
            return "No session identifier found in the response (\(response.statusLine))"
        } catch {
            return "Error: \(error)"
        }
    }

    public func stop() { busy = false }
}

@MainActor
public final class ManualRequest: ObservableObject {
    @Published public var requestText = "GET http://localhost/ HTTP/1.1\nHost: localhost\n\n"
    @Published public private(set) var response: HTTPResponse?
    @Published public private(set) var lastRequest: HTTPRequest?
    @Published public private(set) var busy = false
    @Published public var error: String?

    public func load(_ request: HTTPRequest) {
        requestText = request.rawText
        response = nil
    }

    /// Adds the known cookies for the request's URL ("Get cookies").
    public func addCookies() {
        guard var request = try? HTTPParser.request(fromText: requestText) else { return }
        let cookies = Framework.shared.cookies(for: request.url)
        guard !cookies.isEmpty else { return }
        request.setHeader("Cookie", cookies.map { "\($0.name)=\($0.value)" }.joined(separator: "; "))
        requestText = request.rawText
    }

    public func fetch() {
        let request: HTTPRequest
        do { request = try HTTPParser.request(fromText: requestText) } catch { self.error = "\(error)"; return }
        busy = true
        error = nil
        Task {
            do {
                let response = try await HTTPClient.fetch(request)
                self.response = response
                self.lastRequest = request
                Framework.shared.addConversation(request: request, response: response, origin: "Manual Request")
            } catch {
                self.error = "\(error)"
            }
            busy = false
        }
    }
}
