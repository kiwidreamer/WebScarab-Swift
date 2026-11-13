// WebScarab (Swift) - plugin.fuzz: replays a request with parameter values taken from fuzz sources.

import Foundation

public struct FuzzParameter: Identifiable, Hashable {
    public static let locations = ["Path", "Fragment", "Query", "Cookie", "Body"]
    public var id = UUID()
    public var location = "Query"
    public var name = ""
    public var type = "String"
    public var value = ""
    public var source = ""     // fuzz source name, or "" for the fixed value
    public var priority = 0
}

public struct FuzzSource: Identifiable, Hashable {
    public var id: String { name }
    public var name: String
    public var items: [String]
}

/// util.RegexExpansion: every string a simple pattern can produce.
/// Supports literals, escapes, [a-z0-9] classes, ( | ) groups and {n} / {n,m} / ? quantifiers.
public enum RegexExpansion {
    public static func expand(_ pattern: String, limit: Int = 100_000) throws -> [String] {
        var index = pattern.startIndex
        let result = try parseSequence(pattern, &index, limit: limit)
        if index != pattern.endIndex { throw HTTPError.malformed("unexpected '\(pattern[index])' in pattern") }
        return result
    }

    static func parseSequence(_ p: String, _ i: inout String.Index, limit: Int) throws -> [String] {
        var alternatives: [[String]] = []
        var current: [String] = [""]
        while i < p.endIndex {
            let c = p[i]
            if c == ")" { break }
            if c == "|" {
                alternatives.append(current)
                current = [""]
                i = p.index(after: i)
                continue
            }
            var atom: [String]
            if c == "(" {
                i = p.index(after: i)
                atom = try parseSequence(p, &i, limit: limit)
                guard i < p.endIndex, p[i] == ")" else { throw HTTPError.malformed("missing )") }
                i = p.index(after: i)
            } else if c == "[" {
                atom = try parseClass(p, &i)
            } else if c == "\\" {
                i = p.index(after: i)
                guard i < p.endIndex else { throw HTTPError.malformed("trailing \\") }
                atom = escape(p[i])
                i = p.index(after: i)
            } else {
                atom = [String(c)]
                i = p.index(after: i)
            }
            atom = try quantify(atom, p, &i, limit: limit)
            var next: [String] = []
            for prefix in current {
                for suffix in atom {
                    next.append(prefix + suffix)
                    if next.count > limit { throw HTTPError.tooLarge }
                }
            }
            current = next
        }
        alternatives.append(current)
        return alternatives.flatMap { $0 }
    }

    static func escape(_ c: Character) -> [String] {
        switch c {
        case "d": return (0...9).map(String.init)
        case "w": return chars("a-zA-Z0-9_")
        case "s": return [" "]
        default: return [String(c)]
        }
    }

    static func chars(_ spec: String) -> [String] {
        var result: [String] = []
        let scalars = Array(spec.unicodeScalars)
        var k = 0
        while k < scalars.count {
            if k + 2 < scalars.count, scalars[k + 1] == "-" {
                for v in scalars[k].value...max(scalars[k].value, scalars[k + 2].value) { if let s = Unicode.Scalar(v) { result.append(String(Character(s))) } }
                k += 3
            } else {
                result.append(String(Character(scalars[k])))
                k += 1
            }
        }
        var seen = Set<String>()
        return result.filter { seen.insert($0).inserted }
    }

    static func parseClass(_ p: String, _ i: inout String.Index) throws -> [String] {
        i = p.index(after: i)
        var spec = ""
        while i < p.endIndex, p[i] != "]" {
            if p[i] == "\\" { i = p.index(after: i); guard i < p.endIndex else { break } }
            spec.append(p[i])
            i = p.index(after: i)
        }
        guard i < p.endIndex else { throw HTTPError.malformed("missing ]") }
        i = p.index(after: i)
        return chars(spec)
    }

    static func quantify(_ atom: [String], _ p: String, _ i: inout String.Index, limit: Int) throws -> [String] {
        guard i < p.endIndex else { return atom }
        var minimum = 1, maximum = 1
        if p[i] == "?" {
            minimum = 0; maximum = 1
            i = p.index(after: i)
        } else if p[i] == "{" {
            guard let close = p[i...].firstIndex(of: "}") else { throw HTTPError.malformed("missing }") }
            let inside = p[p.index(after: i)..<close]
            let numbers = inside.split(separator: ",", omittingEmptySubsequences: false).map { Int($0.trimmingCharacters(in: .whitespaces)) }
            guard let first = numbers.first ?? nil else { throw HTTPError.malformed("bad {n,m}") }
            minimum = first
            maximum = numbers.count > 1 ? (numbers[1] ?? first) : first
            i = p.index(after: close)
        } else {
            return atom
        }
        var result: [String] = []
        var layer = [""]
        for count in 0...max(minimum, maximum) {
            if count >= minimum { result += layer }
            if count == maximum { break }
            var next: [String] = []
            for prefix in layer { for item in atom { next.append(prefix + item); if next.count + result.count > limit { throw HTTPError.tooLarge } } }
            layer = next
        }
        return result
    }
}

@MainActor
public final class Fuzzer: ObservableObject {
    @Published public var method = "GET"
    @Published public var url = ""
    @Published public var version = "HTTP/1.1"
    @Published public var headers: [Header] = []
    @Published public var parameters: [FuzzParameter] = []
    @Published public var sources: [FuzzSource] = Fuzzer.builtInSources
    @Published public private(set) var results: [Int] = []
    @Published public private(set) var status = "Idle"
    @Published public private(set) var requestIndex = 0
    @Published public private(set) var totalRequests = 0
    private var busy = false
    private let fetcher = FetcherQueue(threads: 4)

    static let builtInSources: [FuzzSource] = [
        FuzzSource(name: "XSS probes", items: ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>"]),
        FuzzSource(name: "SQL injection probes", items: ["'", "\"", "' OR '1'='1", "1 OR 1=1", "'; --", "\") OR (\"1\"=\"1", "1' AND SLEEP(5)--"]),
        FuzzSource(name: "Path traversal", items: ["../", "../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd", "%00"]),
        FuzzSource(name: "Numbers", items: ["0", "-1", "1", "65535", "2147483647", "2147483648", "-2147483649", "99999999999999999999"]),
        FuzzSource(name: "Long strings", items: [String(repeating: "A", count: 256), String(repeating: "A", count: 1024), String(repeating: "A", count: 8192)]),
    ]

    public var isBusy: Bool { busy }

    /// Fills the fuzzer from a recorded request (the "Use as fuzz template" action).
    public func load(from request: HTTPRequest) {
        method = request.method
        version = request.version
        var components = URLComponents(url: request.url, resolvingAgainstBaseURL: false)
        components?.query = nil
        components?.fragment = nil
        url = components?.url?.absoluteString ?? request.url.absoluteString
        headers = request.headers.filter { !["cookie", "content-length"].contains($0.name.lowercased()) }
        parameters = request.parameters.map { FuzzParameter(location: $0.location, name: $0.name, value: $0.value) }
        results = []
    }

    public func addSource(name: String, items: [String]) {
        sources.removeAll { $0.name == name }
        sources.append(FuzzSource(name: name, items: items))
    }

    public func addSource(fromFile file: URL) throws {
        let text = try String(contentsOf: file, encoding: .utf8)
        addSource(name: file.lastPathComponent, items: text.components(separatedBy: .newlines).filter { !$0.isEmpty })
    }

    public func addRegexSource(name: String, pattern: String) throws {
        addSource(name: name, items: try RegexExpansion.expand(pattern))
    }

    /// Every combination: parameters with the same priority advance together,
    /// a higher priority advances once each time the lower ones run out (FuzzerModel.incrementFuzzer).
    public func combinations() -> [[String]] {
        let fixed = parameters.map(\.value)
        let lists: [[String]?] = parameters.map { parameter in
            parameter.source.isEmpty ? nil : sources.first { $0.name == parameter.source }?.items
        }
        let priorities = Set(parameters.indices.filter { lists[$0] != nil }.map { parameters[$0].priority }).sorted()
        guard !priorities.isEmpty else { return [fixed] }
        // length of each priority level = the shortest source in it
        let lengths = priorities.map { priority in
            parameters.indices.filter { lists[$0] != nil && parameters[$0].priority == priority }.map { lists[$0]!.count }.min() ?? 0
        }
        if lengths.contains(0) { return [] }
        var counters = [Int](repeating: 0, count: priorities.count)
        var result: [[String]] = []
        while result.count < 100_000 {
            var values = fixed
            for index in parameters.indices {
                guard let list = lists[index], let level = priorities.firstIndex(of: parameters[index].priority) else { continue }
                values[index] = list[counters[level]]
            }
            result.append(values)
            var level = 0
            while level < counters.count {
                counters[level] += 1
                if counters[level] < lengths[level] { break }
                counters[level] = 0
                level += 1
            }
            if level == counters.count { break }
        }
        return result
    }

    /// Fuzzer.constructCurrentFuzzRequest
    public func makeRequest(values: [String]) throws -> HTTPRequest {
        var path: String?
        var fragment: String?
        var query: String?
        var cookie: String?
        var body: String?
        for (index, parameter) in parameters.enumerated() {
            let value = values[index]
            switch parameter.location {
            case "Path": path = path.map { $0 + "/" + value } ?? value
            case "Fragment":
                let item = parameter.name.isEmpty ? value : parameter.name + "=" + Encoding.urlEncode(value)
                fragment = fragment.map { $0 + "&" + item } ?? item
            case "Query":
                let item = parameter.name + "=" + Encoding.urlEncode(value)
                query = query.map { $0 + "&" + item } ?? item
            case "Cookie":
                let item = parameter.name + "=" + value
                cookie = cookie.map { $0 + "; " + item } ?? item
            default:
                let item = parameter.name + "=" + Encoding.urlEncode(value)
                body = body.map { $0 + "&" + item } ?? item
            }
        }
        var text = url
        if let path { text += (text.hasSuffix("/") ? "" : "/") + path }
        if let fragment { text += ";" + fragment }
        if let query { text += "?" + query }
        guard let target = URL(string: text) else { throw HTTPError.malformed("URL \(text)") }
        var request = HTTPRequest(method: method, url: target, version: version, headers: headers)
        if request.header("Host") == nil { request.setHeader("Host", target.port.map { "\(target.host(percentEncoded: false) ?? ""):\($0)" } ?? (target.host(percentEncoded: false) ?? "")) }
        if let cookie { request.addHeader("Cookie", cookie) }
        if let body {
            request.body = Data(body.utf8)
            if request.header("Content-Type") == nil { request.setHeader("Content-Type", "application/x-www-form-urlencoded") }
            request.setHeader("Content-Length", String(request.body.count))
        } else if method == "POST" {
            request.setHeader("Content-Length", "0")
        }
        return request
    }

    public func start() {
        guard !busy else { return }
        guard URL(string: url)?.host != nil else { status = "Enter a URL first"; return }
        let all = combinations()
        guard !all.isEmpty else { status = "A fuzz source is empty"; return }
        busy = true
        results = []
        requestIndex = 0
        totalRequests = all.count
        status = "Fuzzing"
        Task {
            for values in all {
                guard busy else { break }
                let request: HTTPRequest
                do { request = try makeRequest(values: values) } catch { status = "\(error)"; break }
                switch await fetcher.fetch(request) {
                case .success(let response):
                    if response.status == "400" { Framework.shared.log(.warning, "Fuzzer", "Bad request for \(request.url.absoluteString)") }
                    if let id = Framework.shared.addConversation(request: request, response: response, origin: "Fuzzer") { results.append(id) }
                case .failure(let error):
                    Framework.shared.log(.warning, "Fuzzer", "Caught exception: \(error)")
                    busy = false
                }
                requestIndex += 1
            }
            busy = false
            status = requestIndex == totalRequests ? "Finished" : "Stopped"
        }
    }

    public func stop() {
        busy = false
        status = "Stopped"
    }
}
