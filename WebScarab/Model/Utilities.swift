// WebScarab (Swift) - small helpers ported from org.owasp.webscarab.util.

import Foundation
import CryptoKit

public struct NamedValue: Hashable, Sendable {
    public var name: String
    public var value: String

    /// NamedValue.splitNamedValues: "a=1&b=2" -> [(a,1),(b,2)].
    public static func split(_ text: String, _ separator: String, _ equals: String) -> [NamedValue] {
        text.components(separatedBy: separator).compactMap { part in
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }
            if let range = trimmed.range(of: equals) {
                return NamedValue(name: String(trimmed[..<range.lowerBound]), value: String(trimmed[range.upperBound...]))
            }
            return NamedValue(name: trimmed, value: "")
        }
    }
}

public enum Encoding {
    public static func urlEncode(_ text: String) -> String {
        // java.net.URLEncoder semantics: space -> '+', unreserved kept.
        var allowed = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)..<Unicode.Scalar(128)))
        allowed.insert(charactersIn: ".-*_")
        let encoded = text.addingPercentEncoding(withAllowedCharacters: allowed.union(CharacterSet(charactersIn: " "))) ?? text
        return encoded.replacingOccurrences(of: " ", with: "+")
    }

    public static func urlDecode(_ text: String) -> String {
        let spaced = text.replacingOccurrences(of: "+", with: " ")
        return spaced.removingPercentEncoding ?? spaced
    }

    public static func base64Encode(_ data: Data) -> String { data.base64EncodedString() }

    public static func base64Decode(_ text: String) -> Data? {
        var cleaned = text.filter { !$0.isWhitespace }
        cleaned = cleaned.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while cleaned.count % 4 != 0 { cleaned += "=" }
        return Data(base64Encoded: cleaned)
    }

    public static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    public static func md5(_ text: String) -> String { hex(Data(Insecure.MD5.hash(data: Data(text.utf8)))) }
    public static func sha1(_ text: String) -> String { hex(Data(Insecure.SHA1.hash(data: Data(text.utf8)))) }
    public static func sha256(_ text: String) -> String { hex(Data(SHA256.hash(data: Data(text.utf8)))) }

    public static func rot13(_ text: String) -> String {
        String(text.unicodeScalars.map { scalar -> Character in
            switch scalar.value {
            case 65...90: return Character(Unicode.Scalar((scalar.value - 65 + 13) % 26 + 65)!)
            case 97...122: return Character(Unicode.Scalar((scalar.value - 97 + 13) % 26 + 97)!)
            default: return Character(scalar)
            }
        })
    }

    public static func hexDump(_ data: Data, limit: Int = 256 * 1024) -> String {
        var lines: [String] = []
        let bytes = [UInt8](data.prefix(limit))
        var offset = 0
        while offset < bytes.count {
            let row = bytes[offset..<min(offset + 16, bytes.count)]
            let hexPart = row.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = String(row.map { ($0 >= 32 && $0 < 127) ? Character(Unicode.Scalar($0)) : "." })
            lines.append(String(format: "%08x  ", offset) + hexPart.padding(toLength: 48, withPad: " ", startingAt: 0) + "  |" + ascii + "|")
            offset += 16
        }
        if data.count > limit { lines.append("... \(data.count - limit) more bytes") }
        return lines.joined(separator: "\n")
    }
}

public enum HtmlEncoder {
    public static func encode(_ text: String) -> String {
        var result = ""
        result.reserveCapacity(text.count)
        for character in text {
            switch character {
            case "<": result += "&lt;"
            case ">": result += "&gt;"
            case "&": result += "&amp;"
            case "\"": result += "&quot;"
            case "'": result += "&#39;"
            default: result.append(character)
            }
        }
        return result
    }

    public static func decode(_ text: String) -> String {
        var result = text
        let named = ["&lt;": "<", "&gt;": ">", "&quot;": "\"", "&#39;": "'", "&apos;": "'", "&nbsp;": "\u{a0}"]
        for (entity, value) in named { result = result.replacingOccurrences(of: entity, with: value) }
        if let regex = try? NSRegularExpression(pattern: "&#(x?)([0-9a-fA-F]+);") {
            let ns = result as NSString
            var output = ""
            var last = 0
            for match in regex.matches(in: result, range: NSRange(location: 0, length: ns.length)) {
                output += ns.substring(with: NSRange(location: last, length: match.range.location - last))
                let isHex = match.range(at: 1).length > 0
                let digits = ns.substring(with: match.range(at: 2))
                if let code = UInt32(digits, radix: isHex ? 16 : 10), let scalar = Unicode.Scalar(code) {
                    output.append(Character(scalar))
                } else {
                    output += ns.substring(with: match.range)
                }
                last = match.range.location + match.range.length
            }
            output += ns.substring(from: last)
            result = output
        }
        return result.replacingOccurrences(of: "&amp;", with: "&")
    }
}

/// Levenshtein distance over token lists, as used by the Compare plugin.
public enum LevenshteinDistance {
    public static func distance<T: Equatable>(_ a: [T], _ b: [T]) -> Int {
        if a.isEmpty { return b.count }
        if b.isEmpty { return a.count }
        var previous = Array(0...b.count)
        var current = [Int](repeating: 0, count: b.count + 1)
        for i in 1...a.count {
            current[0] = i
            for j in 1...b.count {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                current[j] = Swift.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            }
            swap(&previous, &current)
        }
        return previous[b.count]
    }

    public static func tokenize(_ data: Data) -> [String] {
        String(decoding: data, as: UTF8.self).split(whereSeparator: { $0.isWhitespace }).map(String.init)
    }
}

/// A line diff (longest common subsequence), as shown by the Compare panel.
public enum LineDiff {
    public enum Line: Hashable { case same(String), removed(String), added(String) }

    public static func diff(_ left: [String], _ right: [String]) -> [Line] {
        let n = left.count, m = right.count
        guard n * m <= 4_000_000 else {
            return left.map { .removed($0) } + right.map { .added($0) }
        }
        var table = [[Int]](repeating: [Int](repeating: 0, count: m + 1), count: n + 1)
        for i in stride(from: n - 1, through: 0, by: -1) {
            for j in stride(from: m - 1, through: 0, by: -1) {
                table[i][j] = left[i] == right[j] ? table[i + 1][j + 1] + 1 : max(table[i + 1][j], table[i][j + 1])
            }
        }
        var result: [Line] = []
        var i = 0, j = 0
        while i < n && j < m {
            if left[i] == right[j] { result.append(.same(left[i])); i += 1; j += 1 }
            else if table[i + 1][j] >= table[i][j + 1] { result.append(.removed(left[i])); i += 1 }
            else { result.append(.added(right[j])); j += 1 }
        }
        while i < n { result.append(.removed(left[i])); i += 1 }
        while j < m { result.append(.added(right[j])); j += 1 }
        return result
    }
}

public extension String {
    func matches(regex pattern: String, caseSensitive: Bool = true) -> Bool {
        guard !pattern.isEmpty else { return false }
        let options: NSRegularExpression.Options = caseSensitive ? [] : [.caseInsensitive]
        guard let regex = try? NSRegularExpression(pattern: "^(?:" + pattern + ")$", options: options) else { return false }
        return regex.firstMatch(in: self, range: NSRange(location: 0, length: (self as NSString).length)) != nil
    }

    func contains(regex pattern: String, caseSensitive: Bool = true) -> Bool {
        guard !pattern.isEmpty else { return false }
        let options: NSRegularExpression.Options = caseSensitive ? [] : [.caseInsensitive]
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else { return false }
        return regex.firstMatch(in: self, range: NSRange(location: 0, length: (self as NSString).length)) != nil
    }

    func firstMatch(regex pattern: String, group: Int = 1) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = self as NSString
        guard let match = regex.firstMatch(in: self, range: NSRange(location: 0, length: ns.length)),
              match.numberOfRanges > group, match.range(at: group).location != NSNotFound else { return nil }
        return ns.substring(with: match.range(at: group))
    }

    static func isValidRegex(_ pattern: String) -> Bool { (try? NSRegularExpression(pattern: pattern)) != nil }
}
