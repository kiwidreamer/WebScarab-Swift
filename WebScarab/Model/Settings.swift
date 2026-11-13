// WebScarab (Swift) - preferences (model.Preferences), kept in UserDefaults.

import Foundation

public enum Settings {
    static let defaults = UserDefaults.standard

    static func value<T: Codable>(_ key: String, default fallback: T) -> T {
        guard let data = defaults.data(forKey: key), let value = try? JSONDecoder().decode(T.self, from: data) else { return fallback }
        return value
    }

    static func set<T: Codable>(_ key: String, _ value: T) {
        if let data = try? JSONEncoder().encode(value) { defaults.set(data, forKey: key) }
    }

    public static var upstreamProxy: UpstreamProxySettings {
        get { value("Proxy.upstream", default: UpstreamProxySettings()) }
        set { set("Proxy.upstream", newValue) }
    }

    public static var listeners: [ListenerSpec] {
        get { value("Proxy.listeners", default: [ListenerSpec()]) }
        set { set("Proxy.listeners", newValue) }
    }

    public static var dropPattern: String {
        get { defaults.string(forKey: "WebScarab.dropPattern") ?? "" }
        set { defaults.set(newValue, forKey: "WebScarab.dropPattern") }
    }
}

/// One proxy listener (plugin.proxy.ListenerSpec): address, port and an optional base URL for reverse proxying.
public struct ListenerSpec: Codable, Hashable, Identifiable, Sendable {
    public var id: String { "\(address):\(port)" }
    public var address = "127.0.0.1"
    public var port = 8008
    public var base = ""
    public init(address: String = "127.0.0.1", port: Int = 8008, base: String = "") {
        self.address = address
        self.port = port
        self.base = base
    }
    public var baseURL: URL? { base.isEmpty ? nil : URL(string: base) }
}
