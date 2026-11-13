// WebScarab (Swift) - application entry point (org.owasp.webscarab.WebScarab / ui.swing.UIFramework).

import SwiftUI
import AppKit

/// Every plugin, created once and shared (plugin.Framework's plugin list).
@MainActor
final class Plugins {
    static let shared = Plugins()
    let framework = Framework.shared
    let proxy = ProxyController.shared
    let manualRequest = ManualRequest()
    let spider: Spider
    let fuzzer = Fuzzer()
    let search: Search
    let compare = Compare()
    let sessionID: SessionIDAnalysis
    let xss: XSSCRLF
    let fragments: Fragments
    let saml: Saml
    let extensions = Extensions()

    private init() {
        spider = Spider(framework: framework)
        search = Search(framework: framework)
        sessionID = SessionIDAnalysis(framework: framework)
        xss = XSSCRLF(framework: framework)
        fragments = Fragments(framework: framework)
        saml = Saml(framework: framework)
    }
}

enum ToolTab: String, CaseIterable, Identifiable {
    case summary = "Summary", proxy = "Proxy", manualRequest = "Manual Request", spider = "Spider",
         extensions = "Extensions", xss = "XSS/CRLF", sessionID = "SessionID Analysis", fuzzer = "Fuzzer",
         compare = "Compare", search = "Search", fragments = "Fragments", saml = "SAML"
    var id: String { rawValue }
}

/// What the person is looking at, shared between tabs (for "send to" actions).
@MainActor
final class AppState: ObservableObject {
    static let shared = AppState()
    @Published var tab: ToolTab = .summary
    @Published var showLog = true
    @Published var showDiscardDialog = false
    @Published var alert: String?
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let underTest = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
        Task { @MainActor in
            _ = Plugins.shared
            if !underTest { ProxyController.shared.startAll() }
            Framework.shared.log(.info, "WebScarab", "WebScarab (Swift) started")
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct WebScarabApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    private let plugins = Plugins.shared
    @ObservedObject private var state = AppState.shared

    var body: some Scene {
        WindowGroup("WebScarab") {
            MainView()
                .environmentObjects(plugins)
                .environmentObject(state)
                .frame(minWidth: 900, minHeight: 600)
        }
        .commands { WebScarabCommands(state: state) }

        WindowGroup("Conversation", id: "conversation", for: Int.self) { $id in
            ConversationWindow(id: id ?? 0)
                .environmentObjects(plugins)
                .environmentObject(state)
        }
        .defaultSize(width: 900, height: 700)

        Window("Intercepted message", id: "intercept") {
            InterceptWindow().environmentObjects(plugins)
        }
        .defaultSize(width: 800, height: 600)

        Window("Transcoder", id: "transcoder") { TranscoderView() }
            .defaultSize(width: 640, height: 480)

        Window("Shared Cookies", id: "cookies") { CookieJarView().environmentObjects(plugins) }
            .defaultSize(width: 800, height: 400)

        Window("Certificates", id: "certificates") { CertificatesView() }
            .defaultSize(width: 620, height: 560)

        Window("Proxies", id: "upstream") { UpstreamProxyView() }
            .defaultSize(width: 480, height: 260)
    }
}

extension View {
    @MainActor func environmentObjects(_ plugins: Plugins) -> some View {
        self.environmentObject(plugins.framework)
            .environmentObject(plugins.proxy)
            .environmentObject(plugins.manualRequest)
            .environmentObject(plugins.spider)
            .environmentObject(plugins.fuzzer)
            .environmentObject(plugins.search)
            .environmentObject(plugins.compare)
            .environmentObject(plugins.sessionID)
            .environmentObject(plugins.xss)
            .environmentObject(plugins.fragments)
            .environmentObject(plugins.saml)
            .environmentObject(plugins.extensions)
    }
}

struct WebScarabCommands: Commands {
    @ObservedObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Session") { SessionActions.newSession() }.keyboardShortcut("n")
            Button("Open Session…") { SessionActions.open() }.keyboardShortcut("o")
            Button("Save Session…") { SessionActions.save() }.keyboardShortcut("s")
        }
        CommandMenu("Tools") {
            Button("Proxies…") { openWindow(id: "upstream") }
            Button("Certificates…") { openWindow(id: "certificates") }
            Button("Shared Cookies…") { openWindow(id: "cookies") }
            Button("Transcoder…") { openWindow(id: "transcoder") }.keyboardShortcut("t", modifiers: [.command, .shift])
            Divider()
            Button("Discard Conversations…") { state.showDiscardDialog = true }
        }
        CommandGroup(after: .sidebar) {
            Toggle("Show Log", isOn: $state.showLog)
        }
    }
}

@MainActor
enum SessionActions {
    static func newSession() {
        if Framework.shared.modified && !confirm("Discard the current session?", detail: "Conversations that weren't saved will be lost.") { return }
        Framework.shared.reset()
    }

    static func open() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.message = "Choose a WebScarab session folder (it holds a conversationlog file)."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do { try await Framework.shared.open(url) }
            catch { AppState.shared.alert = "Could not open the session: \(error)" }
        }
    }

    static func save() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "WebScarab session"
        panel.message = "Sessions are saved as a folder that the Java WebScarab can open too."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try Framework.shared.save(to: url) }
        catch { AppState.shared.alert = "Could not save the session: \(error)" }
    }

    static func confirm(_ message: String, detail: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = detail
        alert.addButton(withTitle: "Discard")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}
