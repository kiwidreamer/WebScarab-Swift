// WebScarab (Swift) - SessionID Analysis tab and the Tools windows:
// Transcoder, Shared Cookies, Certificates and Proxies.

import SwiftUI
import AppKit
import Charts

// MARK: SessionID Analysis (plugin.sessionid.swing.SessionIDPanel)

struct SessionIDView: View {
    @EnvironmentObject var analysis: SessionIDAnalysis
    @EnvironmentObject var framework: Framework
    @State private var section = 0
    @State private var name: String?
    @State private var requestText = "GET http://localhost/ HTTP/1.1\nHost: localhost\n\n"
    @State private var byCookie = true
    @State private var cookieName = ""
    @State private var regex = "JSESSIONID=([^;]*)"
    @State private var testResult = ""
    @State private var previous: Int?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("", selection: $section) {
                Text("Collection").tag(0)
                Text("Analysis").tag(1)
                Text("Visualisation").tag(2)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            switch section {
            case 0: collection
            case 1: analysisView
            default: chart
            }
        }
        .padding()
    }

    var location: SessionIDAnalysis.Location { byCookie ? .cookie(cookieName) : .regex(regex) }

    var collection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Previous requests", selection: $previous) {
                Text("Choose a recorded request…").tag(Int?.none)
                ForEach(framework.conversations.suffix(200).reversed()) { c in
                    Text("\(c.id) \(c.method) \(c.url.absoluteString)").lineLimit(1).tag(Int?.some(c.id))
                }
            }
            .onChange(of: previous) { _, id in if let id, let c = framework.conversation(id) { requestText = c.request.rawText } }
            CodeTextView(text: $requestText).frame(minHeight: 140).border(Color.secondary.opacity(0.3))
            Picker("Session identifier is", selection: $byCookie) {
                Text("a cookie").tag(true)
                Text("found by a regular expression").tag(false)
            }
            .pickerStyle(.radioGroup)
            if byCookie {
                TextField("Cookie name (empty = first cookie set)", text: $cookieName)
            } else {
                RegexField(title: "Regular expression with one ( ) group", text: $regex)
            }
            HStack {
                Stepper("Samples: \(analysis.sampleCount)", value: $analysis.sampleCount, in: 1...10000, step: 10)
                Button("Test") {
                    guard let request = try? HTTPParser.request(fromText: requestText) else { testResult = "The request could not be read"; return }
                    Task { testResult = await analysis.test(request, location: location) }
                }
                Button("Fetch") {
                    guard let request = try? HTTPParser.request(fromText: requestText) else { testResult = "The request could not be read"; return }
                    analysis.fetch(request, location: location, count: analysis.sampleCount)
                }
                Button("Stop") { analysis.stop() }
                Text(analysis.status).foregroundStyle(.secondary)
            }
            if !testResult.isEmpty { Text(testResult).textSelection(.enabled) }
            Text("Cookies set in any recorded response are collected here too.").font(.caption).foregroundStyle(.secondary)
        }
    }

    var analysisView: some View {
        VStack(alignment: .leading, spacing: 8) {
            namePicker
            if let name {
                let calculator = analysis.calculator(for: name)
                let samples = analysis.samples[name] ?? []
                HStack {
                    TextField("Part of the value to analyse (regex with one group)", text: Binding(
                        get: { analysis.patterns[name] ?? "^(.+)$" }, set: { analysis.patterns[name] = $0 }))
                    Button("Clear samples") { analysis.clear(name) }
                }
                Table(samples) {
                    TableColumn("Date") { Text($0.date.formatted(date: .omitted, time: .standard)) }.width(90)
                    TableColumn("Value") { Text($0.value).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
                    TableColumn("Numeric") { Text(String(format: "%.0f", calculator.calculate($0.value))) }.width(min: 100, ideal: 180)
                    TableColumn("Difference") { sample in
                        let index = samples.firstIndex(of: sample) ?? 0
                        Text(index == 0 ? "" : String(format: "%.0f", calculator.calculate(sample.value) - calculator.calculate(samples[index - 1].value)))
                    }.width(min: 80, ideal: 140)
                }
            } else {
                Spacer()
            }
        }
    }

    var chart: some View {
        VStack(alignment: .leading) {
            namePicker
            if let name {
                let calculator = analysis.calculator(for: name)
                Chart(analysis.samples[name] ?? []) { sample in
                    PointMark(x: .value("Time", sample.date), y: .value("Value", calculator.calculate(sample.value)))
                }
                .chartYAxisLabel("Calculated value")
                Text("Values that line up or climb steadily are predictable; random identifiers scatter.").font(.caption).foregroundStyle(.secondary)
            } else {
                Spacer()
            }
        }
    }

    var namePicker: some View {
        Picker("Session identifier", selection: $name) {
            Text("Choose…").tag(String?.none)
            ForEach(analysis.names, id: \.self) { n in Text("\(n) (\(analysis.samples[n]?.count ?? 0))").tag(String?.some(n)) }
        }
    }
}

// MARK: Transcoder (ui.swing.TranscoderFrame)

struct TranscoderView: View {
    @State private var text = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            CodeTextView(text: $text).border(Color.secondary.opacity(0.3))
            HStack {
                Text("Characters: \(text.count)").foregroundStyle(.secondary)
                if let error { Text(error).foregroundStyle(.red) }
            }
            HStack {
                Button("URL encode") { text = Encoding.urlEncode(text) }
                Button("URL decode") { text = Encoding.urlDecode(text) }
                Button("Base64 encode") { text = Encoding.base64Encode(Data(text.utf8)) }
                Button("Base64 decode") {
                    if let data = Encoding.base64Decode(text) {
                        text = String(data: data, encoding: .utf8) ?? Encoding.hexDump(data)
                        error = nil
                    } else { error = "Not valid Base64" }
                }
            }
            HStack {
                Button("HTML encode") { text = HtmlEncoder.encode(text) }
                Button("HTML decode") { text = HtmlEncoder.decode(text) }
                Button("MD5 hash") { text = Encoding.md5(text) }
                Button("SHA-1 hash") { text = Encoding.sha1(text) }
                Button("SHA-256 hash") { text = Encoding.sha256(text) }
                Button("ROT13") { text = Encoding.rot13(text) }
            }
        }
        .padding()
    }
}

// MARK: Shared Cookies (ui.swing.CookieJarViewer)

struct CookieJarView: View {
    @EnvironmentObject var framework: Framework
    @State private var selection: Set<Cookie.ID> = []
    @State private var url = ""
    @State private var setCookie = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Table(framework.currentCookies, selection: $selection) {
                TableColumn("Date") { Text($0.date.formatted(date: .abbreviated, time: .standard)) }.width(min: 100, ideal: 150)
                TableColumn("Domain", value: \.domain)
                TableColumn("Path", value: \.path).width(min: 40, ideal: 60)
                TableColumn("Name", value: \.name)
                TableColumn("Value") { Text($0.value).textSelection(.enabled) }
                TableColumn("Changes") { Text(String(framework.cookieHistory[$0.key]?.count ?? 0)) }.width(60)
            }
            HStack {
                Button("Delete") {
                    for cookie in framework.currentCookies where selection.contains(cookie.id) { framework.removeCookies(key: cookie.key) }
                }
                .disabled(selection.isEmpty)
                Spacer()
            }
            GroupBox("Add a cookie") {
                HStack {
                    TextField("URL", text: $url).frame(width: 220)
                    TextField("Set-Cookie value, e.g. session=abc; path=/", text: $setCookie)
                    Button("Add") {
                        if let cookie = Cookie(date: Date(), url: URL(string: url), setCookie: setCookie) {
                            framework.addCookie(cookie)
                            setCookie = ""
                        }
                    }
                    .disabled(setCookie.isEmpty)
                }
                .padding(4)
            }
        }
        .padding()
    }
}

// MARK: Certificates

struct CertificatesView: View {
    @State private var summary = CertificateAuthority.shared.caSummary
    @State private var fingerprint = CertificateAuthority.shared.fingerprint
    @State private var trusted = CertificateAuthority.shared.isTrusted
    @State private var message: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Which certificate to trust").font(.headline)
                Text("Trust only the certificate authority this app made for you. Its name starts with \"WebScarab Custom CA for\" followed by this Mac's name. WebScarab uses it to sign a certificate for each secure site you visit, so your browser stops warning. Don't trust anything else: not the server.p12 file that came with the Java WebScarab, and not the per-site certificates.")
                    .fixedSize(horizontal: false, vertical: true)

                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        LabeledContent("Name", value: summary ?? "Not made yet")
                        if let fingerprint {
                            LabeledContent("SHA-256 fingerprint") {
                                Text(fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                        LabeledContent("File", value: summary == nil ? "-" : CertificateAuthority.shared.caCertificateURL.path)
                        LabeledContent("Trusted on this Mac") {
                            Label(trusted ? "Yes" : "No", systemImage: trusted ? "checkmark.seal.fill" : "xmark.seal")
                                .foregroundStyle(trusted ? .green : .secondary)
                        }
                    }
                    .padding(4)
                }

                HStack {
                    if summary == nil {
                        Button("Make the certificate authority") { run { try CertificateAuthority.shared.prepare() } }
                    } else if trusted {
                        Button("Stop trusting it") { run { try CertificateAuthority.shared.untrust() } }
                    } else {
                        Button("Trust it on this Mac…") { run { try CertificateAuthority.shared.trust() } }
                            .keyboardShortcut(.defaultAction)
                    }
                    Button("Export…") { export() }.disabled(summary == nil)
                    Button("Show in Keychain Access") { NSWorkspace.shared.open(CertificateAuthority.shared.caCertificateURL) }
                        .disabled(summary == nil)
                }
                Text("\"Trust it on this Mac\" asks for your Mac password. Safari, Chrome and Edge then accept it. Firefox keeps its own list: export the file and import it under Firefox Settings > Privacy & Security > Certificates > View Certificates > Authorities, ticking \"Trust this CA to identify websites\".")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Text("Anyone holding this authority's key could fake secure sites to your browser, so only trust it on a Mac you use for testing, and choose \"Stop trusting it\" when you're done.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

                Divider()
                Button("Replace with a new certificate authority") {
                    run {
                        try? CertificateAuthority.shared.untrust()
                        try CertificateAuthority.shared.regenerate()
                    }
                }
                Text("Use this if the key may have leaked. You'll need to trust the new one again.")
                    .font(.caption).foregroundStyle(.secondary)

                if let message { Text(message).fixedSize(horizontal: false, vertical: true) }
            }
            .padding()
        }
        .onAppear {
            // Load the authority from earlier runs (made the first time a secure site is visited).
            if summary == nil, FileManager.default.fileExists(atPath: CertificateAuthority.shared.caCertificateURL.path) {
                try? CertificateAuthority.shared.prepare()
            }
            refresh()
        }
    }

    func refresh() {
        summary = CertificateAuthority.shared.caSummary
        fingerprint = CertificateAuthority.shared.fingerprint
        trusted = CertificateAuthority.shared.isTrusted
    }

    func run(_ work: @escaping () throws -> Void) {
        do {
            try work()
            Task { await InterceptListeners.shared.reset() }
            message = nil
        } catch {
            message = "That didn't work: \(error)"
        }
        refresh()
    }

    func export() {
        guard let data = CertificateAuthority.shared.caCertificateData else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "WebScarab-CA.cer"
        if panel.runModal() == .OK, let url = panel.url {
            do { try data.write(to: url); message = "Saved \(url.lastPathComponent)." } catch { message = "\(error)" }
        }
    }
}

// MARK: Proxies (ui.swing.ProxyConfig)

struct UpstreamProxyView: View {
    @State private var settings = Settings.upstreamProxy

    var body: some View {
        Form {
            Section("Send WebScarab's own requests through another proxy") {
                HStack { TextField("HTTP proxy", text: $settings.httpHost); TextField("Port", value: $settings.httpPort, format: .number.grouping(.never)).frame(width: 70) }
                HStack { TextField("HTTPS proxy", text: $settings.httpsHost); TextField("Port", value: $settings.httpsPort, format: .number.grouping(.never)).frame(width: 70) }
                TextField("No proxy for (comma separated)", text: $settings.noProxy)
            }
            HStack {
                Spacer()
                Button("Save") { Settings.upstreamProxy = settings }.keyboardShortcut(.defaultAction)
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}
