// WebScarab (Swift) - the SAML tab (plugin.saml.swing.SamlPanel): the SAML messages seen,
// their decoded XML, attributes, relay state and the protections each one carries.

import SwiftUI

struct SamlView: View {
    @EnvironmentObject var saml: Saml
    @State private var section = 0

    var body: some View {
        VStack(spacing: 6) {
            Picker("", selection: $section) {
                Text("Messages").tag(0)
                Text("Attacks").tag(1)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            .padding(.top, 6)
            if section == 0 { SamlMessagesView() } else { SamlAttacksView() }
        }
    }
}

struct SamlMessagesView: View {
    @EnvironmentObject var saml: Saml
    @State private var selection: Int?

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 4) {
                Text("SAML messages").font(.headline)
                Table(saml.messages, selection: $selection) {
                    TableColumn("ID") { Text(String($0.conversation)) }.width(44)
                    TableColumn("Type") { Text($0.kind.rawValue) }.width(70)
                    TableColumn("Version") { Text($0.version) }.width(80)
                    TableColumn("URL") { Text($0.url.absoluteString).lineLimit(1) }
                }
                .contextMenu(forSelectionType: Int.self) { ids in
                    if let id = ids.first {
                        Button("Use this message for the Replay attack") { saml.useForReplay(id) }
                    }
                }
                Text("SAML single-sign-on messages are picked up automatically from traffic recorded by the proxy.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding()
            .frame(minWidth: 280)

            if let id = selection, let analysis = saml.analyses[id] {
                SamlDetail(analysis: analysis).frame(minWidth: 420)
            } else {
                Text("Select a SAML message to inspect it.").foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}

struct SamlDetail: View {
    let analysis: SamlAnalysis
    @State private var tab = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            GroupBox("Overview") {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                    GridRow { Text("Type").foregroundStyle(.secondary); Text("\(analysis.version) \(analysis.kind.rawValue)") }
                    if let issuer = analysis.issuer { GridRow { Text("Issuer").foregroundStyle(.secondary); Text(issuer).textSelection(.enabled) } }
                    if let subject = analysis.subject { GridRow { Text("Subject").foregroundStyle(.secondary); Text(subject).textSelection(.enabled) } }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            GroupBox("Protections") {
                VStack(alignment: .leading, spacing: 3) {
                    indicator("Protocol message signed", analysis.hasProtocolSignature)
                    indicator("Assertion signed", analysis.hasAssertionSignature)
                    indicator("Destination / recipient stated (anti-replay)", analysis.hasDestinationIndication)
                    indicator("Validity window stated", analysis.hasValidityInterval)
                    if analysis.hasEncryptedAttributes {
                        Label("Carries encrypted attributes", systemImage: "lock.doc").foregroundStyle(.secondary)
                    }
                    Text("Unsigned messages, or ones with no destination or validity window, are easier to replay or tamper with.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            Picker("", selection: $tab) {
                Text("Decoded XML").tag(0)
                Text("Attributes (\(analysis.attributes.count))").tag(1)
                Text("Validity").tag(2)
                Text("Relay State").tag(3)
            }
            .pickerStyle(.segmented).labelsHidden()

            switch tab {
            case 0: ReadOnlyText(text: analysis.prettyXML, wrap: false)
            case 1:
                Table(analysis.attributes.map { NamedPair(name: $0.name, value: $0.value) }) {
                    TableColumn("Name", value: \.name)
                    TableColumn("Value") { Text($0.value).textSelection(.enabled) }
                }
            case 2:
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Not before", value: analysis.notBefore ?? "not stated")
                    LabeledContent("Not on or after", value: analysis.notOnOrAfter ?? "not stated")
                    if analysis.destinations.isEmpty {
                        Text("No destination or recipient stated.").foregroundStyle(.secondary)
                    } else {
                        Text("Destinations").font(.headline)
                        ForEach(analysis.destinations, id: \.self) { Text($0).textSelection(.enabled) }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            default:
                if let relay = analysis.relayState {
                    ReadOnlyText(text: relay)
                } else {
                    Text("No RelayState in this message.").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .padding()
    }

    func indicator(_ title: String, _ present: Bool) -> some View {
        Label(title, systemImage: present ? "checkmark.circle.fill" : "exclamationmark.triangle")
            .foregroundStyle(present ? .green : .orange)
    }
}

struct SamlAttacksView: View {
    @EnvironmentObject var saml: Saml
    @EnvironmentObject var framework: Framework

    var body: some View {
        Form {
            Section {
                Text("These rewrite a SAML message as it leaves your browser through the proxy, so you can test whether a service provider correctly rejects a tampered single-sign-on message. Use them only against systems you are authorized to test. Each change is marked with an X-SAMLProxy header and noted in the log.")
                    .font(.callout).foregroundStyle(.secondary)
                if saml.attacks.isActive {
                    Label("Active: outgoing SAML POSTs are being rewritten", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
            Section("Signatures") {
                Toggle("Remove the protocol (message) signature", isOn: $saml.attacks.removeProtocolSignature)
                Toggle("Remove the assertion signature", isOn: $saml.attacks.removeAssertionSignature)
                Toggle("Corrupt the signature (flip a byte of SignatureValue)", isOn: $saml.attacks.corruptSignature)
                Toggle("Inject a remote Reference URI into the signature", isOn: $saml.attacks.injectRemoteReference)
                if saml.attacks.injectRemoteReference {
                    TextField("Reference URI", text: $saml.attacks.remoteReference)
                }
            }
            Section("Signature wrapping (XSW)") {
                Toggle("Wrap the signed element and add an unsigned copy", isOn: $saml.attacks.signatureWrapping)
                if saml.attacks.signatureWrapping {
                    Picker("Wrapper", selection: $saml.attacks.wrapper) { ForEach(SamlWrapper.allCases) { Text($0.rawValue).tag($0) } }
                    if saml.attacks.wrapper == .dsObject {
                        Picker("Target signature", selection: $saml.attacks.wrapperTarget) { ForEach(SamlSignatureTarget.allCases) { Text($0.rawValue).tag($0) } }
                    }
                    Toggle("Rename the top-level ID", isOn: $saml.attacks.renameTopId)
                    Toggle("Rename the original assertion ID", isOn: $saml.attacks.renameAssertionId)
                    Toggle("Rename the copied assertion ID", isOn: $saml.attacks.renameLastAssertionId)
                }
            }
            Section("Assertion content") {
                Toggle("Overwrite the subject (NameID)", isOn: $saml.attacks.injectSubject)
                if saml.attacks.injectSubject {
                    TextField("New subject", text: $saml.attacks.subject)
                    Picker("Apply to", selection: $saml.attacks.subjectOccurrence) { ForEach(SamlOccurrence.allCases) { Text($0.rawValue).tag($0) } }
                }
                Toggle("Set or add attributes", isOn: $saml.attacks.injectAttribute)
                if saml.attacks.injectAttribute { SamlAttributeEditor(attributes: $saml.attacks.injectionAttributes) }
            }
            Section("Other") {
                Toggle("Inject a DOCTYPE referencing an external DTD (XXE probe)", isOn: $saml.attacks.injectPublicDoctype)
                if saml.attacks.injectPublicDoctype { TextField("DTD URI", text: $saml.attacks.dtdUri) }
                Toggle("Inject / replace RelayState", isOn: $saml.attacks.injectRelayState)
                if saml.attacks.injectRelayState { TextField("RelayState", text: $saml.attacks.relayState) }
                Toggle("Replay a captured SAMLResponse", isOn: $saml.attacks.replay)
                if saml.attacks.replay {
                    if let id = saml.replaySource {
                        Text("Replaying the message from conversation \(id). Right-click a message under Messages to change it.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Right-click a message under Messages and choose \"Use this message for the Replay attack\".")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            Section {
                Button("Turn every attack off") { saml.attacks = SamlAttackConfig() }
            }
        }
        .formStyle(.grouped)
    }
}

struct SamlAttributeEditor: View {
    @Binding var attributes: [SamlNamedValue]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach($attributes) { $attribute in
                HStack {
                    TextField("Name", text: $attribute.name)
                    TextField("Value", text: $attribute.value)
                    Button { attributes.removeAll { $0.id == attribute.id } } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless)
                }
            }
            Button("Add attribute") { attributes.append(SamlNamedValue()) }
        }
    }
}
