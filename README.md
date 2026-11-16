# WebScarab (Swift)

A native macOS rebuild of OWASP WebScarab in Swift and SwiftUI, with no third-party dependencies.
Open `WebScarab.xcodeproj` in Xcode and press Run, or build from the command line:

    xcodebuild -project WebScarab.xcodeproj -scheme WebScarab build
    xcodebuild -project WebScarab.xcodeproj -scheme WebScarab test

Requires macOS 14 or later.

## How to build the application

Run `./build-app.sh` in this folder. It builds the release version and puts the finished app at
`WebScarabSwift/Build/WebScarab.app`: double-click it, or drag it into Applications.

Builds started from Xcode itself go to Xcode's build folder (Product > Show Build Folder in Finder;
on this Mac that is `~/Desktop/Build/Products/Debug/WebScarab.app`).


## What's included

- **Proxy** – listens on 127.0.0.1:8008 (add more listeners, or a base URL for reverse proxying).
  Records every conversation; intercepts and edits requests and responses (Manual Edit, with the same
  include/exclude rules); reveals hidden form fields; stops browser caching; injects known cookies.
  HTTPS is intercepted with certificates signed by a local certificate authority named
  "WebScarab Custom CA for <this Mac>". That authority is the only certificate to trust: open
  Tools > Certificates and choose "Trust it on this Mac…" (Firefox needs the exported file imported
  under its own Authorities list). Don't trust the Java project's server.p12. Choose "Stop trusting it"
  when you're done testing. Without the CA, HTTPS still passes through, but nothing is recorded.
- **Summary** – site tree (URL, methods, status) over the conversation list; the tree filters the list.
  Double-click a conversation for its request and response (parsed, raw, text, HTML, XML/JSON,
  form, image and hex views).
- **SAML** – picks up SAML single-sign-on messages from recorded traffic, decodes them and shows
  their type, attributes, relay state and which protections they carry (signatures, destination, validity
  window). Its Attacks panel rewrites outgoing SAML POSTs for authorized testing of a service provider:
  signature stripping and corruption, signature wrapping (XSW), subject/attribute injection, remote-reference
  and DOCTYPE (XXE) injection, RelayState injection and response replay. Each change is logged and marked
  with an `X-SAMLProxy` header.
- **Manual Request**, **Spider**, **Extensions**, **XSS/CRLF**, **SessionID Analysis** (with chart),
  **Fuzzer** (fuzz sources from files, built-in lists or patterns such as `[a-z]{2}[0-9]`),
  **Compare**, **Search** and **Fragments** tabs.
- **Tools** – Proxies (upstream proxy), Certificates, Shared Cookies, Transcoder, Discard conversations.
- **Sessions** – File > Save/Open uses WebScarab's own session folder format, so sessions move
  between this app and the Java WebScarab.

## Not included in this version

The OpenID, WS-Federation, Identity, BeanShell/script manager, Flash AMF and Java-object viewer plugins.
The SAML plugin's "sign the message with your own key" option is omitted (it needs a full XML-DSig
implementation); every other SAML attack is included. Search uses built-in text and regular-expression searches instead of BeanShell expressions.

## Methadology
This application was ported using Claude Code. All code has been hand reviewed and tested by a development team after any AI adjustments.

## About Us
Kiwi Dreamer Consulting LLC provides software development and Information security services (architecture, management, development) to small and medium size organizations
