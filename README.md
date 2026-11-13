# WebScarab (Swift)

A native macOS rebuild of OWASP WebScarab in Swift and SwiftUI, with no third-party dependencies.
Open `WebScarab.xcodeproj` in Xcode and press Run, or build from the command line:

    xcodebuild -project WebScarab.xcodeproj -scheme WebScarab build
    xcodebuild -project WebScarab.xcodeproj -scheme WebScarab test

Requires macOS 14 or later.

## Where the built app is

Run `./build-app.sh` in this folder. It builds the release version and puts the finished app at
`WebScarabSwift/Build/WebScarab.app`: double-click it, or drag it into Applications.

Builds started from Xcode itself go to Xcode's build folder (Product > Show Build Folder in Finder;
on this Mac that is `~/Desktop/Build/Products/Debug/WebScarab.app`).

The original Java WebScarab builds with `mvn package` into `target/WebScarab-1.0.0-SNAPSHOT.one-jar.jar`.

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
- **Manual Request**, **Spider**, **Extensions**, **XSS/CRLF**, **SessionID Analysis** (with chart),
  **Fuzzer** (fuzz sources from files, built-in lists or patterns such as `[a-z]{2}[0-9]`),
  **Compare**, **Search** and **Fragments** tabs.
- **Tools** – Proxies (upstream proxy), Certificates, Shared Cookies, Transcoder, Discard conversations.
- **Sessions** – File > Save/Open uses WebScarab's own session folder format, so sessions move
  between this app and the Java WebScarab.

## Not included in this version

The SAML, OpenID, WS-Federation, Identity, BeanShell/script manager, Flash AMF and Java-object viewer
plugins. Search uses built-in text and regular-expression searches instead of BeanShell expressions.
