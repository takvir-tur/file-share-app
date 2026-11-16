import Cocoa
import Foundation
import UniformTypeIdentifiers

/// Headless macOS Share Extension principal controller for Finder (`com.apple.share-services`).
/// Extracts shared file and folder URLs from `NSExtensionContext`, forwards them to `BeamDrop.app`,
/// and completes immediately without blocking Finder with an intermediate share sheet UI.
public final class ShareViewController: NSViewController {
    private static let mainBundleIdentifier = "com.beamdrop.app"

    public override var nibName: NSNib.Name? { nil }

    public override func loadView() {
        preferredContentSize = NSSize(width: 1, height: 1)
        view = NSView(frame: NSRect(x: 0, y: 0, width: 1, height: 1))
    }

    public override func beginRequest(with context: NSExtensionContext) {
        super.beginRequest(with: context)
        extractFileURLs(from: context) { [weak self] urls in
            guard let self, !urls.isEmpty else {
                DispatchQueue.main.async {
                    context.completeRequest(returningItems: nil, completionHandler: nil)
                }
                return
            }

            self.forwardToMainApp(fileURLs: urls) {
                DispatchQueue.main.async {
                    context.completeRequest(returningItems: nil, completionHandler: nil)
                }
            }
        }
    }

    private func extractFileURLs(
        from context: NSExtensionContext,
        completion: @escaping ([URL]) -> Void
    ) {
        guard let items = context.inputItems as? [NSExtensionItem], !items.isEmpty else {
            completion([])
            return
        }

        let lock = NSLock()
        let group = DispatchGroup()
        var orderedURLs: [URL] = []
        var seenPaths = Set<String>()

        let appendURL: (URL) -> Void = { url in
            guard url.isFileURL else { return }
            let standardized = url.standardizedFileURL
            lock.lock()
            if seenPaths.insert(standardized.path).inserted {
                orderedURLs.append(standardized)
            }
            lock.unlock()
        }

        let fileURLType = UTType.fileURL.identifier
        let urlType = UTType.url.identifier

        for item in items {
            for provider in item.attachments ?? [] {
                let targetType: String
                if provider.hasItemConformingToTypeIdentifier(fileURLType) {
                    targetType = fileURLType
                } else if provider.hasItemConformingToTypeIdentifier(urlType) {
                    targetType = urlType
                } else {
                    continue
                }

                group.enter()
                provider.loadItem(forTypeIdentifier: targetType, options: nil) { loaded, _ in
                    defer { group.leave() }
                    if let url = Self.coerceURL(from: loaded) {
                        appendURL(url)
                    }
                }
            }
        }

        group.notify(queue: .global(qos: .userInitiated)) {
            lock.lock()
            let snapshot = orderedURLs
            lock.unlock()
            completion(snapshot)
        }
    }

    private static func coerceURL(from item: NSSecureCoding?) -> URL? {
        if let url = item as? URL {
            return url
        }
        if let data = item as? Data {
            if let url = URL(dataRepresentation: data, relativeTo: nil) {
                return url
            }
            if let str = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            {
                return str.hasPrefix("/") ? URL(fileURLWithPath: str) : URL(string: str)
            }
            return nil
        }
        if let str = item as? String {
            let trimmed = str.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            return trimmed.hasPrefix("/") ? URL(fileURLWithPath: trimmed) : URL(string: trimmed)
        }
        return nil
    }

    private func resolveHostAppURL() -> URL? {
        // BeamDrop.app/Contents/PlugIns/BeamDropShare.appex -> walk up 3 components to BeamDrop.app.
        let candidate = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        guard candidate.pathExtension == "app",
              FileManager.default.fileExists(atPath: candidate.path)
        else {
            return nil
        }
        return candidate
    }

    private func buildSendURL(for paths: [String]) -> URL? {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+#?;")
        var queryPairs: [String] = []
        queryPairs.reserveCapacity(paths.count)
        for path in paths {
            guard let encoded = path.addingPercentEncoding(withAllowedCharacters: allowed) else {
                return nil
            }
            queryPairs.append("path=\(encoded)")
        }
        let raw = "beamdrop://send?" + queryPairs.joined(separator: "&")
        guard raw.utf8.count <= 32_768 else {
            return nil
        }
        return URL(string: raw)
    }

    private func forwardToMainApp(fileURLs: [URL], completion: @escaping () -> Void) {
        let paths = fileURLs.map { $0.path }
        let hostAppURL = resolveHostAppURL()

        if let sendURL = buildSendURL(for: paths) {
            let config = NSWorkspace.OpenConfiguration()
            config.activates = true
            if let appURL = hostAppURL {
                NSWorkspace.shared.open([sendURL], withApplicationAt: appURL, configuration: config) { [weak self] _, error in
                    guard let error else {
                        completion()
                        return
                    }
                    NSLog("BeamDropShare: open withApplicationAt failed (%@); retrying URL open", error.localizedDescription)
                    NSWorkspace.shared.open(sendURL, configuration: config) { [weak self] _, urlError in
                        if urlError != nil {
                            self?.launchViaOpenTool(paths: paths, hostAppURL: appURL)
                        }
                        completion()
                    }
                }
                return
            }

            NSWorkspace.shared.open(sendURL, configuration: config) { [weak self] _, error in
                if error != nil {
                    self?.launchViaOpenTool(paths: paths, hostAppURL: nil)
                }
                completion()
            }
            return
        }

        launchViaOpenTool(paths: paths, hostAppURL: hostAppURL)
        completion()
    }

    private func launchViaOpenTool(paths: [String], hostAppURL: URL?) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        var args = ["-n"]
        if let appURL = hostAppURL {
            args.append(contentsOf: ["-a", appURL.path])
        } else {
            args.append(contentsOf: ["-b", Self.mainBundleIdentifier])
        }
        args.append(contentsOf: ["--args", "--send"])
        args.append(contentsOf: paths)
        process.arguments = args

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            // Best-effort handoff; avoid blocking Finder extension termination.
        }
    }
}

