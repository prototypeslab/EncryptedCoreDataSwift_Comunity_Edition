//
//  ViewController.swift  (macOS / AppKit)
//
//  Simple button-driven CRUD UI. No storyboard required.
//

import AppKit
// Only needed when the shared code is consumed as a SwiftPM library.
#if canImport(EncryptedStoreKit)
import EncryptedStoreKit
#endif

final class ViewController: NSViewController {

    private let crud = CRUDController()
    private let logView = NSTextView()

    override func loadView() {
        // Root container view.
        view = NSView(frame: NSRect(x: 0, y: 0, width: 560, height: 460))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        buildUI()
        appendLog("Encrypted Core Data store ready.\nDB: \(PersistenceController.shared.databaseURL.lastPathComponent)")
    }

    private func buildUI() {
        let buttonsDef: [(String, () -> String)] = [
            ("Create",      crud.createPerson),
            ("Read",        crud.readPeople),
            ("Update",      crud.updateFirstPerson),
            ("Tag Person",  crud.tagFirstPerson),
            ("Delete Last", crud.deleteLastPerson),
            ("Delete All",  crud.deleteAll),
            ("Count",       crud.count),
            ("Test SQL",    crud.runTestSQLScript)
        ]

        let buttonStack = NSStackView()
        buttonStack.orientation = .vertical
        buttonStack.alignment = .leading
        buttonStack.spacing = 8
        buttonStack.translatesAutoresizingMaskIntoConstraints = false

        for (titleText, action) in buttonsDef {
            let button = NSButton(title: titleText, target: self, action: #selector(buttonTapped(_:)))
            button.bezelStyle = .rounded
            button.identifier = NSUserInterfaceItemIdentifier(titleText)
            actions[titleText] = action
            buttonStack.addArrangedSubview(button)
            button.widthAnchor.constraint(equalToConstant: 140).isActive = true
        }

        // Scrollable, read-only log.
        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.borderType = .lineBorder
        logView.isEditable = false
        logView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        logView.autoresizingMask = [.width]
        scroll.documentView = logView

        view.addSubview(buttonStack)
        view.addSubview(scroll)

        NSLayoutConstraint.activate([
            buttonStack.topAnchor.constraint(equalTo: view.topAnchor, constant: 16),
            buttonStack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            buttonStack.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -16),

            scroll.topAnchor.constraint(equalTo: view.topAnchor, constant: 16),
            scroll.leadingAnchor.constraint(equalTo: buttonStack.trailingAnchor, constant: 16),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -16)
        ])
    }

    private var actions: [String: () -> String] = [:]

    @objc private func buttonTapped(_ sender: NSButton) {
        guard let id = sender.identifier?.rawValue, let action = actions[id] else { return }
        appendLog(action())
    }

    private func appendLog(_ text: String) {
        let stamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        logView.string = "[\(stamp)] \(text)\n\n" + logView.string
    }
}
