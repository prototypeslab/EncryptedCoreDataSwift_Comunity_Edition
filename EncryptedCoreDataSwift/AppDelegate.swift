//
//  AppDelegate.swift  (macOS / AppKit)
//
//  Minimal programmatic app entry point — no storyboard.
//  Set "Principal class" = NSApplication and remove "Main nib file base name"
//  (NSMainNibFile) from Info.plist, then make this the @main entry point.
//

import AppKit
import Cocoa

struct DatabaseConfig {
    static let passphrase = "1234"
    //SQLCipher_4_16_0
    static let cipherLicense = ""  //Enter licence if you have comercial version of SQLCipher, otherwise leave it empty
//    static let databaseFileName = "ExitNext_encrypted.sqlite"
}

@main
final class AppDelegate: NSObject, NSApplicationDelegate {

    var window: NSWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        let contentRect = NSRect(x: 0, y: 0, width: 560, height: 460)
        window = NSWindow(contentRect: contentRect,
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered,
                          defer: false)
        window.title = "EncryptedStore CRUD"
        window.contentViewController = ViewController()
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}
