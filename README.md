# EncryptedStore (Swift) — Core Data + SQLCipher CRUD demo

A faithful **Swift port** of the Objective-C `EncryptedStore`
(`project-imas/encrypted-core-data`) — a custom `NSIncrementalStore` backed by
**SQLCipher** — plus two minimal, button-driven CRUD demo apps:

- **iOS / UIKit**
- **macOS / AppKit**

```
EncryptedCoreDataSwift/
├── Package.swift                   ← SwiftPM: builds the engine + shared as libraries
├── Engine/
│   └── EncryptedStore.swift        ← the full Swift port of EncryptedStore.h/.m
├── SQLCipher/
│   ├── module.modulemap            ← exposes SQLCipher to Swift as `import SQLCipher`
│   └── shim.h                      ← umbrella header (point at your sqlite3.h)
├── Shared/
│   ├── Person.swift                ← demo NSManagedObject (has many-to-many `tags`)
│   ├── Tag.swift                   ← second entity, many-to-many with Person
│   ├── KeychainPassphrase.swift    ← generates + stores the DB key in the Keychain
│   ├── PersistenceController.swift ← Core Data stack (programmatic model)
│   └── CRUDController.swift         ← Create / Read / Update / Delete / Count / Tag / Test SQL
├── iOS/
│   ├── AppDelegate.swift
│   └── ViewController.swift         ← buttons + log view
└── macOS/
    ├── AppDelegate.swift
    └── ViewController.swift         ← buttons + log view
```
## Packages:
https://github.com/sqlcipher/sqlcipher
https://github.com/stephencelis/SQLite.swift


## The data model

Built programmatically in `PersistenceController` — **no `.xcdatamodeld`**:

- **Person** — `name: String?`, `age: Int64`, `createdAt: Date?`, `tags` (to-many)
- **Tag** — `name: String?`, `people` (to-many)
- **Person.tags ⟷ Tag.people** is a **many-to-many** relationship, so the demo
  exercises EncryptedStore's relation-table paths (`ecd_people_tags` join table,
  `handleUpdatedRelation`, and the `@count` / `ANY ... ==` subquery SQL).

## SwiftPM (`Package.swift`)

Two library products: `EncryptedStore` (the engine) and `EncryptedStoreKit`
(the shared stack). The iOS/macOS folders are **not** SwiftPM products —
SwiftPM can't build app bundles — so add those to Xcode app targets that depend
on `EncryptedStoreKit`, or keep everything in one Xcode project (below). The
package does not link a SQLite binary; the consuming target must link the
commercial SQLCipher framework/static lib (see the SQLCipher section). Open it
with `open Package.swift` or `swift build` for a compile check of the non-UI
code.

> No hand-written `.xcodeproj` is included: a generated `pbxproj` is fragile and
> would likely break on your machine. Either open `Package.swift` in Xcode (it
> creates the project for you) or make a fresh App project and drag in the
> `Engine/`, `SQLCipher/`, `Shared/`, and the matching platform folder.

---

## What was ported

Everything in the 4,145-line `EncryptedStore.m` was translated, preserving the
original SQL generation and on-disk format:

- `NSIncrementalStore` overrides: `loadMetadata`, `execute(_:with:)`,
  `newValuesForObject`, `newValue(forRelationship:)`, `obtainPermanentIDs`,
  register/unregister, `type`.
- Factory helpers (`makeStore(options:...)`, struct-options, passcode variants).
- Passphrase handling — `sqlite3_key` / `sqlite3_rekey` and the embedded
  Zetetic commercial **`PRAGMA cipher_license`** (kept verbatim).
- Schema creation, indices, many-to-many relation tables, lightweight migration
  (`alterTable…`, `checkTableForMissingColumns`, …).
- Full predicate → SQL translation: compound/comparison predicates, `LIKE`
  escaping, `REGEXP`, `STRIP_CASE` / `STRIP_DIACRITICS` user functions,
  `@count` correlated subqueries, `@sum`, `length`, aggregates, joins.
- `CMDIncrementalStoreNode` and the `NSEntityDescription` `typeHash` helpers.

> ⚠️ **typeHash compatibility:** the port uses the **NSString** hash
> (`(name as NSString).hash`), exactly like the ObjC original, so the stored
> `__entityType` integers match byte-for-byte. Do **not** switch this to Swift's
> `String.hashValue` (it is randomized per launch).

---

## Setup — linking SQLCipher (commercial Zetetic)

This code calls `sqlite3_key`, `sqlite3_rekey`, and `PRAGMA cipher_license`,
which **only exist in a SQLCipher build** — not Apple's system `libsqlite3`.

1. **Add the SQLCipher source/library** from your Zetetic commercial package to
   the target (the amalgamation `sqlite3.c`/`sqlite3.h`, or the prebuilt
   framework/static lib).

2. **Compiler flags** (Build Settings → *Other C Flags* / preprocessor macros):
   ```
   -DSQLITE_HAS_CODEC=1
   -DSQLCIPHER_CRYPTO_CC          # use Apple CommonCrypto
   ```

3. **Expose the header to Swift.** Either:
   - Edit `SQLCipher/shim.h` so its `#import` points at the SQLCipher
     `sqlite3.h`, then add the `SQLCipher` folder to
     **Swift Compiler → Import Paths** (`SWIFT_INCLUDE_PATHS`); **or**
   - Add a bridging header that imports the SQLCipher `sqlite3.h` and change the
     top of `EncryptedStore.swift` from `import SQLCipher` to nothing (the
     symbols come in through the bridging header instead).

4. **Do NOT link `libsqlite3.tbd`.** If both are linked, the system SQLite can
   shadow SQLCipher's symbols and `sqlite3_key` becomes a no-op (database stays
   unencrypted). Link only the SQLCipher library.

5. **Verify encryption** once running: open `CRUDDemo.sqlite` from the app's
   Application Support directory with the *system* `sqlite3` CLI — it should
   report *"file is not a database"* (because it's encrypted). With the
   `sqlcipher` CLI + `PRAGMA key='...'` it should open normally.

### Quick compile check without SQLCipher
`swift build` on this package **compiles cleanly** (verified): the bundled
`SQLCipher/shim.h` falls back to the system `<sqlite3.h>` and declares
`sqlite3_key`/`sqlite3_rekey` itself, so all Swift compiles. Those symbols only
need to *resolve at link time*, which happens when you build the actual app
against the real SQLCipher binary. In other words: a green `swift build` proves
the Swift is correct; it does **not** mean the DB is encrypted — that depends on
linking SQLCipher in your app target as described above.

(Two intentional deprecation warnings remain — `NSKeyedArchiver.archivedData(withRootObject:)`
and `unarchiveObject(with:)` — kept because the metadata `plist` blob must stay
format-compatible with databases written by the original Objective-C store.)

---

## Creating the two app targets

The demo uses a **programmatic** Core Data model (see `PersistenceController`),
so there is **no `.xcdatamodeld` to add**.

**iOS target**
- Files: `Engine/`, `SQLCipher/`, `Shared/`, `iOS/`.
- `Info.plist`: remove *Main storyboard file base name* and the
  *Application Scene Manifest* (the app is launched from `AppDelegate`).

**macOS target**
- Files: `Engine/`, `SQLCipher/`, `Shared/`, `macOS/`.
- `Info.plist`: remove *Main nib file base name*; `@main AppDelegate` builds the
  window in code.
- If sandboxed, the DB lives in the app's container Application Support dir —
  no extra entitlement needed for that location.

Both targets share `Engine/` and `Shared/` verbatim.

---

## Using the apps

Each app shows a column of buttons and a log:

| Button       | Action                                                            |
|--------------|-------------------------------------------------------------------|
| **Create**   | Inserts a random `Person` and saves.                              |
| **Read**     | Fetches all people, sorted by creation date.                     |
| **Update**   | Edits the oldest person's name/age and saves.                    |
| **Tag Person** | Adds a random tag to the oldest person (many-to-many write).   |
| **Delete Last** | Deletes the most recently created person.                     |
| **Delete All**  | Deletes every person.                                          |
| **Count**    | `count(for:)` aggregate fetch.                                    |
| **Test SQL** | Runs predicate-driven fetches (`>`, `CONTAINS[cd]`, `BETWEEN`, dictionary projection, **plus relationship predicates** `tags.@count > 0`, `ANY tags.name == …`, inverse `people.@count > 0`) so you can see `EncryptedStore`'s SQL-generation — including the many-to-many join/subquery paths — exercised. Turn on `-com.apple.CoreData.SQLDebug 1` as a launch argument to print the generated SQL. |

---

## Programmatic API recap

```swift
// Register once at launch:
EncryptedStore.registerStoreClass()

// Add an encrypted store:
let options: [String: Any] = [
    EncryptedStorePassphraseKey: "your-passphrase",
    NSMigratePersistentStoresAutomaticallyOption: true,
    NSInferMappingModelAutomaticallyOption: true
]
try coordinator.addPersistentStore(ofType: EncryptedStoreType,
                                   configurationName: nil,
                                   at: databaseURL,
                                   options: options)

// Or via the factory helper:
let coordinator = EncryptedStore.makeStore(options: options, managedObjectModel: model)
```

### Passphrase & the Keychain

The passphrase is **no longer hardcoded**. `KeychainPassphrase` generates a
32-byte random key on first launch, base64-encodes it, and stores it as a
generic-password item protected with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (device-only, not synced).
`PersistenceController` reads it from there on every launch.

```swift
let passphrase = try KeychainPassphrase.passphrase()   // create-or-fetch
// ...
try KeychainPassphrase.reset()   // ⚠️ destroys access to the existing DB
```

> ⚠️ If the Keychain item is lost (e.g. `reset()`, or the app is uninstalled on
> iOS), the existing encrypted database can no longer be decrypted. For real
> apps consider a recovery strategy and/or a user-supplied passcode.

On **macOS**, Keychain access from a non-sandboxed dev build is fine; under the
App Sandbox the item lives in the app's keychain group — no extra entitlement is
needed for `kSecClassGenericPassword`.





1. Add the SQLCipher Community Edition binary to the project

Pick one approach:

• SPM (easiest): Add https://github.com/sqlcipher/sqlcipher as a Swift package, or use a community wrapper package that vends the compiled binary.
• CocoaPods: pod 'SQLCipher' in your Podfile.
• Manual amalgamation: Download sqlite3.c + sqlite3.h from zetetic.net, drag them into the Xcode target, and set the C flags on that file directly.

2. Update SQLCipher/shim.h􀰓

Change the #import <sqlite3.h> at line 11 to point at the SQLCipher community edition's sqlite3.h. For example, with CocoaPods it would be:
#import "sqlite3.h"

For a manual amalgamation, use a relative path to wherever you placed sqlite3.h.

3. Add the SQLCipher folder to Swift Import Paths

In Build Settings → Swift Compiler – Search Paths → Import Paths (SWIFT_INCLUDE_PATHS), add:

$(SRCROOT)/EncryptedCoreDataSwift/SQLCipher

4. Set compiler flags

In Build Settings → Other C Flags, add:
-DSQLITE_HAS_CODEC=1
-DSQLCIPHER_CRYPTO_CC

5. Remove libsqlite3.tbd from Link Binary With Libraries — if it's linked alongside SQLCipher, the system SQLite shadows sqlite3_key and encryption silently doesn't work.

6. Verify

After running, find the .sqlite file in the app's Application Support directory and open it with the system sqlite3 CLI — it should say "file is not a database", confirming it's encrypted.

⸻

The shim.h􀰓 and module.modulemap􀰓 are already in place and correctly structured — the main missing piece is the actual SQLCipher binary and the build settings wired up around it.
