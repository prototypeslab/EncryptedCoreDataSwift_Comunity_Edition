//
//  PersistenceController.swift
//
//  Builds the Core Data stack on top of the ported `EncryptedStore`
//  (SQLCipher-backed). The managed object model is created in code so the
//  demo is fully self-contained.
//
//  The passphrase is generated once and stored in the Keychain (see
//  KeychainPassphrase) rather than hardcoded.
//

import Foundation
import CoreData
// When built as separate SwiftPM modules the engine lives in its own module.
// In a single Xcode target this module doesn't exist and the symbols are local.
#if canImport(EncryptedStore)
import EncryptedStore
#endif

public final class PersistenceController {

    public static let shared = PersistenceController()

    public let model: NSManagedObjectModel
    public let coordinator: NSPersistentStoreCoordinator
    public let context: NSManagedObjectContext

    /// On-disk location of the encrypted SQLite database.
    public let databaseURL: URL

    private init() {
        // Register the custom store type once.
        EncryptedStore.registerStoreClass()

        self.model = PersistenceController.makeModel()

        // --- Database location ---------------------------------------------
        let fm = FileManager.default
        let docs = (try? fm.url(for: .applicationSupportDirectory,
                                in: .userDomainMask,
                                appropriateFor: nil,
                                create: true))
            ?? fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
        databaseURL = docs.appendingPathComponent("CRUDDemo.sqlite")

        // --- Passphrase from the Keychain ----------------------------------
        let passphrase: String
        do {
            passphrase = try KeychainPassphrase.passphrase()
        } catch {
            fatalError("Could not obtain database passphrase from Keychain: \(error)")
        }

        // --- Add the encrypted store ---------------------------------------
        coordinator = NSPersistentStoreCoordinator(managedObjectModel: model)

        let options: [String: Any] = [
            EncryptedStorePassphraseKey: passphrase,
            NSMigratePersistentStoresAutomaticallyOption: true,
            NSInferMappingModelAutomaticallyOption: true
        ]

        do {
            try coordinator.addPersistentStore(ofType: EncryptedStoreType,
                                               configurationName: nil,
                                               at: databaseURL,
                                               options: options)
        } catch {
            fatalError("Failed to add encrypted store: \(error)")
        }

        context = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)
        context.persistentStoreCoordinator = coordinator
    }

    // MARK: - Programmatic model

    private static func makeModel() -> NSManagedObjectModel {
        // --- Person --------------------------------------------------------
        let person = NSEntityDescription()
        person.name = Person.entityName
        person.managedObjectClassName = NSStringFromClass(Person.self)

        let nameAttr = NSAttributeDescription()
        nameAttr.name = "name"
        nameAttr.attributeType = .stringAttributeType
        nameAttr.isOptional = true

        let ageAttr = NSAttributeDescription()
        ageAttr.name = "age"
        ageAttr.attributeType = .integer64AttributeType
        ageAttr.isOptional = false
        ageAttr.defaultValue = 0

        let createdAttr = NSAttributeDescription()
        createdAttr.name = "createdAt"
        createdAttr.attributeType = .dateAttributeType
        createdAttr.isOptional = true

        // --- Tag -----------------------------------------------------------
        let tag = NSEntityDescription()
        tag.name = Tag.entityName
        tag.managedObjectClassName = NSStringFromClass(Tag.self)

        let tagNameAttr = NSAttributeDescription()
        tagNameAttr.name = "name"
        tagNameAttr.attributeType = .stringAttributeType
        tagNameAttr.isOptional = true

        // --- Many-to-many relationship: Person.tags <-> Tag.people ---------
        let personToTags = NSRelationshipDescription()
        personToTags.name = "tags"
        personToTags.destinationEntity = tag
        personToTags.minCount = 0
        personToTags.maxCount = 0            // 0 == to-many
        personToTags.deleteRule = .nullifyDeleteRule

        let tagToPeople = NSRelationshipDescription()
        tagToPeople.name = "people"
        tagToPeople.destinationEntity = person
        tagToPeople.minCount = 0
        tagToPeople.maxCount = 0            // 0 == to-many
        tagToPeople.deleteRule = .nullifyDeleteRule

        personToTags.inverseRelationship = tagToPeople
        tagToPeople.inverseRelationship = personToTags

        person.properties = [nameAttr, ageAttr, createdAttr, personToTags]
        tag.properties = [tagNameAttr, tagToPeople]

        let model = NSManagedObjectModel()
        model.entities = [person, tag]
        return model
    }
}
