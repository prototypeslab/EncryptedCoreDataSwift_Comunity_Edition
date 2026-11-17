//
//  Person.swift
//
//  A tiny managed-object subclass used by the CRUD demo. The model is built
//  programmatically (see PersistenceController) so the project needs no
//  .xcdatamodeld file.
//

import Foundation
import CoreData

@objc(Person)
public final class Person: NSManagedObject {
    @NSManaged public var name: String?
    @NSManaged public var age: Int64
    @NSManaged public var createdAt: Date?
    /// Many-to-many relationship with Tag.
    @NSManaged public var tags: NSSet?
}

extension Person {
    static let entityName = "Person"

    @nonobjc public class func fetchRequest() -> NSFetchRequest<Person> {
        return NSFetchRequest<Person>(entityName: entityName)
    }

    @objc(addTagsObject:)
    @NSManaged public func addToTags(_ value: Tag)

    @objc(removeTagsObject:)
    @NSManaged public func removeFromTags(_ value: Tag)
}
