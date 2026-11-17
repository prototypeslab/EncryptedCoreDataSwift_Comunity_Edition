//
//  Tag.swift
//
//  A second entity in a many-to-many relationship with Person. This exercises
//  EncryptedStore's relation-table code paths (the `ecd_<a>_<b>` join tables,
//  handleUpdatedRelation, and many-to-many fetch SQL).
//

import Foundation
import CoreData

@objc(Tag)
public final class Tag: NSManagedObject {
    @NSManaged public var name: String?
    @NSManaged public var people: NSSet?
}

extension Tag {
    static let entityName = "Tag"

    @nonobjc public class func fetchRequest() -> NSFetchRequest<Tag> {
        return NSFetchRequest<Tag>(entityName: entityName)
    }

    @objc(addPeopleObject:)
    @NSManaged public func addToPeople(_ value: Person)

    @objc(removePeopleObject:)
    @NSManaged public func removeFromPeople(_ value: Person)
}
