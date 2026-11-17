//
//  CRUDController.swift
//
//  Platform-agnostic CRUD operations and a raw-SQL test, shared by the
//  UIKit (iOS) and AppKit (macOS) demo apps. Every method returns a human
//  readable log line so the UI can just print the result.
//

import Foundation
import CoreData

public final class CRUDController {

    private let context: NSManagedObjectContext
    private let coordinator: NSPersistentStoreCoordinator

    public init(persistence: PersistenceController = .shared) {
        self.context = persistence.context
        self.coordinator = persistence.coordinator
    }

    // MARK: - Create

    public func createPerson() -> String {
        let names = ["Ada", "Alan", "Grace", "Linus", "Margaret", "Dennis", "Barbara", "Ken"]
        let person = Person(context: context)
        person.name = names.randomElement()! + " #\(Int.random(in: 1...999))"
        person.age = Int64(Int.random(in: 18...80))
        person.createdAt = Date()
        do {
            try context.save()
            return "CREATE → inserted \(person.name ?? "?"), age \(person.age)"
        } catch {
            return "CREATE failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Read

    public func readPeople() -> String {
        let request = Person.fetchRequest()
        request.sortDescriptors = [NSSortDescriptor(key: "createdAt", ascending: true)]
        do {
            let people = try context.fetch(request)
            if people.isEmpty { return "READ → no rows yet. Tap Create." }
            let lines = people.map { p -> String in
                let tagNames = (p.tags as? Set<Tag>)?.compactMap { $0.name }.sorted() ?? []
                let tagText = tagNames.isEmpty ? "" : "  [\(tagNames.joined(separator: ", "))]"
                return "  • \(p.name ?? "?")  (age \(p.age))\(tagText)"
            }
            return "READ → \(people.count) row(s):\n" + lines.joined(separator: "\n")
        } catch {
            return "READ failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Update

    public func updateFirstPerson() -> String {
        let request = Person.fetchRequest()
        request.fetchLimit = 1
        request.sortDescriptors = [NSSortDescriptor(key: "createdAt", ascending: true)]
        do {
            guard let person = try context.fetch(request).first else {
                return "UPDATE → nothing to update. Tap Create first."
            }
            let oldAge = person.age
            person.age = Int64(Int.random(in: 18...99))
            person.name = (person.name ?? "?") + " (edited)"
            try context.save()
            return "UPDATE → \(person.name ?? "?")  age \(oldAge) → \(person.age)"
        } catch {
            return "UPDATE failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Delete

    public func deleteLastPerson() -> String {
        let request = Person.fetchRequest()
        request.sortDescriptors = [NSSortDescriptor(key: "createdAt", ascending: false)]
        request.fetchLimit = 1
        do {
            guard let person = try context.fetch(request).first else {
                return "DELETE → nothing to delete."
            }
            let name = person.name ?? "?"
            context.delete(person)
            try context.save()
            return "DELETE → removed \(name)"
        } catch {
            return "DELETE failed: \(error.localizedDescription)"
        }
    }

    public func deleteAll() -> String {
        do {
            let people = try context.fetch(Person.fetchRequest())
            people.forEach { context.delete($0) }
            let tags = try context.fetch(Tag.fetchRequest())
            tags.forEach { context.delete($0) }
            try context.save()
            return "DELETE ALL → removed \(people.count) person(s), \(tags.count) tag(s)"
        } catch {
            return "DELETE ALL failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Count (aggregate fetch)

    public func count() -> String {
        do {
            let people = try context.count(for: Person.fetchRequest())
            let tags = try context.count(for: Tag.fetchRequest())
            return "COUNT → \(people) person(s), \(tags) tag(s)"
        } catch {
            return "COUNT failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Relationships (many-to-many)

    /// Attaches a random tag to the oldest person, creating the tag if needed.
    /// Exercises the many-to-many WRITE path (relation table insert/update).
    public func tagFirstPerson() -> String {
        let palette = ["vip", "swift", "core-data", "encrypted", "demo", "alpha"]
        let request = Person.fetchRequest()
        request.fetchLimit = 1
        request.sortDescriptors = [NSSortDescriptor(key: "createdAt", ascending: true)]
        do {
            guard let person = try context.fetch(request).first else {
                return "TAG → no person yet. Tap Create first."
            }
            let tagName = palette.randomElement()!

            // Reuse an existing tag with that name or create a new one.
            let tagRequest = Tag.fetchRequest()
            tagRequest.predicate = NSPredicate(format: "name == %@", tagName)
            tagRequest.fetchLimit = 1
            let tag = try context.fetch(tagRequest).first ?? {
                let t = Tag(context: context)
                t.name = tagName
                return t
            }()

            person.addToTags(tag)
            try context.save()
            return "TAG → '\(tagName)' added to \(person.name ?? "?")"
        } catch {
            return "TAG failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Test SQL script
    //
    // Runs predicate-based fetches that EncryptedStore translates into raw SQL.
    // Includes relationship predicates so the many-to-many join / @count /
    // subquery code paths are exercised.

    public func runTestSQLScript() -> String {
        var lines: [String] = ["TEST SQL → running predicate-driven fetches:"]

        // 1) age > 50
        let r1 = Person.fetchRequest()
        r1.predicate = NSPredicate(format: "age > %d", 50)
        if let c = try? context.count(for: r1) {
            lines.append("  WHERE age > 50                  → \(c) row(s)")
        }

        // 2) name CONTAINS[cd] 'a'  (LIKE + STRIP_CASE_DIACRITICS)
        let r2 = Person.fetchRequest()
        r2.predicate = NSPredicate(format: "name CONTAINS[cd] %@", "a")
        if let c = try? context.count(for: r2) {
            lines.append("  WHERE name CONTAINS[cd] 'a'     → \(c) row(s)")
        }

        // 3) age BETWEEN {30,60}, sorted, limited
        let r3 = Person.fetchRequest()
        r3.predicate = NSPredicate(format: "age BETWEEN {30, 60}")
        r3.sortDescriptors = [NSSortDescriptor(key: "age", ascending: true)]
        r3.fetchLimit = 5
        if let rows = try? context.fetch(r3) {
            let detail = rows.map { "\($0.name ?? "?")=\($0.age)" }.joined(separator: ", ")
            lines.append("  WHERE age BETWEEN 30..60        → \(rows.count): \(detail)")
        }

        // 4) dictionary result type (projection)
        let r4 = NSFetchRequest<NSDictionary>(entityName: Person.entityName)
        r4.resultType = .dictionaryResultType
        r4.propertiesToFetch = ["name", "age"]
        r4.fetchLimit = 3
        if let dicts = try? context.fetch(r4) {
            lines.append("  SELECT name, age LIMIT 3        → \(dicts)")
        }

        // 5) RELATIONSHIP: people that have at least one tag  (@count subquery)
        let r5 = Person.fetchRequest()
        r5.predicate = NSPredicate(format: "tags.@count > 0")
        if let c = try? context.count(for: r5) {
            lines.append("  WHERE tags.@count > 0           → \(c) tagged person(s)")
        }

        // 6) RELATIONSHIP: people with a specific tag  (ANY ... join on relation table)
        let r6 = Person.fetchRequest()
        r6.predicate = NSPredicate(format: "ANY tags.name == %@", "swift")
        if let rows = try? context.fetch(r6) {
            let detail = rows.compactMap { $0.name }.joined(separator: ", ")
            lines.append("  WHERE ANY tags.name == 'swift'  → \(rows.count): \(detail)")
        }

        // 7) RELATIONSHIP (inverse): tags used by someone
        let r7 = Tag.fetchRequest()
        r7.predicate = NSPredicate(format: "people.@count > 0")
        if let rows = try? context.fetch(r7) {
            let detail = rows.compactMap { $0.name }.sorted().joined(separator: ", ")
            lines.append("  WHERE people.@count > 0 (Tag)   → \(rows.count): \(detail)")
        }

        return lines.joined(separator: "\n")
    }
}
