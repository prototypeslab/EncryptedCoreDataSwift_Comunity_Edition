//
//  EncryptedStore.swift
//
//  A faithful Swift port of the Objective-C `EncryptedStore`
//  (project-imas / encrypted-core-data) — a custom `NSIncrementalStore`
//  backed by SQLCipher Community Edition.
//
//  Original: Copyright 2012 - 2014 The MITRE Corporation, All Rights Reserved.
//  Swift port preserves the original behaviour and SQL generation.
//
//  Requirements:
//  -------------
//  This file calls `sqlite3_key` / `sqlite3_rekey`, which are only available
//  in a SQLCipher build, NOT in Apple's system SQLite. You must link the
//  SQLCipher Community Edition library (e.g. via CocoaPods or SPM) and expose
//  its headers to Swift as a module named `SQLCipher`
//  (see SQLCipher/module.modulemap in this project).
//

import Foundation
import CoreData
import SQLCipher   // ← SQLCipher Community Edition exposed as a module

// MARK: - SQLite helpers not imported into Swift

/// `SQLITE_TRANSIENT` tells SQLite to copy the bound bytes immediately.
/// The macro is not imported into Swift, so we recreate it.
nonisolated(unsafe) internal let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Lightweight logging shim replacing the ObjC `MDELog(...)` macro.
@inline(__always)
internal nonisolated func MDELog(_ items: Any...) {
    #if DEBUG
    print("[EncryptedStore]", items.map { "\($0)" }.joined(separator: " "))
    #endif
}

// MARK: - Public constants

public nonisolated let EncryptedStoreType            = "EncryptedStore"
public nonisolated let EncryptedStorePassphraseKey   = "EncryptedStorePassphrase"
public nonisolated let EncryptedStoreErrorDomain     = "EncryptedStoreErrorDomain"
public nonisolated let EncryptedStoreErrorMessageKey = "EncryptedStoreErrorMessage"
public nonisolated let EncryptedStoreDatabaseLocation = "EncryptedStoreDatabaseLocation"
public nonisolated let EncryptedStoreCacheSize       = "EncryptedStoreCacheSize"

private nonisolated let EncryptedStoreMetadataTableName = "meta"
private nonisolated let EncryptedStoreMetadataTableCheckVersionKey = "EncryptedStoreMetadataTableCheckVersion"
private nonisolated let kTableCheckVersion = 1

public struct EncryptedStoreOptions {
    public var passphrase: String?
    public var databaseLocation: String?
    public var cacheSize: Int?

    public nonisolated init(passphrase: String? = nil,
                databaseLocation: String? = nil,
                cacheSize: Int? = nil) {
        self.passphrase = passphrase
        self.databaseLocation = databaseLocation
        self.cacheSize = cacheSize
    }
}

public enum EncryptedStoreError: Int {
    case incorrectPasscode = 6000
    case migrationFailed   = 6001
}

// MARK: - Entity type-hash helpers (ported from NSEntityDescription (CMDTypeHash))

extension NSEntityDescription {

    /// Mirrors the ObjC `typeHash` which used `(long)self.name.hash`, i.e. the
    /// **NSString** hash. We deliberately use the NSString hash (not Swift's
    /// String.hashValue) so the stored `__entityType` integers match the ObjC
    /// store byte-for-byte.
    nonisolated var typeHash: Int {
        return (self.name! as NSString).hash
    }

    /// Recursively returns this entity's typeHash along with all subentities'.
    nonisolated var typeHashSubhierarchy: [NSNumber] {
        var hashes: [NSNumber] = [NSNumber(value: self.typeHash)]
        for sub in self.subentities {
            hashes.append(contentsOf: sub.typeHashSubhierarchy)
        }
        return hashes
    }

    /// Attributes declared directly on this entity (not on its superentity).
    nonisolated var directAttributesByName: [String: NSAttributeDescription]? {
        guard let superentity = self.superentity else { return nil }
        let superKeys = Set(superentity.attributesByName.keys)
        var dict: [String: NSAttributeDescription] = [:]
        for (key, obj) in self.attributesByName where !superKeys.contains(key) {
            dict[key] = obj
        }
        return dict
    }

    /// Relationships declared directly on this entity (not on its superentity).
    nonisolated var directRelationshipsByName: [String: NSRelationshipDescription]? {
        guard let superentity = self.superentity else { return nil }
        let superKeys = Set(superentity.relationshipsByName.keys)
        var dict: [String: NSRelationshipDescription] = [:]
        for (key, obj) in self.relationshipsByName where !superKeys.contains(key) {
            dict[key] = obj
        }
        return dict
    }
}

// MARK: - Custom incremental store node (ported from CMDIncrementalStoreNode)

final class CMDIncrementalStoreNode: NSIncrementalStoreNode {

    nonisolated(unsafe) var allProperties: [NSPropertyDescription] = []

    nonisolated override init() {
        super.init()
    }

    nonisolated override init(objectID: NSManagedObjectID, withValues values: [String: Any], version: UInt64) {
        super.init(objectID: objectID, withValues: values, version: version)
    }

    nonisolated init(objectID: NSManagedObjectID,
         values: [String: Any],
         version: UInt64,
         properties: [NSPropertyDescription]) {
        super.init(objectID: objectID, withValues: values, version: version)
        self.allProperties = properties
    }

    nonisolated func updateWithChangedValues(_ changedValues: [String: Any]) {
        var updateValues: [String: Any] = [:]
        updateValues.reserveCapacity(allProperties.count)
        for key in allProperties {
            autoreleasepool {
                let value = changedValues[key.name] ?? self.value(for: key)
                if let value = value, !(value is NSNull) {
                    updateValues[key.name] = value
                }
            }
        }
        self.update(withValues: updateValues, version: self.version + 1)
    }
}

// MARK: - Free-function SQLite user functions (REGEXP / STRIP_*)
// These must be plain C functions (no captured context) to be passed to
// sqlite3_create_function.

private nonisolated func dbsqliteRegExp(_ context: OpaquePointer?,
                            _ argc: Int32,
                            _ argv: UnsafeMutablePointer<OpaquePointer?>?) {
    var numberOfMatches = 0
    guard argc == 2, let argv = argv else {
        sqlite3_result_int(context, 0)
        return
    }
    var pattern: String?
    var string: String?
    if let p = sqlite3_value_text(argv[0]) {
        pattern = String(cString: p)
    }
    if let s = sqlite3_value_text(argv[1]) {
        string = String(cString: s)
    }
    if let pattern = pattern, let string = string,
       let regex = try? NSRegularExpression(pattern: pattern,
                                            options: .caseInsensitive) {
        numberOfMatches = regex.numberOfMatches(
            in: string, options: [],
            range: NSRange(location: 0, length: (string as NSString).length))
    }
    sqlite3_result_int(context, Int32(numberOfMatches))
}

private nonisolated func dbsqliteFold(_ context: OpaquePointer?,
                          _ argv: UnsafeMutablePointer<OpaquePointer?>?,
                          options: NSString.CompareOptions) {
    guard let argv = argv, let raw = sqlite3_value_text(argv[0]) else {
        sqlite3_result_text(context, nil, -1, nil)
        return
    }
    let folded = String(cString: raw).folding(options: options, locale: nil)
    sqlite3_result_text(context, folded, -1, SQLITE_TRANSIENT)
}

private nonisolated func dbsqliteStripCase(_ context: OpaquePointer?,
                               _ argc: Int32,
                               _ argv: UnsafeMutablePointer<OpaquePointer?>?) {
    dbsqliteFold(context, argv, options: .caseInsensitive)
}

private nonisolated func dbsqliteStripDiacritics(_ context: OpaquePointer?,
                                     _ argc: Int32,
                                     _ argv: UnsafeMutablePointer<OpaquePointer?>?) {
    dbsqliteFold(context, argv, options: .diacriticInsensitive)
}

private nonisolated func dbsqliteStripCaseDiacritics(_ context: OpaquePointer?,
                                         _ argc: Int32,
                                         _ argv: UnsafeMutablePointer<OpaquePointer?>?) {
    dbsqliteFold(context, argv, options: [.caseInsensitive, .diacriticInsensitive])
}

// MARK: - Small Array helper mirroring NSArray (EncryptedStoreAdditions)

private extension Array {
    /// Recursively flattens nested arrays.
    nonisolated func cmdFlatten() -> [Any] {
        var out: [Any] = []
        for obj in self {
            if let arr = obj as? [Any] {
                out.append(contentsOf: arr.cmdFlatten())
            } else {
                out.append(obj)
            }
        }
        return out
    }
}

private nonisolated func cmdArray(of object: Any, times: Int) -> [Any] {
    return Array(repeating: object, count: times)
}

// MARK: - EncryptedStore

public final class EncryptedStore: NSIncrementalStore {

    // database resources
    nonisolated(unsafe) private var database: OpaquePointer?

    // caches
    nonisolated(unsafe) private var objectIDCache: [String: NSNumber] = [:]
    nonisolated(unsafe) private var nodeCache: [NSManagedObjectID: CMDIncrementalStoreNode] = [:]
    nonisolated(unsafe) private var objectCountCache: [NSManagedObjectID: Int] = [:]
    nonisolated(unsafe) private var entityTypeCache: [NSNumber: NSEntityDescription] = [:]

    // MARK: Registration

    /// Registers the store class with Core Data. Call once at launch
    /// (Swift has no `+load`, so this must be invoked explicitly).
    public static func registerStoreClass() {
        NSPersistentStoreCoordinator.registerStoreClass(
            EncryptedStore.self, forStoreType: EncryptedStoreType)
    }

    // MARK: - Factory helpers

    @discardableResult
    public class func makeStore(options: [String: Any]?,
                                managedObjectModel objModel: NSManagedObjectModel) -> NSPersistentStoreCoordinator {
        var error: NSError?
        return makeStore(options: options, managedObjectModel: objModel, error: &error)
    }

    @discardableResult
    public class func makeStore(structOptions options: EncryptedStoreOptions,
                                managedObjectModel objModel: NSManagedObjectModel) -> NSPersistentStoreCoordinator {
        var error: NSError?
        return makeStore(structOptions: options, managedObjectModel: objModel, error: &error)
    }

    @discardableResult
    public class func makeStore(_ objModel: NSManagedObjectModel,
                                passcode: String?) -> NSPersistentStoreCoordinator {
        var error: NSError?
        return makeStore(objModel, passcode: passcode, error: &error)
    }

    @discardableResult
    public class func makeStore(options: [String: Any]?,
                                managedObjectModel objModel: NSManagedObjectModel,
                                error: inout NSError?) -> NSPersistentStoreCoordinator {
        let coordinator = NSPersistentStoreCoordinator(managedObjectModel: objModel)

        var backup = true
        var databaseURL: URL?
        if let dburl = options?[EncryptedStoreDatabaseLocation] {
            if let s = dburl as? String {
                databaseURL = URL(string: s)
                backup = false
            } else if let u = dburl as? URL {
                databaseURL = u
                backup = false
            }
        }

        if let databaseURL = databaseURL {
            var fileAttributes = options ?? [:]
            fileAttributes.removeValue(forKey: EncryptedStorePassphraseKey)
            fileAttributes.removeValue(forKey: EncryptedStoreDatabaseLocation)
            try? FileManager.default.setAttributes(
                fileAttributes as! [FileAttributeKey: Any],
                ofItemAtPath: databaseURL.absoluteString)
        }

        if backup {
            let dbName = (Bundle.main.infoDictionary?[kCFBundleNameKey as String] as? String) ?? "database"
            let fm = FileManager.default
            if let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).last {
                try? fm.createDirectory(at: docs, withIntermediateDirectories: false, attributes: nil)
                databaseURL = docs.appendingPathComponent(dbName + ".sqlite")
            }
        }

        do {
            try coordinator.addPersistentStore(ofType: EncryptedStoreType,
                                               configurationName: nil,
                                               at: databaseURL,
                                               options: options)
        } catch let e as NSError {
            error = e
            MDELog("Unable to add persistent store.")
            MDELog("Error:", e, e.userInfo, e.localizedDescription)
        }

        return coordinator
    }

    @discardableResult
    public class func makeStore(structOptions options: EncryptedStoreOptions,
                                managedObjectModel objModel: NSManagedObjectModel,
                                error: inout NSError?) -> NSPersistentStoreCoordinator {
        var newOptions: [String: Any] = [:]
        if let pass = options.passphrase {
            newOptions[EncryptedStorePassphraseKey] = pass
        }
        if let loc = options.databaseLocation {
            newOptions[EncryptedStoreDatabaseLocation] = loc
        }
        if let cache = options.cacheSize {
            newOptions[EncryptedStoreCacheSize] = NSNumber(value: cache)
        }
        return makeStore(options: newOptions, managedObjectModel: objModel, error: &error)
    }

    @discardableResult
    public class func makeStore(_ objModel: NSManagedObjectModel,
                                passcode: String?,
                                error: inout NSError?) -> NSPersistentStoreCoordinator {
        let options: [String: Any]? = passcode.map { [EncryptedStorePassphraseKey: $0] }
        return makeStore(options: options, managedObjectModel: objModel, error: &error)
    }

    // MARK: - Incremental store lifecycle

    nonisolated public override init(persistentStoreCoordinator root: NSPersistentStoreCoordinator?,
                                     configurationName name: String?,
                                     at url: URL,
                                     options: [AnyHashable: Any]?) {
        super.init(persistentStoreCoordinator: root,
                   configurationName: name,
                   at: url,
                   options: options)
        if let model = root?.managedObjectModel {
            for entity in model.entities(forConfigurationName: name) ?? [] {
                if entityNeedsEntityTypeColumn(entity) {
                    entityTypeCache[NSNumber(value: entity.typeHash)] = entity
                }
            }
        }
        database = nil
    }

    deinit {
        sqlite3_close(database)
        database = nil
    }

    private nonisolated var storeEntities: [NSEntityDescription] {
        return persistentStoreCoordinator?.managedObjectModel
            .entities(forConfigurationName: configurationName) ?? []
    }

    nonisolated public override func obtainPermanentIDs(for array: [NSManagedObject]) throws -> [NSManagedObjectID] {
        var objectIDs: [NSManagedObjectID] = []
        objectIDs.reserveCapacity(array.count)
        for obj in array {
            var objectID = obj.objectID
            if objectID.isTemporaryID {
                let entity = obj.entity
                let table = tableNameForEntity(entity)
                guard let value = maximumObjectID(inTable: table) else {
                    throw databaseError() ?? genericError()
                }
                objectID = newObjectID(for: entity, referenceObject: value)
            }
            objectIDs.append(objectID)
        }
        return objectIDs
    }

    nonisolated public override func execute(_ request: NSPersistentStoreRequest,
                                             with context: NSManagedObjectContext?) throws -> Any {
        if request.requestType == .fetchRequestType {
            return try executeFetchRequest(request as! NSFetchRequest<NSFetchRequestResult>,
                                           with: context)
        } else if request.requestType == .saveRequestType {
            return try handleSaveChangesRequest(request as! NSSaveChangesRequest)
        }
        return []
    }

    private nonisolated func executeFetchRequest(_ fetchRequest: NSFetchRequest<NSFetchRequestResult>,
                                     with context: NSManagedObjectContext?) throws -> Any {
        let entity = fetchRequest.entity!
        let type = fetchRequest.resultType
        var results: [Any] = []
        let joinStatement = getJoinClause(fetchRequest, withPredicate: fetchRequest.predicate, initial: true)

        let table = tableNameForEntity(entity)
        let condition = whereClause(with: fetchRequest)
        let ordering = orderClause(fetchRequest, forEntity: entity)
        var limit = fetchRequest.fetchLimit > 0 ? " LIMIT \(fetchRequest.fetchLimit)" : ""
        if fetchRequest.fetchOffset > 0 {
            let offset = " OFFSET \(fetchRequest.fetchOffset)"
            limit = limit.isEmpty ? offset : limit + offset
        }
        let isDistinctFetchEnabled = fetchRequest.returnsDistinctResults
        let shouldFetchEntityType = entityNeedsEntityTypeColumn(entity) && !isDistinctFetchEnabled

        let conditionQuery = (condition["query"] as? String) ?? ""
        let orderQuery = (ordering["order"] as? String) ?? ""

        if type == .managedObjectResultType || type == .managedObjectIDResultType {
            var string = "SELECT \(isDistinctFetchEnabled ? "DISTINCT " : "")\(table).__objectID"
                + (shouldFetchEntityType ? ", \(table).__entityType" : "")
                + " FROM \(table) \(joinStatement)\(conditionQuery)\(orderQuery)\(limit);"

            if let endHavingRange = string.range(of: "END_HAVING"),
               let havingRange = string.range(of: "HAVING") {
                let substr = String(string[havingRange.lowerBound..<endHavingRange.lowerBound])
                let tail = String(string[endHavingRange.upperBound...])
                let groupHaving = " GROUP BY \(table).__objectID \(substr) \(tail)"
                string = "SELECT \(isDistinctFetchEnabled ? "DISTINCT " : "")\(table).__objectID"
                    + (shouldFetchEntityType ? ", \(table).__entityType" : "")
                    + " FROM \(table) \(joinStatement)\(groupHaving)\(orderQuery)\(limit);"
            }

            let statement = preparedStatement(for: string)
            bindWhereClause(condition, to: statement)
            while sqlite3_step(statement) == SQLITE_ROW {
                let primaryKey = sqlite3_column_int64(statement, 0)
                var entityToFetch: NSEntityDescription? = nil
                if shouldFetchEntityType {
                    let entityType = sqlite3_column_int64(statement, 1)
                    entityToFetch = entityTypeCache[NSNumber(value: entityType)]
                }
                if entityToFetch == nil { entityToFetch = entity }
                let objectID = newObjectID(for: entityToFetch!, referenceObject: NSNumber(value: primaryKey))
                if type == .managedObjectIDResultType {
                    results.append(objectID)
                } else if let context = context {
                    results.append(context.object(with: objectID))
                }
            }
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                throw databaseError() ?? genericError()
            }
        }

        if type == .dictionaryResultType,
           let propertiesToFetch = fetchRequest.propertiesToFetch, !propertiesToFetch.isEmpty {
            let propsString = columnsClause(withProperties: propertiesToFetch)
            let string = "SELECT \(isDistinctFetchEnabled ? "DISTINCT " : "")\(propsString) FROM \(table) \(joinStatement)\(conditionQuery)\(orderQuery)\(limit);"
            let statement = preparedStatement(for: string)
            bindWhereClause(condition, to: statement)
            while sqlite3_step(statement) == SQLITE_ROW {
                var singleResult: [String: Any] = [:]
                for (idx, property) in propertiesToFetch.enumerated() {
                    if let prop = property as? NSPropertyDescription,
                       let value = valueForProperty(prop, in: statement, atIndex: Int32(idx), withEntity: entity) {
                        singleResult[prop.name] = value
                    }
                }
                results.append(singleResult)
            }
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                throw databaseError() ?? genericError()
            }
        } else if type == .countResultType {
            let string = "SELECT COUNT(*) FROM \(table) \(joinStatement)\(conditionQuery)\(limit);"
            let statement = preparedStatement(for: string)
            bindWhereClause(condition, to: statement)
            if sqlite3_step(statement) == SQLITE_ROW {
                let count = sqlite3_column_int64(statement, 0)
                results.append(NSNumber(value: count))
            }
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                throw databaseError() ?? genericError()
            }
        }

        return results
    }

    nonisolated public override func newValuesForObject(with objectID: NSManagedObjectID,
                                                        with context: NSManagedObjectContext) throws -> NSIncrementalStoreNode {
        if let node = nodeCache[objectID] { return node }

        let entity = objectID.entity
        var columns: [String] = []
        var keys: [String] = []
        var typeJoins: [String] = []
        var entityTypes = Set<String>()
        let primaryKey = (referenceObject(for: objectID) as! NSNumber).uint64Value
        let table = tableNameForEntity(entity)

        let properties = entity.propertiesByName
        var tableAliasIndex = 0
        for (key, obj) in properties {
            if obj.isTransient { continue }
            if obj is NSAttributeDescription {
                columns.append("\(table).\(key)")
                keys.append(key)
            } else if let relationship = obj as? NSRelationshipDescription {
                let destinationEntity = relationship.destinationEntity
                if !relationship.isToMany {
                    let column = foreignKeyColumn(for: relationship)
                    columns.append("\(table).\(column)")
                    keys.append(key)
                    if let destinationEntity = destinationEntity, entityNeedsEntityTypeColumn(destinationEntity) {
                        let destinationTable = tableNameForEntity(destinationEntity)
                        let destinationAlias = "t\(tableAliasIndex)"
                        tableAliasIndex += 1
                        columns.append("\(destinationAlias).__entityType")
                        let join = " LEFT JOIN \(destinationTable) as \(destinationAlias) ON \(destinationAlias).__objectid=\(table).\(column)"
                        typeJoins.append(join)
                        entityTypes.insert(key)
                    }
                }
            }
        }

        let string = "SELECT \(columns.joined(separator: ", ")) FROM \(table)\(typeJoins.joined()) WHERE \(table).__objectid=?;"
        let statement = preparedStatement(for: string)
        sqlite3_bind_int64(statement, 1, Int64(bitPattern: primaryKey))

        if sqlite3_step(statement) == SQLITE_ROW {
            var dictionary: [String: Any] = [:]
            var allProperties: [NSPropertyDescription] = []
            var offset: Int32 = 0
            for (idx, obj) in keys.enumerated() {
                let property = properties[obj]!
                let value = valueForProperty(property, in: statement, atIndex: Int32(idx) + offset, withEntity: entity)
                if entityTypes.contains(obj) { offset += 1 }
                if let value = value { dictionary[obj] = value }
                allProperties.append(property)
            }
            sqlite3_finalize(statement)
            let node = CMDIncrementalStoreNode(objectID: objectID,
                                               values: dictionary,
                                               version: 1,
                                               properties: allProperties)
            nodeCache[objectID] = node
            return node
        } else {
            sqlite3_finalize(statement)
            throw databaseError() ?? genericError()
        }
    }

    nonisolated public override func newValue(forRelationship relationship: NSRelationshipDescription,
                                              forObjectWith objectID: NSManagedObjectID,
                                              with context: NSManagedObjectContext?) throws -> Any {
        let key = (referenceObject(for: objectID) as! NSNumber).uint64Value
        let sourceEntity = objectID.entity
        let inverseRelationship = relationship.inverseRelationship
        let destinationEntity = relationship.destinationEntity!
        var statement: OpaquePointer?

        let shouldFetchDestinationEntityType = entityNeedsEntityTypeColumn(destinationEntity)

        if !relationship.isToMany {
            // to-one: foreign key in source table
            let string = "SELECT \(foreignKeyColumn(for: relationship))"
                + (shouldFetchDestinationEntityType ? ", __entityType" : "")
                + " FROM \(tableNameForEntity(sourceEntity)) WHERE __objectID=?"
            statement = preparedStatement(for: string)
            sqlite3_bind_int64(statement, 1, Int64(bitPattern: key))
        } else if relationship.isToMany, let inverseRelationship = inverseRelationship, inverseRelationship.isToMany {
            // many-to-many: foreign key in relation table
            var firstID = "", secondID = "", firstOrder = "", secondOrder = ""
            let firstColumnIsSource = relationships(relationship,
                                                    firstIDColumn: &firstID,
                                                    secondIDColumn: &secondID,
                                                    firstOrderColumn: &firstOrder,
                                                    secondOrderColumn: &secondOrder)
            let relationTable = tableNameForRelationship(relationship)
            var sourceIDColumn = firstColumnIsSource ? firstID : secondID
            var destinationIDColumn = firstColumnIsSource ? secondID : firstID

            var join = ""
            var destinationTypeColumn = ""
            if shouldFetchDestinationEntityType {
                let destinationTable = tableNameForEntity(destinationEntity)
                destinationTypeColumn = ", \(destinationTable).__entityType"
                join = " INNER JOIN \(destinationTable) ON \(destinationTable).__objectid=\(relationTable).\(destinationIDColumn)"
                sourceIDColumn = "\(relationTable).\(sourceIDColumn)"
                destinationIDColumn = "\(relationTable).\(destinationIDColumn)"
            }
            let orderColumn = firstColumnIsSource ? secondOrder : firstOrder
            let string = "SELECT \(destinationIDColumn)\(destinationTypeColumn) FROM \(relationTable)\(join) WHERE \(sourceIDColumn)=? ORDER BY \(orderColumn) ASC"
            statement = preparedStatement(for: string)
            sqlite3_bind_int64(statement, 1, Int64(bitPattern: key))
        } else {
            // one-to-many: foreign key in destination table
            let destinationTable = tableNameForEntity(destinationEntity)
            let typeFilter = shouldFetchDestinationEntityType
                ? "__entityType IN (\(destinationEntity.typeHashSubhierarchy.map { "\($0)" }.joined(separator: ", ")))"
                : "1==1"
            let string = "SELECT __objectID"
                + (shouldFetchDestinationEntityType ? ", __entityType" : "")
                + " FROM \(destinationTable) WHERE \(typeFilter) AND \(foreignKeyColumn(for: inverseRelationship!))=? ORDER BY \(inverseRelationship!.name)_order ASC"
            statement = preparedStatement(for: string)
            sqlite3_bind_int64(statement, 1, Int64(bitPattern: key))
        }

        var objectIDs: [NSManagedObjectID] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            if sqlite3_column_type(statement, 0) != SQLITE_NULL {
                let value = NSNumber(value: sqlite3_column_int64(statement, 0))
                var resolvedDestinationEntity: NSEntityDescription? = nil
                if shouldFetchDestinationEntityType {
                    let entityType = sqlite3_column_int64(statement, 1)
                    resolvedDestinationEntity = entityTypeCache[NSNumber(value: entityType)]
                }
                if resolvedDestinationEntity == nil { resolvedDestinationEntity = destinationEntity }
                let oid = newObjectID(for: resolvedDestinationEntity!, referenceObject: value)
                objectIDs.append(oid)
            }
        }

        if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
            throw databaseError() ?? genericError()
        }

        if relationship.isToMany {
            return objectIDs
        } else if objectIDs.isEmpty {
            return NSNull()
        } else {
            return objectIDs.last!
        }
    }

    nonisolated public override func managedObjectContextDidRegisterObjects(with objectIDs: [NSManagedObjectID]) {
        for obj in objectIDs {
            objectCountCache[obj, default: 0] += 1
        }
    }

    nonisolated public override func managedObjectContextDidUnregisterObjects(with objectIDs: [NSManagedObjectID]) {
        for obj in objectIDs {
            if let value = objectCountCache[obj] {
                let newValue = value - 1
                if newValue == 0 {
                    objectCountCache.removeValue(forKey: obj)
                    nodeCache.removeValue(forKey: obj)
                } else {
                    objectCountCache[obj] = newValue
                }
            }
        }
    }

    nonisolated public override var type: String { return EncryptedStoreType }

    // MARK: - Metadata helpers

    nonisolated public override func loadMetadata() throws {
        let path = self.url!.path
        if sqlite3_open(path, &database) == SQLITE_OK {
//            applyCipherLicense()
            // passphrase
            var err: NSError?
            if !configureDatabasePassphrase(&err) {
                sqlite3_close(database); database = nil
                throw err ?? genericError()
            }
            if !configureDatabaseCacheSize() {
                let e = databaseError()
                sqlite3_close(database); database = nil
                throw e ?? genericError()
            }

            // optional VACUUM
            if let vacuum = options?[NSSQLiteManualVacuumOption] as? Bool, vacuum {
                var errorMessage: UnsafeMutablePointer<CChar>? = nil
                if sqlite3_exec(database, "VACUUM;", nil, nil, &errorMessage) != SQLITE_OK {
                    if let errorMessage = errorMessage {
                        MDELog("Failed to invoke VACUUM:", String(cString: errorMessage))
                        sqlite3_free(errorMessage)
                    } else {
                        MDELog("Failed to invoke VACUUM.")
                    }
                }
            }

            var thrownError: NSError?
            let success = performInTransaction {
                // make 'LIKE' case-sensitive
                let setPragma = self.preparedStatement(for: "PRAGMA case_sensitive_like = true;")
                if setPragma == nil || sqlite3_step(setPragma) != SQLITE_DONE || sqlite3_finalize(setPragma) != SQLITE_OK {
                    return false
                }

                // register user functions
                let det = SQLITE_UTF8 | SQLITE_DETERMINISTIC
                sqlite3_create_function(self.database, "REGEXP", 2, det, nil, dbsqliteRegExp, nil, nil)
                sqlite3_create_function(self.database, "STRIP_CASE", 1, det, nil, dbsqliteStripCase, nil, nil)
                sqlite3_create_function(self.database, "STRIP_DIACRITICS", 1, det, nil, dbsqliteStripDiacritics, nil, nil)
                sqlite3_create_function(self.database, "STRIP_CASE_DIACRITICS", 1, det, nil, dbsqliteStripCaseDiacritics, nil, nil)

                var hasTable = false
                do {
                    try self.checkMetadataTable(&hasTable)
                } catch let e as NSError { thrownError = e; return false }

                if hasTable {
                    // load metadata
                    var metadata: [String: Any]? = nil
                    let string = "SELECT plist FROM \(EncryptedStoreMetadataTableName) LIMIT 1;"
                    let statement = self.preparedStatement(for: string)
                    if statement != nil && sqlite3_step(statement) == SQLITE_ROW {
                        if let bytes = sqlite3_column_blob(statement, 0) {
                            let length = Int(sqlite3_column_bytes(statement, 0))
                            let data = Data(bytes: bytes, count: length)
                            metadata = try? NSKeyedUnarchiver.unarchivedObject(ofClasses: [NSDictionary.self, NSString.self, NSNumber.self, NSArray.self, NSData.self, NSDate.self, NSURL.self], from: data) as? [String: Any]
                            if let metadata = metadata { self.metadata = metadata }
                        }
                    } else {
                        thrownError = self.databaseError()
                        sqlite3_finalize(statement)
                        return false
                    }
                    sqlite3_finalize(statement)

                    // migrations
                    if let opts = self.options,
                       (opts[NSMigratePersistentStoresAutomaticallyOption] as? Bool) == true,
                       (opts[NSInferMappingModelAutomaticallyOption] as? Bool) == true,
                       let metadata = metadata {

                        if ((metadata[EncryptedStoreMetadataTableCheckVersionKey] as? NSNumber)?.intValue ?? 0) < kTableCheckVersion {
                            do {
                                try self.checkTableForMissingColumns(metadata)
                            } catch let e as NSError { thrownError = e; return false }
                            var mutableMetadata = metadata
                            mutableMetadata[EncryptedStoreMetadataTableCheckVersionKey] = NSNumber(value: kTableCheckVersion)
                            self.metadata = mutableMetadata
                            if !self.saveMetadata() {
                                thrownError = self.databaseError(); return false
                            }
                        }

                        let newModel = self.persistentStoreCoordinator!.managedObjectModel
                        if newModel.isConfiguration(withName: nil, compatibleWithStoreMetadata: metadata) {
                            return true
                        }
                        let bundles = [Bundle.main]
                        let oldModel = NSManagedObjectModel.mergedModel(from: bundles, forStoreMetadata: metadata)
                        if let oldModel = oldModel {
                            if (oldModel.entityVersionHashesByName as NSDictionary)
                                .isEqual(to: newModel.entityVersionHashesByName) {
                                return true
                            }
                            do {
                                try self.migrate(from: oldModel, to: newModel)
                            } catch let e as NSError { thrownError = e; return false }
                            var mutableMetadata = metadata
                            mutableMetadata[NSStoreModelVersionHashesKey] = newModel.entityVersionHashesByName
                            self.metadata = mutableMetadata
                            if !self.saveMetadata() {
                                thrownError = self.databaseError(); return false
                            }
                        } else {
                            MDELog("Failed to create NSManagedObject models for migration.")
                            thrownError = NSError(domain: EncryptedStoreErrorDomain,
                                                  code: EncryptedStoreError.migrationFailed.rawValue,
                                                  userInfo: [EncryptedStoreErrorMessageKey: "Missing old model, cannot migrate database"])
                            return false
                        }
                    }
                } else {
                    // new store: create metadata table
                    let string = "CREATE TABLE \(EncryptedStoreMetadataTableName)(plist);"
                    let statement = self.preparedStatement(for: string)
                    sqlite3_step(statement)
                    if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                        thrownError = self.databaseError(); return false
                    }
                    do {
                        try self.initializeDatabase()
                    } catch let e as NSError { thrownError = e; return false }

                    let newMetadata: [String: Any] = [
                        NSStoreUUIDKey: EncryptedStore.identifierForNewStore(at: self.url!),
                        NSStoreTypeKey: self.type
                    ]
                    self.metadata = newMetadata
                    if !self.saveMetadata() {
                        thrownError = self.databaseError(); return false
                    }
                }
                return true
            }

            if success { return }
            if let thrownError = thrownError { throw thrownError }
        }

        sqlite3_close(database); database = nil
        throw databaseError() ?? genericError()
    }

    private nonisolated func checkMetadataTable(_ hasTable: inout Bool) throws {
        try checkTable(&hasTable, withName: EncryptedStoreMetadataTableName)
    }

    @discardableResult
    private nonisolated func saveMetadata() -> Bool {
        // delete
        var string = "DELETE FROM \(EncryptedStoreMetadataTableName);"
        var statement = preparedStatement(for: string)
        sqlite3_step(statement)
        if statement == nil || sqlite3_finalize(statement) != SQLITE_OK { return false }

        // insert
        string = "INSERT INTO \(EncryptedStoreMetadataTableName) (plist) VALUES(?);"
        statement = preparedStatement(for: string)
        let metadataValue = self.metadata ?? [:]
        guard let data = try? NSKeyedArchiver.archivedData(withRootObject: metadataValue, requiringSecureCoding: false) else { return false }
        _ = data.withUnsafeBytes { raw in
            sqlite3_bind_blob(statement, 1, raw.baseAddress, Int32(data.count), SQLITE_TRANSIENT)
        }
        sqlite3_step(statement)
        if statement == nil || sqlite3_finalize(statement) != SQLITE_OK { return false }
        return true
    }

    // MARK: - Passphrase

    @discardableResult
    public nonisolated func configureDatabasePassphrase(_ error: inout NSError?) -> Bool {
        let passphrase = options?[EncryptedStorePassphraseKey] as? String
        return setDatabasePassphrase(passphrase, error: &error)
    }

    @discardableResult
    public nonisolated func checkDatabaseStatus(_ error: inout NSError?) -> Bool {
        let status = sqlite3_exec(database, "SELECT count(*) FROM sqlite_master;", nil, nil, nil)
        let result = status == SQLITE_OK
        if !result {
            var userInfo: [String: Any] = [NSLocalizedDescriptionKey: "Incorrect passcode !!!!! "]
            if let underlying = databaseError() { userInfo[NSUnderlyingErrorKey] = underlying }
            error = NSError(domain: EncryptedStoreErrorDomain,
                            code: EncryptedStoreError.incorrectPasscode.rawValue,
                            userInfo: userInfo)
        }
        return result && (error == nil)
    }

    @discardableResult
    public nonisolated func changeDatabasePassphrase(_ passphrase: String?, error: inout NSError?) -> Bool {
        var status: Int32 = SQLITE_OK
        if let passphrase = passphrase, !passphrase.isEmpty {
            status = passphrase.withCString { cstr in
                sqlite3_rekey(database, cstr, Int32(strlen(cstr)))
            }
        }
        var result = status == SQLITE_OK
        if result { result = checkDatabaseStatus(&error) }
        return result && (error == nil)
    }

    @discardableResult
    public nonisolated func setDatabasePassphrase(_ passphrase: String?, error: inout NSError?) -> Bool {
        var status: Int32 = SQLITE_OK
        if let passphrase = passphrase, !passphrase.isEmpty {
            status = passphrase.withCString { cstr in
                sqlite3_key(database, cstr, Int32(strlen(cstr)))
            }
            if status != SQLITE_OK { MDELog("Failed to key database") }
        }
        var result = status == SQLITE_OK
        if result { result = checkDatabaseStatus(&error) }
        return result && (error == nil)
    }

    @discardableResult
    public nonisolated func validateDatabasePassphrase(_ passphrase: String?, error: inout NSError?) -> Bool {
        var status = sqlite3_close(database)
        var result = status == SQLITE_OK
        if result {
            status = sqlite3_open(url!.path, &database)
            result = status == SQLITE_OK
            if result {
                result = setDatabasePassphrase(passphrase, error: &error)
            } else {
                var userInfo: [String: Any] = [NSLocalizedDescriptionKey: "Could not open database :("]
                if let underlying = databaseError() { userInfo[NSUnderlyingErrorKey] = underlying }
                error = NSError(domain: EncryptedStoreErrorDomain,
                                code: EncryptedStoreError.incorrectPasscode.rawValue,
                                userInfo: userInfo)
                sqlite3_close(database); database = nil
            }
        } else {
            var userInfo: [String: Any] = [NSLocalizedDescriptionKey: "Could not close database :("]
            if let underlying = databaseError() { userInfo[NSUnderlyingErrorKey] = underlying }
            error = NSError(domain: EncryptedStoreErrorDomain,
                            code: EncryptedStoreError.incorrectPasscode.rawValue,
                            userInfo: userInfo)
        }
        return result && (error == nil)
    }

    @discardableResult
    public nonisolated func changeDatabasePassphrase(_ oldPassphrase: String?,
                                         toNewPassphrase newPassphrase: String?,
                                         error: inout NSError?) -> Bool {
        var result = setDatabasePassphrase(oldPassphrase, error: &error)
        if result { result = changeDatabasePassphrase(newPassphrase, error: &error) }
        return result && (error == nil)
    }

    @discardableResult
    private nonisolated func configureDatabaseCacheSize() -> Bool {
        guard let cacheSize = options?[EncryptedStoreCacheSize] as? NSNumber else { return true }
        let string = "PRAGMA cache_size = \(cacheSize.intValue);"
        let statement = preparedStatement(for: string)
        sqlite3_step(statement)
        if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
            MDELog("Error: statement is NULL or could not be finalized")
            return false
        }
        return true
    }

    // MARK: - Migration helpers

    private nonisolated func migrate(from fromModel: NSManagedObjectModel,
                         to toModel: NSManagedObjectModel) throws {
        var success = true
        let mappingModel = try NSMappingModel.inferredMappingModel(forSourceModel: fromModel,
                                                                   destinationModel: toModel)
        let sourceEntities = fromModel.entitiesByName
        let destinationEntities = toModel.entitiesByName

        var removedRootEntities = Set<NSEntityDescription>()
        var updatedRootEntities = Set<NSEntityDescription>()

        var thrown: NSError?

        // root entities first
        for entityMapping in mappingModel.entityMappings {
            if !success { break }
            let sourceEntity = entityMapping.sourceEntityName.flatMap { sourceEntities[$0] }
            let destinationEntity = entityMapping.destinationEntityName.flatMap { destinationEntities[$0] }
            if sourceEntity?.superentity != nil || destinationEntity?.superentity != nil { continue }

            switch entityMapping.mappingType {
            case .addEntityMappingType:
                if let destinationEntity = destinationEntity {
                    do { try createTable(for: destinationEntity) } catch let e as NSError { thrown = e; success = false }
                    updatedRootEntities.insert(destinationEntity)
                }
            case .removeEntityMappingType:
                if let sourceEntity = sourceEntity {
                    success = dropTable(for: sourceEntity) && success
                    removedRootEntities.insert(sourceEntity)
                }
            case .transformEntityMappingType:
                if let sourceEntity = sourceEntity, let destinationEntity = destinationEntity {
                    do {
                        try alterTable(forSourceEntity: sourceEntity, destinationEntity: destinationEntity, withMapping: entityMapping)
                        try alterRelationship(forSourceEntity: sourceEntity, destinationEntity: destinationEntity, withMapping: entityMapping)
                    } catch let e as NSError { thrown = e; success = false }
                    updatedRootEntities.insert(destinationEntity)
                }
            default:
                break
            }
        }

        // subentities second
        for entityMapping in mappingModel.entityMappings {
            if !success { break }
            guard let sourceEntity = entityMapping.sourceEntityName.flatMap({ sourceEntities[$0] }),
                  let destinationEntity = entityMapping.destinationEntityName.flatMap({ destinationEntities[$0] }) else { continue }
            if !(sourceEntity.superentity != nil || destinationEntity.superentity != nil) { continue }

            switch entityMapping.mappingType {
            case .addEntityMappingType:
                let destRootEntityName = rootForEntity(destinationEntity).name!
                guard let destRootEntity = destinationEntities[destRootEntityName] else { continue }
                if updatedRootEntities.contains(destRootEntity) { continue }
                updatedRootEntities.insert(destRootEntity)
                let srcRootEntity = sourceEntities[destRootEntity.name!]
                if let srcRootEntity = srcRootEntity {
                    do {
                        try alterTable(forSourceEntity: srcRootEntity, destinationEntity: destinationEntity, withMapping: nil)
                    } catch let e as NSError { thrown = e; success = false; break }
                }
                if let directRels = destinationEntity.directRelationshipsByName {
                    for (_, rel) in directRels {
                        let tableName = tableNameForRelationship(rel)
                        var hasTable = false
                        do { try checkTable(&hasTable, withName: tableName) } catch let e as NSError { thrown = e; success = false; break }
                        if !hasTable {
                            do { try createTable(forRelationship: rel) } catch let e as NSError { thrown = e; success = false; break }
                        }
                    }
                }
            case .removeEntityMappingType:
                let srcRootEntityName = rootForEntity(sourceEntity).name!
                guard let srcRootEntity = sourceEntities[srcRootEntityName] else { continue }
                if removedRootEntities.contains(srcRootEntity) { continue }
                guard let destRootEntity = destinationEntities[srcRootEntity.name!] else { continue }
                if updatedRootEntities.contains(destRootEntity) { continue }
                updatedRootEntities.insert(destRootEntity)
                do {
                    try alterTable(forSourceEntity: srcRootEntity, destinationEntity: destRootEntity, withMapping: nil)
                } catch let e as NSError { thrown = e; success = false }
            case .transformEntityMappingType:
                let srcRootEntityName = rootForEntity(sourceEntity).name!
                let destRootEntityName = rootForEntity(destinationEntity).name!
                let srcRootEntity = sourceEntities[srcRootEntityName]
                guard let destRootEntity = destinationEntities[destRootEntityName] else { continue }
                if updatedRootEntities.contains(destRootEntity) { continue }
                updatedRootEntities.insert(destRootEntity)
                if let srcRootEntity = srcRootEntity {
                    do {
                        try alterTable(forSourceEntity: srcRootEntity, destinationEntity: destRootEntity, withMapping: nil)
                        try alterRelationship(forSourceEntity: sourceEntity, destinationEntity: destinationEntity, withMapping: entityMapping)
                    } catch let e as NSError { thrown = e; success = false }
                }
            default:
                break
            }
        }

        if let thrown = thrown { throw thrown }
        if !success { throw genericError() }
    }

    private nonisolated func initializeDatabase() throws {
        var manytomanys = Set<NSRelationshipDescription>()
        for entity in storeEntities {
            try createTable(for: entity)
            for (_, relation) in entity.relationshipsByName {
                guard let inverse = relation.inverseRelationship else { continue }
                if relation.isTransient || inverse.isTransient { continue }
                if relation.isToMany && inverse.isToMany && !manytomanys.contains(inverse) {
                    manytomanys.insert(relation)
                }
            }
        }
        for rel in manytomanys {
            try createTable(forRelationship: rel)
        }
    }

    private nonisolated func entityIds(for entity: NSEntityDescription) -> [NSNumber] {
        var ids: [NSNumber] = [NSNumber(value: entity.typeHash)]
        for subentity in entity.subentities {
            ids.append(contentsOf: entityIds(for: subentity))
        }
        return ids
    }

    private nonisolated func relationships(for entity: NSEntityDescription) -> [String: NSRelationshipDescription] {
        var relationships: [String: NSRelationshipDescription] = [:]
        for (key, obj) in entity.relationshipsByName where !obj.isTransient {
            relationships[key] = obj
        }
        for subentity in entity.subentities {
            relationships.merge(self.relationships(for: subentity)) { _, new in new }
        }
        return relationships
    }

    private nonisolated func columnNames(for entity: NSEntityDescription,
                             indexedOnly: Bool,
                             quotedNames: Bool) -> [String] {
        var columns = Set<String>()

        for (name, description) in entity.attributesByName {
            if description.isTransient { continue }
            if !indexedOnly || (entity.indexes.isEmpty == false) {
                columns.insert(quotedNames ? "'\(name)'" : name)
            }
        }

        for (_, description) in entity.relationshipsByName {
            if description.isTransient { continue }
            if description.isToMany { continue }
            var column = foreignKeyColumn(for: description)
            var orderColumn = "\(description.name)_order"
            if quotedNames {
                column = "'\(column)'"
                orderColumn = "'\(orderColumn)' integer default 0"
            }
            columns.insert(column)
            columns.insert(orderColumn)
        }

        for subentity in entity.subentities {
            columns.formUnion(columnNames(for: subentity, indexedOnly: indexedOnly, quotedNames: quotedNames))
        }

        return Array(columns)
    }

    private nonisolated func entityNeedsEntityTypeColumn(_ entity: NSEntityDescription) -> Bool {
        return entity.subentities.count > 0 || entity.superentity != nil
    }

    private nonisolated func createTable(for entity: NSEntityDescription) throws {
        // Sub-entities are handled by their root entity.
        if entity.superentity != nil { return }

        var columns = ["'__objectid' integer primary key"]
        if entity.subentities.count > 0 {
            columns.append("'__entityType' integer")
        }
        columns.append(contentsOf: columnNames(for: entity, indexedOnly: false, quotedNames: true))

        let string = "CREATE TABLE \(tableNameForEntity(entity)) (\(columns.joined(separator: ", ")));"
        let statement = preparedStatement(for: string)
        sqlite3_step(statement)
        if !(statement != nil && sqlite3_finalize(statement) == SQLITE_OK) {
            throw databaseError() ?? genericError()
        }
        try createIndices(for: entity)
    }

    private nonisolated func createIndices(for entity: NSEntityDescription) throws {
        if entity.superentity != nil { return }
        let indexedColumns = columnNames(for: entity, indexedOnly: true, quotedNames: false)
        let tableName = tableNameForEntity(entity)
        for column in indexedColumns {
            let query = "CREATE INDEX \(tableName)_\(column)_INDEX ON \(tableName) (`\(column)`)"
            let statement = preparedStatement(for: query)
            sqlite3_step(statement)
            if !(statement != nil && sqlite3_finalize(statement) == SQLITE_OK) {
                throw databaseError() ?? genericError()
            }
        }
    }

    private nonisolated func dropIndices(for entity: NSEntityDescription) throws {
        if entity.superentity != nil { return }
        let indexedColumns = columnNames(for: entity, indexedOnly: true, quotedNames: false)
        let tableName = tableNameForEntity(entity)
        for column in indexedColumns {
            let query = "DROP INDEX IF EXISTS \(tableName)_\(column)_INDEX"
            let statement = preparedStatement(for: query)
            sqlite3_step(statement)
            if !(statement != nil && sqlite3_finalize(statement) == SQLITE_OK) {
                throw databaseError() ?? genericError()
            }
        }
    }

    @discardableResult
    private nonisolated func dropTable(for entity: NSEntityDescription) -> Bool {
        return dropTable(named: tableNameForEntity(entity))
    }

    @discardableResult
    private nonisolated func dropTable(named name: String) -> Bool {
        let string = "DROP TABLE \(name);"
        let statement = preparedStatement(for: string)
        sqlite3_step(statement)
        return statement != nil && sqlite3_finalize(statement) == SQLITE_OK
    }

    private nonisolated func alterTable(forSourceEntity sourceEntity: NSEntityDescription,
                            destinationEntity: NSEntityDescription,
                            withMapping mapping: NSEntityMapping?) throws {
        let rootSourceEntity = rootForEntity(sourceEntity)
        let rootDestinationEntity = rootForEntity(destinationEntity)

        let sourceEntityName = "ecd\(rootSourceEntity.name!)"
        let temporaryTableName = "_T_\(sourceEntityName)"
        let destinationTableName = "ecd\(rootDestinationEntity.name!)"

        try dropIndices(for: rootDestinationEntity)

        // move existing table to temporary table
        var string = "ALTER TABLE \(sourceEntityName) RENAME TO \(temporaryTableName);"
        var statement = preparedStatement(for: string)
        sqlite3_step(statement)
        if statement == nil || sqlite3_finalize(statement) != SQLITE_OK { throw genericError() }

        // create destination table
        try createTable(for: rootDestinationEntity)

        let validDestinationColumns = columnNames(for: rootDestinationEntity, indexedOnly: false, quotedNames: false)

        // column mappings (renames)
        var columnMappings: [String: String] = [:]
        if let mapping = mapping {
            for am in mapping.attributeMappings ?? [] {
                if let expression = am.valueExpression,
                   let source = (expression.arguments?.first)?.constantValue as? String,
                   let name = am.name {
                    columnMappings[source] = name
                }
            }
        }

        // source columns (only those still valid in destination)
        var sourceColumns: [String] = []
        for column in columnNames(for: rootSourceEntity, indexedOnly: false, quotedNames: false) {
            if !sourceColumns.contains(column) && validDestinationColumns.contains(column) {
                sourceColumns.append(column)
            }
            if columnMappings[column] == nil { columnMappings[column] = column }
        }

        var destinationColumns: [String] = []
        for column in sourceColumns {
            if let mapped = columnMappings[column] {
                destinationColumns.append(mapped)
            } else if validDestinationColumns.contains(column) {
                destinationColumns.append(column)
            }
        }

        // relationships
        if let mapping = mapping {
            for rm in mapping.relationshipMappings ?? [] {
                guard let name = rm.name else { continue }
                let destinationRelationship = destinationEntity.relationshipsByName[name]
                let lookupKey = destinationRelationship?.renamingIdentifier ?? name
                let relationship = sourceEntity.relationshipsByName[lookupKey]
                if let relationship = relationship, !relationship.isToMany {
                    if let expression = rm.valueExpression,
                       let sourceConst = (expression.arguments?.first)?.constantValue as? String {
                        let destination = foreignKeyColumn(forRelationshipName: name)
                        destinationColumns.append(destination)
                        sourceColumns.append(foreignKeyColumn(forRelationshipName: sourceConst))
                    }
                }
            }
        }

        // ensure relationships for subentities not in the mapping
        let sourceRelationships = relationships(for: rootSourceEntity)
        let destinationRelationships = relationships(for: destinationEntity)
        for (key, relationship) in sourceRelationships {
            let fk = foreignKeyColumn(forRelationshipName: relationship.name)
            if !relationship.isToMany && !sourceColumns.contains(fk) {
                if destinationRelationships[key] != nil {
                    sourceColumns.append(fk)
                    destinationColumns.append(fk)
                }
            }
        }

        if rootDestinationEntity.subentities.count > 0 {
            sourceColumns.append("__entityType")
            destinationColumns.append("__entityType")
        }
        sourceColumns.append("__objectid")
        destinationColumns.append("__objectid")

        string = "INSERT INTO \(destinationTableName) (\(destinationColumns.joined(separator: ", ")))SELECT \(sourceColumns.joined(separator: ", ")) FROM \(temporaryTableName)"
        statement = preparedStatement(for: string)
        sqlite3_step(statement)
        if statement == nil || sqlite3_finalize(statement) != SQLITE_OK { throw genericError() }

        if !dropTable(named: temporaryTableName) { throw genericError() }
    }

    private nonisolated func createTable(forRelationship relationship: NSRelationshipDescription) throws {
        var firstID = "", secondID = "", firstOrder = "", secondOrder = ""
        _ = relationships(relationship, firstIDColumn: &firstID, secondIDColumn: &secondID,
                          firstOrderColumn: &firstOrder, secondOrderColumn: &secondOrder)
        let relationTable = tableNameForRelationship(relationship)
        let string = "CREATE TABLE \(relationTable) ('\(firstID)' INTEGER NOT NULL, '\(secondID)' INTEGER NOT NULL, '\(firstOrder)' INTEGER DEFAULT 0, '\(secondOrder)' INTEGER DEFAULT 0, PRIMARY KEY('\(firstID)', '\(secondID)'));"
        let statement = preparedStatement(for: string)
        sqlite3_step(statement)
        if !(statement != nil && sqlite3_finalize(statement) == SQLITE_OK) {
            throw databaseError() ?? genericError()
        }
    }

    private nonisolated func alterRelationship(forSourceEntity sourceEntity: NSEntityDescription,
                                   destinationEntity: NSEntityDescription,
                                   withMapping mapping: NSEntityMapping?) throws {
        guard let mapping = mapping else { return }
        for rm in mapping.relationshipMappings ?? [] {
            guard let name = rm.name else { continue }
            let destinationRelationship = destinationEntity.relationshipsByName[name]
            let lookupKey = destinationRelationship?.renamingIdentifier ?? name
            guard let relationship = sourceEntity.relationshipsByName[lookupKey],
                  let destinationRelationship = destinationRelationship else { continue }

            if relationship.isToMany && (relationship.inverseRelationship?.isToMany ?? false)
                && destinationRelationship.isToMany && (destinationRelationship.inverseRelationship?.isToMany ?? false) {

                let oldTableName = tableNameForPreviousRelationship(relationship)
                let newTableName = tableNameForRelationship(destinationRelationship)

                // does the old table exist?
                var tableExists = false
                var statement = preparedStatement(for: "SELECT count(*) FROM \(oldTableName)")
                sqlite3_step(statement)
                if statement != nil && sqlite3_finalize(statement) == SQLITE_OK { tableExists = true }

                if tableExists {
                    let temporaryTableName = "_T_\(oldTableName)"
                    var string = "ALTER TABLE \(oldTableName) RENAME TO \(temporaryTableName);"
                    statement = preparedStatement(for: string)
                    sqlite3_step(statement)
                    if statement == nil || sqlite3_finalize(statement) != SQLITE_OK { throw genericError() }

                    try createTable(forRelationship: destinationRelationship)

                    var f1 = "", f2 = "", f3 = "", f4 = ""
                    _ = relationships(destinationRelationship, firstIDColumn: &f1, secondIDColumn: &f2,
                                      firstOrderColumn: &f3, secondOrderColumn: &f4)
                    var p1 = "", p2 = "", p3 = "", p4 = ""
                    _ = previousRelationships(destinationRelationship, firstIDColumn: &p1, secondIDColumn: &p2,
                                              firstOrderColumn: &p3, secondOrderColumn: &p4)

                    string = "INSERT INTO \(newTableName) (\([f1, f2, f3, f4].joined(separator: ", ")))SELECT \([p1, p2, p3, p4].joined(separator: ", ")) FROM \(temporaryTableName)"
                    statement = preparedStatement(for: string)
                    sqlite3_step(statement)
                    if statement == nil || sqlite3_finalize(statement) != SQLITE_OK { throw genericError() }

                    if !dropTable(named: temporaryTableName) { throw genericError() }
                } else {
                    statement = preparedStatement(for: "SELECT count(*) FROM \(newTableName)")
                    sqlite3_step(statement)
                    if statement != nil && sqlite3_finalize(statement) == SQLITE_OK { tableExists = true }
                    if !tableExists {
                        try createTable(forRelationship: destinationRelationship)
                    }
                }
            }
        }
    }

    private nonisolated func getTableColumnNames(_ nameSet: inout Set<String>?, tableName: String) throws {
        let tiPragmaStr = "PRAGMA table_info(\(tableName));"
        let tiPragma = preparedStatement(for: tiPragmaStr)
        var mNameSet = Set<String>()
        while sqlite3_step(tiPragma) == SQLITE_ROW {
            if let name = sqlite3_column_text(tiPragma, 1) {
                mNameSet.insert(String(cString: name))
            }
        }
        if tiPragma == nil || sqlite3_finalize(tiPragma) != SQLITE_OK {
            throw databaseError() ?? genericError()
        }
        nameSet = mNameSet
    }

    /// Case-insensitive comparison using a fixed en_US_POSIX locale.
    private nonisolated static let fixedLocale = Locale(identifier: "en_US_POSIX")
    private nonisolated func fixedLocaleCaseInsensitiveCompare(_ a: String, _ b: String) -> ComparisonResult {
        return (a as NSString).compare(b, options: .caseInsensitive,
                                       range: NSRange(location: 0, length: (a as NSString).length),
                                       locale: EncryptedStore.fixedLocale)
    }

    private nonisolated func tableNameForRelationship(_ relationship: NSRelationshipDescription) -> String {
        let inverse = relationship.inverseRelationship
        let names = [relationship.name, inverse?.name ?? ""]
            .sorted { fixedLocaleCaseInsensitiveCompare($0, $1) == .orderedAscending }
        return "ecd_\(names.joined(separator: "_"))"
    }

    private nonisolated func tableNameForPreviousRelationship(_ relationship: NSRelationshipDescription) -> String {
        let inverse = relationship.inverseRelationship
        let a = relationship.renamingIdentifier ?? relationship.name
        let b = inverse?.renamingIdentifier ?? inverse?.name ?? ""
        let names = [a, b].sorted { fixedLocaleCaseInsensitiveCompare($0, $1) == .orderedAscending }
        return "ecd_\(names.joined(separator: "_"))"
    }

    /// Builds column names for both object IDs. Returns true if relationship.entity was first.
    @discardableResult
    private nonisolated func relationships(_ relationship: NSRelationshipDescription,
                               firstIDColumn: inout String,
                               secondIDColumn: inout String,
                               firstOrderColumn: inout String,
                               secondOrderColumn: inout String) -> Bool {
        let rootSourceEntity = rootForEntity(relationship.entity)
        let rootDestinationEntity = rootForEntity(relationship.destinationEntity!)
        let format = "%@__objectid"
        let orderFormat = "%@_order"

        if rootSourceEntity == rootDestinationEntity {
            firstIDColumn = String(format: format, rootSourceEntity.name! + "_1")
            secondIDColumn = String(format: format, rootDestinationEntity.name! + "_2")
            firstOrderColumn = String(format: orderFormat, rootSourceEntity.name! + "_1")
            secondOrderColumn = String(format: orderFormat, rootDestinationEntity.name! + "_2")
            return true
        }

        let ordered = [rootSourceEntity, rootDestinationEntity]
            .sorted { fixedLocaleCaseInsensitiveCompare($0.name!, $1.name!) == .orderedAscending }
        let firstEntity = ordered.first!
        let secondEntity = ordered.last!
        firstIDColumn = String(format: format, firstEntity.name!)
        firstOrderColumn = String(format: orderFormat, firstEntity.name!)
        secondIDColumn = String(format: format, secondEntity.name!)
        secondOrderColumn = String(format: orderFormat, secondEntity.name!)
        return ordered[0] == rootSourceEntity
    }

    @discardableResult
    private nonisolated func previousRelationships(_ relationship: NSRelationshipDescription,
                                       firstIDColumn: inout String,
                                       secondIDColumn: inout String,
                                       firstOrderColumn: inout String,
                                       secondOrderColumn: inout String) -> Bool {
        let rootSourceEntity = rootForEntity(relationship.entity)
        let rootDestinationEntity = rootForEntity(relationship.destinationEntity!)
        let format = "%@__objectid"
        let orderFormat = "%@_order"

        if rootSourceEntity == rootDestinationEntity {
            firstIDColumn = String(format: format, rootSourceEntity.name! + "_1")
            secondIDColumn = String(format: format, rootDestinationEntity.name! + "_2")
            firstOrderColumn = String(format: orderFormat, rootSourceEntity.name! + "_1")
            secondOrderColumn = String(format: orderFormat, rootDestinationEntity.name! + "_2")
            return true
        }

        let ordered = [rootSourceEntity, rootDestinationEntity]
            .sorted { fixedLocaleCaseInsensitiveCompare($0.name!, $1.name!) == .orderedAscending }
        let firstEntity = ordered.first!
        let secondEntity = ordered.last!
        let firstName = firstEntity.renamingIdentifier ?? firstEntity.name!
        let secondName = secondEntity.renamingIdentifier ?? secondEntity.name!
        firstIDColumn = String(format: format, firstName)
        firstOrderColumn = String(format: orderFormat, firstName)
        secondIDColumn = String(format: format, secondName)
        secondOrderColumn = String(format: orderFormat, secondName)
        return ordered[0] == rootSourceEntity
    }

    @discardableResult
    private nonisolated func relationships(_ relationship: NSRelationshipDescription,
                               firstIDColumn: inout String,
                               secondIDColumn: inout String) -> Bool {
        let rootSourceEntity = rootForEntity(relationship.entity)
        let rootDestinationEntity = rootForEntity(relationship.destinationEntity!)
        let format = "%@__objectid"

        if rootSourceEntity == rootDestinationEntity {
            firstIDColumn = String(format: format, rootSourceEntity.name! + "_1")
            secondIDColumn = String(format: format, rootDestinationEntity.name! + "_2")
            return true
        }
        let ordered = [rootSourceEntity, rootDestinationEntity]
            .sorted { fixedLocaleCaseInsensitiveCompare($0.name!, $1.name!) == .orderedAscending }
        firstIDColumn = String(format: format, ordered.first!.name!)
        secondIDColumn = String(format: format, ordered.last!.name!)
        return ordered[0] == rootSourceEntity
    }

    private nonisolated func checkTableForMissingColumns(_ metadata: [String: Any]) throws {
        guard let currentModel = self.persistentStoreCoordinator?.managedObjectModel
                               ?? NSManagedObjectModel.mergedModel(from: [Bundle.main], forStoreMetadata: metadata) else {
            MDELog("Failed to create NSManagedObjectModel.")
            throw NSError(domain: EncryptedStoreErrorDomain,
                          code: EncryptedStoreError.migrationFailed.rawValue,
                          userInfo: [EncryptedStoreErrorMessageKey: "Missing old model, cannot check database"])
        }

        let configurationName = (self.configurationName == "PF_DEFAULT_CONFIGURATION_NAME") ? nil : self.configurationName
        let entities = currentModel.entities(forConfigurationName: configurationName) ?? []
        var manytomany = Set<NSRelationshipDescription>()

        for entity in entities {
            if entity.superentity == nil {
                try checkTable(forEntity: entity)
            }
            for relation in entity.relationshipsByName.values {
                guard let inverse = relation.inverseRelationship else { continue }
                if relation.isTransient || inverse.isTransient { continue }
                if relation.isToMany && inverse.isToMany && !manytomany.contains(inverse) {
                    manytomany.insert(relation)
                }
            }
        }
        for relation in manytomany {
            try checkTable(forRelationship: relation)
        }
    }

    private nonisolated func checkTable(forEntity entity: NSEntityDescription) throws {
        if entity.superentity != nil { return }
        let tableName = tableNameForEntity(entity)
        var hasTable = false
        try checkTable(&hasTable, withName: tableName)
        if !hasTable { try createTable(for: entity); return }

        var nameSet: Set<String>? = nil
        try getTableColumnNames(&nameSet, tableName: tableName)
        let existing = nameSet ?? []

        let requiredNames = columnNames(for: entity, indexedOnly: false, quotedNames: false)
        var requiredNameSet = Set(requiredNames)
        requiredNameSet.subtract(existing)

        var addColumns: [String] = []
        for columnName in requiredNameSet {
            if columnName.hasSuffix("_order") {
                addColumns.append("'\(columnName)' integer default 0")
            } else {
                addColumns.append("'\(columnName)'")
            }
        }
        if entityNeedsEntityTypeColumn(entity) && !existing.contains("__entityType") {
            addColumns.append("'__entityType' integer")
        }

        for columnDef in addColumns {
            let string = "ALTER TABLE \(tableName) ADD COLUMN \(columnDef);"
            let statement = preparedStatement(for: string)
            sqlite3_step(statement)
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                throw databaseError() ?? genericError()
            }
        }
    }

    private nonisolated func checkTable(forRelationship relation: NSRelationshipDescription) throws {
        let tableName = tableNameForRelationship(relation)
        var hasTable = false
        try checkTable(&hasTable, withName: tableName)
        if !hasTable { try createTable(forRelationship: relation); return }

        var nameSet: Set<String>? = nil
        try getTableColumnNames(&nameSet, tableName: tableName)
        let existing = nameSet ?? []

        var c1 = "", c2 = "", c3 = "", c4 = ""
        _ = relationships(relation, firstIDColumn: &c1, secondIDColumn: &c2,
                          firstOrderColumn: &c3, secondOrderColumn: &c4)
        var requiredNameSet: Set<String> = [c1, c2, c3, c4]
        requiredNameSet.subtract(existing)

        for obj in requiredNameSet {
            let columnDef = obj.hasSuffix("__objectid")
                ? "'\(obj)' INTEGER NOT NULL"
                : "'\(obj)' INTEGER DEFAULT 0"
            let string = "ALTER TABLE \(tableName) ADD COLUMN \(columnDef);"
            let statement = preparedStatement(for: string)
            sqlite3_step(statement)
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                throw databaseError() ?? genericError()
            }
        }
    }

    // MARK: - Save changes

    private nonisolated func handleSaveChangesRequest(_ request: NSSaveChangesRequest) throws -> [Any] {
        var localNodeCache = nodeCache
        var thrown: NSError?
        let success = performInTransaction {
            var ok = true
            do { ok = try self.handleInsertedObjects(in: request) && ok } catch let e as NSError { thrown = e; ok = false }
            do { ok = try self.handleUpdatedObjects(in: request, cache: &localNodeCache) && ok } catch let e as NSError { thrown = e; ok = false }
            do { ok = try self.handleDeletedObjects(in: request) && ok } catch let e as NSError { thrown = e; ok = false }
            return ok
        }
        if success {
            nodeCache = localNodeCache
            return []
        }
        if let thrown = thrown { throw thrown }
        throw databaseError() ?? genericError()
    }

    private nonisolated func handleInsertedObjects(in request: NSSaveChangesRequest) throws -> Bool {
        var success = true
        var thrown: NSError?
        for object in request.insertedObjects ?? [] {
            var containsOrder = false
            var orderValues: [[String: Any]] = []

            let entity = object.entity
            var keys: [String] = []
            var columns = ["'__objectid'"]
            let properties = entity.propertiesByName
            for (key, obj) in properties {
                if obj.isTransient { continue }
                if obj is NSAttributeDescription {
                    keys.append(key)
                    columns.append("'\(key)'")
                } else if let desc = obj as? NSRelationshipDescription {
                    let inverse = desc.inverseRelationship
                    if !desc.isToMany {
                        keys.append(key)
                        columns.append("'\(foreignKeyColumn(for: desc))'")
                        if let inverse = inverse, inverse.isToMany {
                            let relationshipObject = object.value(forKey: desc.name) as? NSManagedObject
                            let values = relationshipObject?.value(forKey: inverse.name)
                            if let orderedValues = values as? NSOrderedSet {
                                containsOrder = true
                                var orderSequence = NSNumber(value: Int(Int32.max))
                                if orderedValues.contains(object) {
                                    orderSequence = NSNumber(value: orderedValues.index(of: object))
                                }
                                orderValues.append(["k": "'\(desc.name)_order'", "v": orderSequence])
                            }
                        }
                    } else if desc.isToMany, let inverse = inverse, inverse.isToMany {
                        do {
                            if try !handleUpdatedRelation(in: desc, forObject: object) { success = false }
                        } catch let e as NSError { thrown = e; success = false }
                    }
                }
            }

            if containsOrder {
                for dict in orderValues { columns.append(dict["k"] as! String) }
            }

            let string: String
            if entityNeedsEntityTypeColumn(entity) {
                string = "INSERT INTO \(tableNameForEntity(entity)) ('__entityType', \(columns.joined(separator: ", "))) VALUES(\(entity.typeHash), \(cmdArray(of: "?", times: columns.count).map { "\($0)" }.joined(separator: ", ")));"
            } else {
                string = "INSERT INTO \(tableNameForEntity(entity)) (\(columns.joined(separator: ", "))) VALUES(\(cmdArray(of: "?", times: columns.count).map { "\($0)" }.joined(separator: ", ")));"
            }

            let statement = preparedStatement(for: string)

            let number = referenceObject(for: object.objectID) as! NSNumber
            sqlite3_bind_int64(statement, 1, Int64(bitPattern: number.uint64Value))

            var columnIndex: Int32 = 0
            for (idx, obj) in keys.enumerated() {
                columnIndex = Int32(idx) + 1
                let property = properties[obj]!
                bindProperty(property, withValue: object.value(forKey: obj), forKey: obj,
                             to: statement, atIndex: columnIndex + 1)
            }

            if containsOrder {
                columnIndex += 1
                for dict in orderValues {
                    sqlite3_bind_int(statement, columnIndex + 1, (dict["v"] as! NSNumber).int32Value)
                    columnIndex += 1
                }
            }

            sqlite3_step(statement)
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                thrown = databaseError()
                success = false
                break
            }
        }
        if let thrown = thrown { throw thrown }
        return success
    }

    private nonisolated func nextOrderForColumn(inRelationship relationship: NSRelationshipDescription,
                                    forObject object: NSManagedObject,
                                    andSource source: Bool) -> Int32 {
        var order: Int32 = 0
        let objectID = (referenceObject(for: object.objectID) as! NSNumber).uint64Value
        let tableName = tableNameForRelationship(relationship)
        var firstID = "", secondID = "", firstOrder = "", secondOrder = ""
        let firstColumnIsSource = relationships(relationship, firstIDColumn: &firstID, secondIDColumn: &secondID,
                                                firstOrderColumn: &firstOrder, secondOrderColumn: &secondOrder)
        let orderColumn = source ? (firstColumnIsSource ? firstOrder : secondOrder)
                                  : (firstColumnIsSource ? secondOrder : firstOrder)
        let idColumn = source ? (firstColumnIsSource ? secondID : firstID)
                              : (firstColumnIsSource ? firstID : secondID)
        let string = "SELECT MAX(\(orderColumn)) FROM \(tableName) WHERE \(idColumn)=\(objectID);"
        let statement = preparedStatement(for: string)
        if sqlite3_step(statement) == SQLITE_ROW {
            order = sqlite3_column_int(statement, 0)
        }
        _ = sqlite3_finalize(statement)
        return order + 1
    }

    private nonisolated func handleUpdatedObjects(in request: NSSaveChangesRequest,
                                      cache: inout [NSManagedObjectID: CMDIncrementalStoreNode]) throws -> Bool {
        var success = true
        var thrown: NSError?
        for object in request.updatedObjects ?? [] {
            let objectID = object.objectID
            var cacheChanges: [String: Any] = [:]
            let node = cache[objectID]

            let entity = object.entity
            let changedAttributes = object.changedValues()
            var columns: [String] = []
            var keys: [String] = []
            let properties = entity.propertiesByName

            for (key, _) in changedAttributes {
                let property = properties[key]
                if property is NSAttributeDescription {
                    columns.append("\(key)=?")
                    keys.append(key)
                } else if let desc = property as? NSRelationshipDescription {
                    let inverse = desc.inverseRelationship
                    if !desc.isToMany {
                        let column = foreignKeyColumn(for: desc)
                        let orderColumn = "\(desc.name)_order"
                        var orderSequence = 0
                        let relationshipObject = object.value(forKey: desc.name) as? NSManagedObject
                        if let inverse = inverse {
                            let values = relationshipObject?.value(forKey: inverse.name)
                            if let orderedValues = values as? NSOrderedSet {
                                orderSequence = orderedValues.index(of: object)
                            }
                        }
                        columns.append("\(column)=?")
                        columns.append("\(orderColumn)=\(orderSequence)")
                        keys.append(key)
                    } else if desc.isToMany, let inverse = inverse, inverse.isToMany {
                        do {
                            if try !handleUpdatedRelation(in: desc, forObject: object) { success = false }
                        } catch let e as NSError { thrown = e; success = false }
                    }
                }
            }

            if keys.isEmpty {
                node?.updateWithChangedValues(cacheChanges)
                continue
            }

            let string = "UPDATE \(tableNameForEntity(entity)) SET \(columns.joined(separator: ", ")) WHERE __objectID=?;"
            let statement = preparedStatement(for: string)

            for (idx, obj) in keys.enumerated() {
                let value = changedAttributes[obj]
                let property = properties[obj]
                if let value = value, !(value is NSNull) {
                    if property is NSRelationshipDescription, let mo = value as? NSManagedObject {
                        cacheChanges[obj] = mo.objectID
                    } else {
                        cacheChanges[obj] = value
                    }
                } else {
                    cacheChanges[obj] = NSNull()
                }
                bindProperty(property!, withValue: value, forKey: obj, to: statement, atIndex: Int32(idx) + 1)
            }

            let number = referenceObject(for: objectID) as! NSNumber
            sqlite3_bind_int64(statement, Int32(keys.count) + 1, Int64(bitPattern: number.uint64Value))
            sqlite3_step(statement)

            if statement != nil && sqlite3_finalize(statement) == SQLITE_OK {
                node?.updateWithChangedValues(cacheChanges)
            } else {
                thrown = databaseError()
                success = false
                break
            }
        }
        if let thrown = thrown { throw thrown }
        return success
    }

    private nonisolated func handleUpdatedRelation(in relationship: NSRelationshipDescription,
                                       forObject object: NSManagedObject) throws -> Bool {
        let inverseObjects = object.value(forKey: relationship.name) as? NSSet ?? NSSet()
        let tableName = tableNameForRelationship(relationship)
        var firstID = "", secondID = "", firstOrder = "", secondOrder = ""
        let firstColumnIsSource = relationships(relationship, firstIDColumn: &firstID, secondIDColumn: &secondID,
                                                firstOrderColumn: &firstOrder, secondOrderColumn: &secondOrder)
        let objectID = (referenceObject(for: object.objectID) as! NSNumber).uint64Value

        let valuesFormat = firstColumnIsSource ? "\(objectID), ?, ?, ?" : "?, \(objectID), ?, ?"
        let insert = "INSERT INTO \(tableName) (\(firstID), \(secondID), \(firstOrder), \(secondOrder)) VALUES (\(valuesFormat));"
        let update = "UPDATE \(tableName) SET \(firstColumnIsSource ? secondOrder : firstOrder) = ? WHERE \(firstID) = ? AND \(secondID) = ?"

        let success = true
        var x: Int32 = 1
        var inverseObjectIDs: [NSNumber] = []

        for case let obj as NSManagedObject in inverseObjects {
            let inverseObjectID = referenceObject(for: obj.objectID) as! NSNumber
            let refObjectID = inverseObjectID.uint64Value

            let countQuery = "SELECT COUNT(*) FROM \(tableName) WHERE \(firstID) = \(firstColumnIsSource ? objectID : refObjectID) AND \(secondID) = \(firstColumnIsSource ? refObjectID : objectID)"

            if hasRows(countQuery) {
                let statement = preparedStatement(for: update)
                if firstColumnIsSource {
                    sqlite3_bind_int(statement, 1, x)
                    sqlite3_bind_int64(statement, 2, Int64(bitPattern: objectID))
                    sqlite3_bind_int64(statement, 3, Int64(bitPattern: inverseObjectID.uint64Value))
                } else {
                    sqlite3_bind_int(statement, 1, x)
                    sqlite3_bind_int64(statement, 2, Int64(bitPattern: inverseObjectID.uint64Value))
                    sqlite3_bind_int64(statement, 3, Int64(bitPattern: objectID))
                }
                sqlite3_step(statement)
                let finalize = sqlite3_finalize(statement)
                if finalize != SQLITE_OK && finalize != SQLITE_CONSTRAINT {
                    throw databaseError() ?? genericError()
                }
            } else {
                let firstOrderValue = nextOrderForColumn(inRelationship: relationship, forObject: obj, andSource: true)
                let secondOrderValue = x
                let statement = preparedStatement(for: insert)
                sqlite3_bind_int64(statement, 1, Int64(bitPattern: inverseObjectID.uint64Value))
                if firstColumnIsSource {
                    sqlite3_bind_int(statement, 2, firstOrderValue)
                    sqlite3_bind_int(statement, 3, secondOrderValue)
                } else {
                    sqlite3_bind_int(statement, 2, secondOrderValue)
                    sqlite3_bind_int(statement, 3, firstOrderValue)
                }
                sqlite3_step(statement)
                let finalize = sqlite3_finalize(statement)
                if finalize != SQLITE_OK && finalize != SQLITE_CONSTRAINT {
                    throw databaseError() ?? genericError()
                }
            }

            inverseObjectIDs.append(inverseObjectID)
            x += 1
        }

        if success {
            let notInValues = inverseObjectIDs.map { "\($0)" }.joined(separator: ",")
            let deleteQuery = "DELETE FROM \(tableNameForRelationship(relationship)) WHERE \(firstColumnIsSource ? firstID : secondID)=? AND \(firstColumnIsSource ? secondID : firstID) NOT IN (\(notInValues));"
            let statement = preparedStatement(for: deleteQuery)
            let number = referenceObject(for: object.objectID) as! NSNumber
            sqlite3_bind_int64(statement, 1, Int64(bitPattern: number.uint64Value))
            sqlite3_step(statement)
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                throw databaseError() ?? genericError()
            }
        }
        return success
    }

    private nonisolated func handleDeletedObjects(in request: NSSaveChangesRequest) throws -> Bool {
        var success = true
        var thrown: NSError?
        for object in request.deletedObjects ?? [] {
            let entity = object.entity
            let objectID = referenceObject(for: object.objectID) as! NSNumber
            let string = "DELETE FROM \(tableNameForEntity(entity)) WHERE __objectID=?;"
            let statement = preparedStatement(for: string)
            sqlite3_bind_int64(statement, 1, Int64(bitPattern: objectID.uint64Value))
            sqlite3_step(statement)
            if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                thrown = databaseError(); success = false; break
            }
            do {
                if try !handleDeletedRelation(in: object) { success = false; break }
            } catch let e as NSError { thrown = e; success = false; break }
        }
        if let thrown = thrown { throw thrown }
        return success
    }

    private nonisolated func handleDeletedRelation(in object: NSManagedObject) throws -> Bool {
        for (_, prop) in object.entity.propertiesByName {
            if let desc = prop as? NSRelationshipDescription {
                let inverse = desc.inverseRelationship
                if desc.isToMany, let inverse = inverse, inverse.isToMany {
                    let string = "DELETE FROM \(tableNameForRelationship(desc)) WHERE \(rootForEntity(desc.entity).name!)__objectid=?;"
                    let statement = preparedStatement(for: string)
                    let number = referenceObject(for: object.objectID) as! NSNumber
                    sqlite3_bind_int64(statement, 1, Int64(bitPattern: number.uint64Value))
                    sqlite3_step(statement)
                    if statement == nil || sqlite3_finalize(statement) != SQLITE_OK {
                        throw databaseError() ?? genericError()
                    }
                }
            }
        }
        return true
    }

    // MARK: - SQL helpers

    private nonisolated func escapedString(_ string: String, allowWildcards: Bool) -> String {
        var result = string
        let escapePattern = allowWildcards ? "[%_]" : "[\\\\%_]"
        if let escape = try? NSRegularExpression(pattern: escapePattern, options: []) {
            result = escape.stringByReplacingMatches(in: result, options: [],
                                                     range: NSRange(location: 0, length: (result as NSString).length),
                                                     withTemplate: "\\\\$0")
        }
        if allowWildcards {
            if let multi = try? NSRegularExpression(pattern: "(?<!\\\\)((?:\\\\{2})*+)\\*", options: []) {
                result = multi.stringByReplacingMatches(in: result, options: [],
                                                        range: NSRange(location: 0, length: (result as NSString).length),
                                                        withTemplate: "$1%")
            }
            if let single = try? NSRegularExpression(pattern: "(?<!\\\\)((?:\\\\{2})*+)\\?", options: []) {
                result = single.stringByReplacingMatches(in: result, options: [],
                                                         range: NSRange(location: 0, length: (result as NSString).length),
                                                         withTemplate: "$1_")
            }
        }
        return result
    }

    private nonisolated func hasRows(_ query: String) -> Bool {
        var count: Int32 = 0
        let statement = preparedStatement(for: query)
        if statement != nil && sqlite3_step(statement) == SQLITE_ROW {
            count = sqlite3_column_int(statement, 0)
        }
        sqlite3_finalize(statement)
        return count > 0
    }

    private nonisolated func checkTable(_ hasTable: inout Bool, withName name: String) throws {
        var count: Int32 = 0
        let string = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='\(name)';"
        let statement = preparedStatement(for: string)
        if statement != nil && sqlite3_step(statement) == SQLITE_ROW {
            count = sqlite3_column_int(statement, 0)
        } else {
            sqlite3_finalize(statement)
            throw databaseError() ?? genericError()
        }
        sqlite3_finalize(statement)
        hasTable = count > 0
    }

    private nonisolated func databaseError() -> NSError? {
        let code = sqlite3_errcode(database)
        if code != 0 {
            let message = sqlite3_errmsg(database).map { String(cString: $0) } ?? ""
            return NSError(domain: NSSQLiteErrorDomain, code: Int(code),
                           userInfo: [EncryptedStoreErrorMessageKey: message])
        }
        return nil
    }

    private nonisolated func genericError() -> NSError {
        return NSError(domain: EncryptedStoreErrorDomain, code: -1,
                       userInfo: [EncryptedStoreErrorMessageKey: "Unknown EncryptedStore error"])
    }

    private nonisolated func performInTransaction(_ block: () -> Bool) -> Bool {
        var statement = preparedStatement(for: "BEGIN EXCLUSIVE;")
        sqlite3_step(statement)
        if sqlite3_finalize(statement) != SQLITE_OK { return false }

        let success = block()

        statement = preparedStatement(for: success ? "COMMIT;" : "ROLLBACK;")
        sqlite3_step(statement)
        if sqlite3_finalize(statement) != SQLITE_OK { return false }
        return success
    }

    private nonisolated func tableNameForEntity(_ entity: NSEntityDescription) -> String {
        return "ecd\(rootForEntity(entity).name!)"
    }

    /// Traverses up the object hierarchy to find the base (root) entity.
    private nonisolated func rootForEntity(_ entity: NSEntityDescription) -> NSEntityDescription {
        var target = entity
        while let sup = target.superentity { target = sup }
        return target
    }

    private nonisolated(unsafe) static var sqlDebug: Bool = {
        UserDefaults.standard.bool(forKey: "com.apple.CoreData.SQLDebug")
    }()

    private nonisolated func preparedStatement(for query: String) -> OpaquePointer? {
        if EncryptedStore.sqlDebug { MDELog("SQL DEBUG:", query) }
        var statement: OpaquePointer?
        if sqlite3_prepare_v2(database, query, -1, &statement, nil) == SQLITE_OK {
            return statement
        }
        if EncryptedStore.sqlDebug {
            MDELog("could not prepare statement:", sqlite3_errmsg(database).map { String(cString: $0) } ?? "")
        }
        return nil
    }

    private nonisolated func orderClause(_ fetchRequest: NSFetchRequest<NSFetchRequestResult>,
                             forEntity entity: NSEntityDescription) -> [String: Any] {
        let descriptors = fetchRequest.sortDescriptors ?? []
        var order = ""
        var columns: [String] = []
        for desc in descriptors {
            var tableName = tableNameForEntity(entity)
            var key = desc.key ?? ""
            if let descKey = desc.key, descKey.range(of: ".") != nil {
                let components = descKey.components(separatedBy: ".")
                tableName = joinedTableName(forComponents: Array(components[0..<(components.count - 1)]), forRelationship: false)
                key = components.last!
            }
            var collate = ""
            if let selector = desc.selector, NSStringFromSelector(selector).range(of: "InsensitiveCompare") != nil {
                collate = "COLLATE NOCASE"
            }
            columns.append("\(tableName).\(key) \(collate) \(desc.ascending ? "ASC" : "DESC")")
        }
        if !columns.isEmpty {
            order = " ORDER BY \(columns.joined(separator: ", "))"
        }
        return ["order": order]
    }

    // MARK: - Join clause generation

    private nonisolated func getJoinClause(_ fetchRequest: NSFetchRequest<NSFetchRequestResult>,
                               withPredicate predicate: NSPredicate?,
                               initial: Bool) -> String {
        return getJoinClause(fetchRequest, withPredicate: predicate, initial: initial, withStatements: nil)
    }

    private nonisolated func getJoinClause(_ fetchRequest: NSFetchRequest<NSFetchRequestResult>,
                               withPredicate predicate: NSPredicate?,
                               initial: Bool,
                               withStatements previousJoinStatementsSet: NSMutableSet?) -> String {
        let entity = fetchRequest.entity!
        let joinStatementsSet: NSMutableSet = previousJoinStatementsSet ?? NSMutableSet()
        let joinStatementsArray = NSMutableArray()

        if initial {
            for sd in fetchRequest.sortDescriptors ?? [] {
                if let sortKey = sd.key, sortKey.range(of: ".") != nil {
                    if maybeAddJoinStatements(forKey: sortKey, toStatementArray: joinStatementsArray,
                                              withExistingStatementSet: joinStatementsSet, rootEntity: entity) {
                        fetchRequest.returnsDistinctResults = true
                    }
                }
            }
        }

        if let compoundPred = predicate as? NSCompoundPredicate {
            for subpred in compoundPred.subpredicates {
                joinStatementsArray.add(getJoinClause(fetchRequest, withPredicate: subpred as? NSPredicate,
                                                      initial: false, withStatements: joinStatementsSet))
            }
        } else if let comparisonPred = predicate as? NSComparisonPredicate {
            let predicateString = predicate?.predicateFormat
            if let predicateString = predicateString,
               let regex = try? NSRegularExpression(pattern: "\\b([a-zA-Z]\\w*\\.[^= ]+)\\b", options: []) {
                let matches = regex.matches(in: predicateString, options: [],
                                            range: NSRange(location: 0, length: (predicateString as NSString).length))
                for match in matches {
                    let matchText = (predicateString as NSString).substring(with: match.range)
                    if matchText.hasSuffix(".@count") { continue }
                    if maybeAddJoinStatements(forKey: matchText, toStatementArray: joinStatementsArray,
                                              withExistingStatementSet: joinStatementsSet, rootEntity: entity) {
                        fetchRequest.returnsDistinctResults = true
                    }
                }
            }
            let leftExp = comparisonPred.leftExpression
            if leftExp.expressionType == .keyPath,
               let property = entity.propertiesByName[leftExp.keyPath] as? NSRelationshipDescription,
               property.isToMany, property.inverseRelationship?.isToMany ?? false {
                if maybeAddJoinStatements(forKey: leftExp.keyPath, toStatementArray: joinStatementsArray,
                                          withExistingStatementSet: joinStatementsSet, rootEntity: entity) {
                    fetchRequest.returnsDistinctResults = true
                }
            }
            let rightExp = comparisonPred.rightExpression
            if rightExp.expressionType == .keyPath,
               let property = entity.propertiesByName[rightExp.keyPath] as? NSRelationshipDescription,
               property.isToMany, property.inverseRelationship?.isToMany ?? false {
                if maybeAddJoinStatements(forKey: rightExp.keyPath, toStatementArray: joinStatementsArray,
                                          withExistingStatementSet: joinStatementsSet, rootEntity: entity) {
                    fetchRequest.returnsDistinctResults = true
                }
            }
        }

        if joinStatementsArray.count > 0 {
            return joinStatementsArray.componentsJoined(by: " ")
        }
        return ""
    }

    @discardableResult
    private nonisolated func maybeAddJoinStatements(forKey key: String,
                                        toStatementArray statementArray: NSMutableArray,
                                        withExistingStatementSet statementsSet: NSMutableSet,
                                        rootEntity: NSEntityDescription) -> Bool {
        var retval = false
        let keysArray = key.components(separatedBy: ".")
        var currentEntity = rootEntity
        var fullJoinClause = ""
        var lastTableName = tableNameForEntity(currentEntity)

        for i in 0..<keysArray.count {
            let relTableName = joinedTableName(forComponents: Array(keysArray[0...i]), forRelationship: true)
            let nextTableName = joinedTableName(forComponents: Array(keysArray[0...i]), forRelationship: false)
            guard let rel = currentEntity.relationshipsByName[keysArray[i]] else { continue }
            let inverse = rel.inverseRelationship

            retval = true
            if rel.isToMany, let inverse = inverse, inverse.isToMany {
                var firstID = "", secondID = ""
                let sourceFirst = relationships(rel, firstIDColumn: &firstID, secondIDColumn: &secondID)
                let clause1Column = sourceFirst ? firstID : secondID
                let clause2Column = sourceFirst ? secondID : firstID

                let joinTableAsClause1 = "\(tableNameForRelationship(rel)) AS \(relTableName)"
                let joinTableOnClause1 = "\(lastTableName).__objectID = \(relTableName).\(clause1Column)"
                let firstJoinClause = "LEFT OUTER JOIN \(joinTableAsClause1) ON \(joinTableOnClause1)"

                let joinTableAsClause2 = "\(tableNameForEntity(rel.destinationEntity!)) AS \(nextTableName)"
                let joinTableOnClause2 = "\(relTableName).\(clause2Column) = \(nextTableName).__objectID"
                let secondJoinClause = "LEFT OUTER JOIN \(joinTableAsClause2) ON \(joinTableOnClause2)"

                fullJoinClause = "\(firstJoinClause) \(secondJoinClause)"
            } else {
                let joinTableAsClause = "\(tableNameForEntity(rel.destinationEntity!)) AS \(nextTableName)"
                let joinTableOnClause: String
                if rel.isToMany {
                    joinTableOnClause = "\(lastTableName).__objectID = \(nextTableName).\(foreignKeyColumn(for: rel.inverseRelationship!))"
                } else {
                    joinTableOnClause = "\(lastTableName).\(foreignKeyColumn(for: rel)) = \(nextTableName).__objectID"
                }
                fullJoinClause = "LEFT OUTER JOIN \(joinTableAsClause) ON \(joinTableOnClause)"
            }

            currentEntity = rel.destinationEntity!
            lastTableName = nextTableName
            if !statementsSet.contains(fullJoinClause) {
                statementsSet.add(fullJoinClause)
                statementArray.add(fullJoinClause)
            }
        }
        return retval
    }

    private nonisolated func expressionDescriptionTypeString(_ expressionDescription: NSExpressionDescription) -> String {
        switch expressionDescription.expressionResultType {
        case .objectIDAttributeType:
            return "__objectID"
        case .integer16AttributeType, .integer32AttributeType, .integer64AttributeType,
             .floatAttributeType, .doubleAttributeType:
            return columnForExpressionDescription(expressionDescription) ?? ""
        default:
            return ""
        }
    }

    private nonisolated func columnsClause(withProperties properties: [Any]) -> String {
        var columns: [String] = []
        for prop in properties {
            if let rel = prop as? NSRelationshipDescription {
                if !rel.isToMany { columns.append(foreignKeyColumn(for: rel)) }
            } else if let expression = prop as? NSExpressionDescription {
                columns.append(expressionDescriptionTypeString(expression))
            } else if let prop = prop as? NSPropertyDescription {
                columns.append(prop.name)
            }
        }
        if !columns.isEmpty { return columns.joined(separator: ", ") }
        return ""
    }

    private nonisolated func maximumObjectID(inTable table: String) -> NSNumber? {
        var value = objectIDCache[table]
        if value == nil {
            let string = "SELECT MAX(__objectID) FROM \(table);"
            let statement = preparedStatement(for: string)
            if sqlite3_step(statement) == SQLITE_ROW {
                value = NSNumber(value: sqlite3_column_int64(statement, 0))
            }
            sqlite3_finalize(statement)
        }
        let next = NSNumber(value: (value?.uint64Value ?? 0) + 1)
        objectIDCache[table] = next
        return next
    }

    // MARK: - Property binding / reading

    private nonisolated func bindProperty(_ property: NSPropertyDescription,
                              withValue value: Any?,
                              forKey key: String,
                              to statement: OpaquePointer?,
                              atIndex index: Int32) {
        guard let value = value, !(value is NSNull) else { return }

        if let attribute = property as? NSAttributeDescription {
            switch attribute.attributeType {
            case .stringAttributeType:
                sqlite3_bind_text(statement, index, (value as! String), -1, SQLITE_TRANSIENT)
            case .doubleAttributeType, .floatAttributeType:
                sqlite3_bind_double(statement, index, (value as! NSNumber).doubleValue)
            case .integer16AttributeType, .integer32AttributeType, .integer64AttributeType:
                sqlite3_bind_int64(statement, index, (value as! NSNumber).int64Value)
            case .booleanAttributeType:
                sqlite3_bind_int(statement, index, (value as! NSNumber).boolValue ? 1 : 0)
            case .dateAttributeType:
                sqlite3_bind_double(statement, index, (value as! Date).timeIntervalSince1970)
            case .binaryDataAttributeType:
                let data = value as! Data
                _ = data.withUnsafeBytes { raw in
                    sqlite3_bind_blob(statement, index, raw.baseAddress, Int32(data.count), SQLITE_TRANSIENT)
                }
            case .transformableAttributeType:
                var name = attribute.valueTransformerName ?? NSValueTransformerName.secureUnarchiveFromDataTransformerName.rawValue
                if name.isEmpty { name = NSValueTransformerName.secureUnarchiveFromDataTransformerName.rawValue }
                let isDefault = (name == NSValueTransformerName.secureUnarchiveFromDataTransformerName.rawValue)
                let transformer = ValueTransformer(forName: NSValueTransformerName(name))
                let data = (isDefault ? transformer?.reverseTransformedValue(value)
                                      : transformer?.transformedValue(value)) as? Data ?? Data()
                _ = data.withUnsafeBytes { raw in
                    sqlite3_bind_blob(statement, index, raw.baseAddress, Int32(data.count), SQLITE_TRANSIENT)
                }
            case .decimalAttributeType:
                let decimalString = (value as! NSNumber).stringValue
                sqlite3_bind_text(statement, index, decimalString, -1, SQLITE_TRANSIENT)
            default:
                break
            }
        } else if let desc = property as? NSRelationshipDescription, !desc.isToMany {
            if let mo = value as? NSManagedObject {
                let number = referenceObject(for: mo.objectID) as! NSNumber
                sqlite3_bind_int64(statement, index, Int64(bitPattern: number.uint64Value))
            }
        }
    }

    private nonisolated func valueForProperty(_ property: NSPropertyDescription,
                                  in statement: OpaquePointer?,
                                  atIndex index: Int32,
                                  withEntity theEntity: NSEntityDescription) -> Any? {
        if sqlite3_column_type(statement, index) == SQLITE_NULL { return nil }

        if let attribute = property as? NSAttributeDescription {
            switch attribute.attributeType {
            case .stringAttributeType:
                if let c = sqlite3_column_text(statement, index) { return String(cString: c) }
                return nil
            case .doubleAttributeType, .floatAttributeType:
                return NSNumber(value: sqlite3_column_double(statement, index))
            case .integer16AttributeType, .integer32AttributeType, .integer64AttributeType:
                return NSNumber(value: sqlite3_column_int64(statement, index))
            case .booleanAttributeType:
                return NSNumber(value: sqlite3_column_int(statement, index) != 0)
            case .dateAttributeType:
                return Date(timeIntervalSince1970: sqlite3_column_double(statement, index))
            case .binaryDataAttributeType:
                if let bytes = sqlite3_column_blob(statement, index) {
                    let length = Int(sqlite3_column_bytes(statement, index))
                    return Data(bytes: bytes, count: length)
                }
                return Data()
            case .transformableAttributeType:
                var name = attribute.valueTransformerName ?? NSValueTransformerName.secureUnarchiveFromDataTransformerName.rawValue
                if name.isEmpty { name = NSValueTransformerName.secureUnarchiveFromDataTransformerName.rawValue }
                let transformer = ValueTransformer(forName: NSValueTransformerName(name))
                let length = Int(sqlite3_column_bytes(statement, index))
                if length > 0, let bytes = sqlite3_column_blob(statement, index) {
                    let isDefault = (name == NSValueTransformerName.secureUnarchiveFromDataTransformerName.rawValue)
                    let data = Data(bytes: bytes, count: length)
                    return isDefault ? transformer?.transformedValue(data)
                                     : transformer?.reverseTransformedValue(data)
                }
                return nil
            case .decimalAttributeType:
                if let c = sqlite3_column_text(statement, index) {
                    return NSDecimalNumber(string: String(cString: c))
                }
                return nil
            default:
                return nil
            }
        } else if let relationship = property as? NSRelationshipDescription {
            var target = relationship.destinationEntity!
            if entityNeedsEntityTypeColumn(target) {
                let entityType = sqlite3_column_int64(statement, index + 1)
                if let resolved = entityTypeCache[NSNumber(value: entityType)] { target = resolved }
            }
            let number = NSNumber(value: sqlite3_column_int64(statement, index))
            return newObjectID(for: target, referenceObject: number)
        } else if let expression = property as? NSExpressionDescription {
            let number = NSNumber(value: sqlite3_column_double(statement, index))
            return expressionDescriptionTypeValue(expression, withReferenceNumber: number, withEntity: theEntity)
        }
        return nil
    }

    private nonisolated func expressionDescriptionTypeValue(_ expressionDescription: NSExpressionDescription,
                                                withReferenceNumber number: NSNumber,
                                                withEntity entity: NSEntityDescription) -> Any? {
        switch expressionDescription.expressionResultType {
        case .objectIDAttributeType:
            // `.entity` / `.name` are implicitly-unwrapped; rebind as optionals
            // so we can faithfully reproduce the ObjC nil checks.
            let expEntity: NSEntityDescription? = expressionDescription.entity
            let expName: String? = expressionDescription.name
            if let e = expEntity {
                return newObjectID(for: e, referenceObject: number)
            } else if let name = expName {
                let e = persistentStoreCoordinator?.managedObjectModel.entitiesByName[name] ?? entity
                return newObjectID(for: e, referenceObject: number)
            } else {
                return newObjectID(for: entity, referenceObject: number)
            }
        case .integer64AttributeType, .integer32AttributeType, .integer16AttributeType,
             .doubleAttributeType, .floatAttributeType:
            return number
        default:
            return nil
        }
    }

    // MARK: - WHERE clause generation

    private nonisolated func whereClause(with request: NSFetchRequest<NSFetchRequestResult>) -> [String: Any] {
        var result = recursiveWhereClause(with: request, predicate: request.predicate)
        var query = (result["query"] as? String) ?? ""

        if let entity = request.entity, entityNeedsEntityTypeColumn(entity) {
            let entityWhere: String
            if entity.subentities.count > 0 && request.includesSubentities {
                entityWhere = "\(tableNameForEntity(entity)).__entityType IN (\(entityIds(for: entity).map { "\($0)" }.joined(separator: ", ")))"
            } else {
                entityWhere = "\(tableNameForEntity(entity)).__entityType = \(entity.typeHash)"
            }
            if query.count > 0 {
                query = [entityWhere, query].joined(separator: " AND ")
            } else {
                query = entityWhere
            }
        }

        if query.count > 0 {
            result["query"] = " WHERE \(query)"
        }
        return result
    }

    private nonisolated(unsafe) static let predicateOperators: [UInt: [String: String]] = [
        NSComparisonPredicate.Operator.equalTo.rawValue:              ["operator": "=", "format": "%@"],
        NSComparisonPredicate.Operator.notEqualTo.rawValue:           ["operator": "!=", "format": "%@"],
        NSComparisonPredicate.Operator.contains.rawValue:             ["operator": "LIKE", "format": "%%%@%%"],
        NSComparisonPredicate.Operator.beginsWith.rawValue:           ["operator": "LIKE", "format": "%@%%"],
        NSComparisonPredicate.Operator.endsWith.rawValue:             ["operator": "LIKE", "format": "%%%@"],
        NSComparisonPredicate.Operator.like.rawValue:                 ["operator": "LIKE", "format": "%@"],
        NSComparisonPredicate.Operator.matches.rawValue:              ["operator": "REGEXP", "format": "%@"],
        NSComparisonPredicate.Operator.in.rawValue:                   ["operator": "IN", "format": "(%@)"],
        NSComparisonPredicate.Operator.lessThan.rawValue:             ["operator": "<", "format": "%@"],
        NSComparisonPredicate.Operator.lessThanOrEqualTo.rawValue:    ["operator": "<=", "format": "%@"],
        NSComparisonPredicate.Operator.greaterThan.rawValue:          ["operator": ">", "format": "%@"],
        NSComparisonPredicate.Operator.greaterThanOrEqualTo.rawValue: ["operator": ">=", "format": "%@"],
        NSComparisonPredicate.Operator.between.rawValue:              ["operator": "BETWEEN", "format": "%@ AND %@"]
    ]

    private nonisolated func recursiveWhereClause(with request: NSFetchRequest<NSFetchRequestResult>,
                                      predicate: NSPredicate?) -> [String: Any] {
        var query = ""
        var bindings: [Any] = []

        if let compoundPredicate = predicate as? NSCompoundPredicate {
            var queries: [String] = []
            for obj in compoundPredicate.subpredicates {
                let result = recursiveWhereClause(with: request, predicate: obj as? NSPredicate)
                queries.append((result["query"] as? String) ?? "")
                if let b = result["bindings"] as? [Any] { bindings.append(contentsOf: b) }
            }
            switch compoundPredicate.compoundPredicateType {
            case .not:
                query = "(NOT \(queries[0]))"
            case .and:
                query = "(\(queries.joined(separator: " AND ")))"
            case .or:
                query = "(\(queries.joined(separator: " OR ")))"
            @unknown default:
                break
            }
        } else if let comparisonPredicate = predicate as? NSComparisonPredicate {
            let type = comparisonPredicate.predicateOperatorType
            if comparisonPredicate.comparisonPredicateModifier == .any {
                request.returnsDistinctResults = true
            }
            let op = EncryptedStore.predicateOperators[type.rawValue] ?? [:]

            var leftOperand: Any?
            var leftBindings: Any?
            parseExpression(comparisonPredicate.leftExpression, inPredicate: comparisonPredicate,
                            inFetchRequest: request, operator: op, operand: &leftOperand, bindings: &leftBindings)

            var rightOperand: Any?
            var rightBindings: Any?
            parseExpression(comparisonPredicate.rightExpression, inPredicate: comparisonPredicate,
                            inFetchRequest: request, operator: op, operand: &rightOperand, bindings: &rightBindings)

            if let rightOperand = rightOperand, rightBindings == nil {
                if (op["operator"] ?? "") == "!=" {
                    query = [leftOperand as? String ?? "", "IS NOT", rightOperand as? String ?? ""].joined(separator: " ")
                } else {
                    query = [leftOperand as? String ?? "", "IS", rightOperand as? String ?? ""].joined(separator: " ")
                }
            } else {
                query = [leftOperand as? String ?? "", op["operator"] ?? "", rightOperand as? String ?? ""].joined(separator: " ")
                if (op["operator"] ?? "") == "LIKE" {
                    query += " ESCAPE '\\'"
                }
            }

            var comparisonBindings: [Any] = []
            if let leftBindings = leftBindings { comparisonBindings.append(leftBindings) }
            if let rightBindings = rightBindings { comparisonBindings.append(rightBindings) }
            bindings = comparisonBindings.cmdFlatten()
        } else if let predicate = predicate, predicate == NSPredicate(value: true) {
            query = "1"
        } else if let predicate = predicate, predicate == NSPredicate(value: false) {
            query = "0"
        }

        return ["query": query, "bindings": bindings]
    }

    private nonisolated func bindWhereClause(_ clause: [String: Any], to statement: OpaquePointer?) {
        guard statement != nil else { return }
        let bindings = (clause["bindings"] as? [Any]) ?? []
        for (idx, obj) in bindings.enumerated() {
            let i = Int32(idx + 1)
            if let str = obj as? String {
                sqlite3_bind_text(statement, i, str, Int32(str.utf8.count), SQLITE_TRANSIENT)
            } else if let number = obj as? NSNumber {
                let typeChar = String(cString: number.objCType)
                if typeChar == "f" || typeChar == "d" {
                    sqlite3_bind_double(statement, i, number.doubleValue)
                } else {
                    sqlite3_bind_int64(statement, i, number.int64Value)
                }
            } else if let oid = obj as? NSManagedObjectID {
                let ref = referenceObject(for: oid) as! NSNumber
                sqlite3_bind_int64(statement, i, Int64(bitPattern: ref.uint64Value))
            } else if let mo = obj as? NSManagedObject {
                let ref = referenceObject(for: mo.objectID) as! NSNumber
                sqlite3_bind_int64(statement, i, Int64(bitPattern: ref.uint64Value))
            } else if let date = obj as? Date {
                sqlite3_bind_double(statement, i, date.timeIntervalSince1970)
            }
        }
    }

    private nonisolated func parseExpression(_ expression: NSExpression,
                                 inPredicate predicate: NSComparisonPredicate,
                                 inFetchRequest request: NSFetchRequest<NSFetchRequestResult>,
                                 operator op: [String: String],
                                 operand: inout Any?,
                                 bindings: inout Any?) {
        var type = expression.expressionType
        var value: Any? = nil

        if type == .function {
            if expression.function == "valueForKeyPath:" {
                let argumentExpression = expression.arguments![0]
                if argumentExpression.expressionType == .constantValue {
                    value = argumentExpression.constantValue
                    type = .keyPath
                }
            }
        }

        if type == .keyPath {
            if value == nil { value = expression.keyPath }
            var foundPredicate = false
            let entity = request.entity!
            let properties = entity.propertiesByName
            let property = properties[value as? String ?? ""]

            if let desc = property as? NSRelationshipDescription {
                if desc.isToMany && (desc.inverseRelationship?.isToMany ?? false) {
                    let keys = (value as! String).components(separatedBy: ".")
                    value = "\(joinedTableName(forComponents: keys, forRelationship: false)).__objectid"
                } else {
                    value = "\(tableNameForEntity(entity)).\(foreignKeyColumn(for: desc))"
                }
            } else if property != nil {
                value = "\(tableNameForEntity(entity)).\(value as! String)"
            } else if let strValue = value as? String, strValue.range(of: ".") != nil {
                var pathComponents = strValue.components(separatedBy: ".")
                let lastComponent = pathComponents.last!

                var sumBuilder = "HAVING SUM("
                for i in 0..<pathComponents.count {
                    let part = pathComponents[i]
                    if part == "@sum" {
                        foundPredicate = true
                    } else {
                        let rel = entity.relationshipsByName[pathComponents[i]]
                        let inverse = rel?.inverseRelationship
                        if let rel = rel {
                            if rel.isToMany && (inverse?.isToMany ?? false) {
                                request.returnsDistinctResults = true
                                sumBuilder += "[\(inverse!.entity.name!)]."
                            } else {
                                sumBuilder += "[\(pathComponents[i])]."
                            }
                        } else {
                            sumBuilder += pathComponents[i]
                            sumBuilder += ")END_HAVING"
                            if foundPredicate { value = sumBuilder; break }
                        }
                    }
                }

                let entityTableName = tableNameForEntity(entity)
                if lastComponent == "length" {
                    for i in 0..<(pathComponents.count - 1) {
                        let rel = entity.relationshipsByName[pathComponents[i]]
                        let inverse = rel?.inverseRelationship
                        if let rel = rel {
                            if rel.isToMany && (inverse?.isToMany ?? false) {
                                pathComponents[0] = "[\(inverse!.entity.name!)]"
                                request.returnsDistinctResults = true
                            } else {
                                pathComponents[0] = "[\(pathComponents[i])]"
                            }
                        }
                    }
                    value = "LENGTH(\(entityTableName).\(pathComponents[0..<(pathComponents.count - 1)].joined(separator: ".")))"
                    foundPredicate = true
                }

                if lastComponent == "@count" {
                    value = buildCountSubquery(entity: entity, pathComponents: pathComponents,
                                               entityTableName: entityTableName, request: request)
                    foundPredicate = true
                }

                if !foundPredicate {
                    var lastComponentName = lastComponent
                    var subProperties = properties
                    var prop: Any? = nil
                    for comp in pathComponents {
                        prop = subProperties[comp]
                        if let p = prop as? NSRelationshipDescription, let dest = p.destinationEntity {
                            subProperties = dest.propertiesByName
                        } else {
                            prop = nil
                            break
                        }
                    }
                    if prop is NSRelationshipDescription {
                        request.returnsDistinctResults = true
                        lastComponentName = "__objectID"
                    }
                    value = "\(joinedTableName(forComponents: Array(pathComponents[0..<(pathComponents.count - 1)]), forRelationship: false)).\(lastComponentName)"
                }
            }

            let options = predicate.options
            if options.contains(.caseInsensitive) && options.contains(.diacriticInsensitive) {
                operand = "STRIP_CASE_DIACRITICS(\(value as! String))"
            } else if options.contains(.caseInsensitive) {
                operand = "STRIP_CASE(\(value as! String))"
            } else if options.contains(.diacriticInsensitive) {
                operand = "STRIP_DIACRITICS(\(value as! String))"
            } else {
                operand = value
            }
        } else if type == .evaluatedObject {
            operand = "__objectid"
        } else if type == .constantValue {
            value = expression.constantValue
            if let set = value as? NSSet {
                let count = set.count
                let parameters = cmdArray(of: "?", times: count).map { "\($0)" }
                bindings = set.allObjects
                operand = String(format: op["format"] ?? "%@", parameters.joined(separator: ", "))
            } else if value is Date {
                bindings = value
                operand = "?"
            } else if let array = value as? [Any] {
                if predicate.predicateOperatorType == .between {
                    bindings = array
                    operand = String(format: op["format"] ?? "%@", "?", "?")
                } else {
                    let count = array.count
                    let parameters = cmdArray(of: "?", times: count).map { "\($0)" }
                    bindings = array
                    operand = String(format: op["format"] ?? "%@", parameters.joined(separator: ", "))
                }
            } else if var strValue = value as? String {
                if (op["operator"] ?? "") == "LIKE" {
                    let isLike = predicate.predicateOperatorType == .like
                    strValue = escapedString(strValue, allowWildcards: isLike)
                }
                let options = predicate.options
                if options.contains(.caseInsensitive) && options.contains(.diacriticInsensitive) {
                    strValue = strValue.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
                } else if options.contains(.caseInsensitive) {
                    strValue = strValue.folding(options: .caseInsensitive, locale: nil)
                } else if options.contains(.diacriticInsensitive) {
                    strValue = strValue.folding(options: .diacriticInsensitive, locale: nil)
                }
                operand = "?"
                bindings = String(format: op["format"] ?? "%@", strValue)
            } else if value is NSManagedObject || value is NSManagedObjectID {
                let objectId = (value as? NSManagedObject)?.objectID ?? (value as! NSManagedObjectID)
                operand = "?"
                if objectId.isTemporaryID {
                    bindings = "-1"
                } else {
                    bindings = value
                }
            } else if value == nil || value is NSNull {
                bindings = nil
                operand = "NULL"
            } else {
                bindings = value
                operand = "?"
            }
        } else if type == .aggregate {
            let collection = (expression.collection as? [NSExpression]) ?? []
            var subOperands: [String] = []
            var aggBindings: [Any] = []
            let exprOperator = ["operator": "=", "format": "%@"]
            for expr in collection {
                var subOperand: Any?
                var binding: Any?
                parseExpression(expr, inPredicate: predicate, inFetchRequest: request,
                                operator: exprOperator, operand: &subOperand, bindings: &binding)
                if let s = subOperand as? String { subOperands.append(s) }
                if let b = binding { aggBindings.append(b) }
            }
            operand = String(format: op["format"] ?? "%@", subOperands.joined(separator: ","))
            bindings = aggBindings.cmdFlatten()
        } else {
            MDELog("Unsupported expression type", type.rawValue)
        }
    }

    /// Builds the `@count` correlated subquery (ported from the ObjC inline block).
    private nonisolated func buildCountSubquery(entity: NSEntityDescription,
                                    pathComponents: [String],
                                    entityTableName: String,
                                    request: NSFetchRequest<NSFetchRequestResult>) -> String {
        var relationshipsList: [NSRelationshipDescription] = []
        var relEntity = entity
        for i in 0..<(pathComponents.count - 1) {
            let rel = relationshipForEntity(relEntity, name: pathComponents[i])!
            relationshipsList.append(rel)
            relEntity = rel.destinationEntity!
        }

        var path: String? = nil
        var prevPath: String? = nil
        var subquery = ""

        for rel in relationshipsList {
            prevPath = path
            path = path.map { "\($0).\(rel.name)" } ?? rel.name

            if let prevPath = prevPath {
                let destTableName = tableNameForEntity(rel.destinationEntity!)
                if rel.isToMany {
                    if rel.inverseRelationship?.isToMany ?? false { // many-to-many
                        let relationTable = tableNameForRelationship(rel)
                        var f1 = "", f2 = "", f3 = "", f4 = ""
                        let firstColumnIsSource = relationships(rel, firstIDColumn: &f1, secondIDColumn: &f2,
                                                                firstOrderColumn: &f3, secondOrderColumn: &f4)
                        let sourceIDColumn = firstColumnIsSource ? f1 : f2
                        let destinationIDColumn = firstColumnIsSource ? f2 : f1
                        let relationTableAlias = "\(path!)_rel"
                        subquery += "LEFT OUTER JOIN \(relationTable) [\(relationTableAlias)] ON [\(prevPath)].[__objectid] = [\(relationTableAlias)].[\(sourceIDColumn)]\n"
                        subquery += "LEFT OUTER JOIN \(destTableName) [\(path!)] ON [\(relationTableAlias)].[\(destinationIDColumn)] = [\(path!)].[__objectid]"
                    } else { // one-to-many
                        subquery += "LEFT OUTER JOIN \(destTableName) [\(path!)] ON [\(prevPath)].[__objectid] = [\(path!)].[\(foreignKeyColumn(for: rel.inverseRelationship!))]"
                    }
                } else { // one-to-one
                    subquery += "LEFT OUTER JOIN \(destTableName) [\(path!)] ON [\(prevPath)].[\(foreignKeyColumn(for: rel))] = [\(path!)].[__objectid]"
                }
                if rel.destinationEntity?.superentity != nil {
                    subquery += " AND [\(path!)].__entityType IN (\(rel.destinationEntity!.typeHashSubhierarchy.map { "\($0)" }.joined(separator: ", ")))"
                }
                subquery += "\n"
            }
        }

        let firstRel = relationshipsList.first!
        let isFirstRelManyToMany = firstRel.isToMany && (firstRel.inverseRelationship?.isToMany ?? false)
        let firstDestTableName = tableNameForEntity(firstRel.destinationEntity!)

        var select = "(SELECT COUNT([\(path!)].[__objectid])\nFROM \(isFirstRelManyToMany ? tableNameForRelationship(firstRel) : firstDestTableName) [\(isFirstRelManyToMany ? "\(firstRel.name)_rel" : firstRel.name)]\n"

        if isFirstRelManyToMany {
            var f1 = "", f2 = "", f3 = "", f4 = ""
            let firstColumnIsSource = relationships(firstRel, firstIDColumn: &f1, secondIDColumn: &f2,
                                                    firstOrderColumn: &f3, secondOrderColumn: &f4)
            let destinationIDColumn = firstColumnIsSource ? f2 : f1
            select += "LEFT OUTER JOIN \(firstDestTableName) [\(firstRel.name)] ON [\(firstRel.name)_rel].[\(destinationIDColumn)] = [\(firstRel.name)].[__objectid]\n"
        }

        subquery = select + subquery

        if isFirstRelManyToMany {
            var f1 = "", f2 = "", f3 = "", f4 = ""
            let firstColumnIsSource = relationships(firstRel, firstIDColumn: &f1, secondIDColumn: &f2,
                                                    firstOrderColumn: &f3, secondOrderColumn: &f4)
            let sourceIDColumn = firstColumnIsSource ? f1 : f2
            subquery += "WHERE \(entityTableName).[__objectid] = [\(firstRel.name)_rel].[\(sourceIDColumn)]"
        } else {
            subquery += "WHERE \(entityTableName).[\(firstRel.isToMany ? "__objectid" : foreignKeyColumn(for: firstRel))] = [\(firstRel.name)].[\(firstRel.isToMany ? foreignKeyColumn(for: firstRel.inverseRelationship!) : "__objectid")]"
        }

        if firstRel.destinationEntity?.superentity != nil {
            subquery += " AND [\(firstRel.name)].__entityType IN (\(firstRel.destinationEntity!.typeHashSubhierarchy.map { "\($0)" }.joined(separator: ", ")))"
        }
        subquery += ")"
        return subquery
    }

    private nonisolated func foreignKeyColumn(forRelationshipName relationshipName: String) -> String {
        return "\(relationshipName)__objectid"
    }

    private nonisolated func foreignKeyColumn(for relationship: NSRelationshipDescription) -> String {
        return foreignKeyColumn(forRelationshipName: relationship.name)
    }

    private nonisolated func joinedTableName(forComponents componentsArray: [String], forRelationship: Bool) -> String {
        assert(componentsArray.count > 0)
        let tableName = componentsArray.joined(separator: ".")
        return forRelationship ? "[\(tableName)_rel]" : "[\(tableName)]"
    }

    private nonisolated func relationshipForEntity(_ entity: NSEntityDescription, name: String) -> NSRelationshipDescription? {
        return entity.relationshipsByName[name]
    }

    // MARK: - Expression descriptions

    private nonisolated func columnForExpressionDescription(_ expressionDescription: NSExpressionDescription) -> String? {
        let expression = expressionDescription.expression!
        switch expression.expressionType {
        case .function:
            return columnForFunctionExpressionDescription(expressionDescription)
        default:
            return nil
        }
    }

    private nonisolated func columnForFunctionExpressionDescription(_ expressionDescription: NSExpressionDescription) -> String? {
        let expression = expressionDescription.expression!
        let function = expression.function
        let arguments = (expression.arguments ?? []).map { "\($0)" }.joined(separator: ",")
        switch function {
        case "sum:":     return "sum(\(arguments))"
        case "average:": return "avg(\(arguments))"
        case "count:":   return "count(\(arguments))"
        case "min:":     return "min(\(arguments))"
        case "max:":     return "max(\(arguments))"
        default:         return nil
        }
    }
}
