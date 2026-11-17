// Umbrella header for the SQLCipher Community Edition module.
//
// Replace the include below with the path to the sqlite3.h that ships with
// your SQLCipher Community Edition build. The system <sqlite3.h> does NOT
// declare sqlite3_key / sqlite3_rekey, so pointing at it will fail to compile
// the key/rekey calls in EncryptedStore.swift.
//
// Example (CocoaPods 'SQLCipher'):   #import "sqlite3.h"
// Example (SPM sqlcipher package):   #import "sqlite3.h"

#import <sqlite3.h>

// SQLCipher Community Edition exposes these in its sqlite3.h. Declared here
// as a safety net in case your header variant guards them behind SQLITE_HAS_CODEC.
#ifndef SQLITE_HAS_CODEC
int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);
int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey);
#endif
