#ifndef PFHASH_H
#define PFHASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t (*pfHashFunction)(const char *key);

typedef struct sPfHashSetNode {
  char *key;
  struct sPfHashSetNode *next;
  uint32_t hash;
} pfHashSetNode;

typedef struct {
  pfHashFunction fn;
  uint32_t bucketCount;
  size_t keyCount;
  pfHashSetNode *lookup[];
} pfHashSet;

typedef struct sPfHashMapNode {
  char *key;
  pfHashSet *values;
  struct sPfHashMapNode *next;
  uint32_t hash;
} pfHashMapNode;

/* Maps each string key to an owned, dynamically sized string set. */
typedef struct {
  pfHashFunction fn;
  uint32_t bucketCount;
  size_t keyCount;
  pfHashMapNode *lookup[];
} pfHashMap;

pfHashSet *pfHashSetCreate(pfHashFunction fn, uint32_t bucketCount);
void pfHashSetDestroy(pfHashSet *set);
bool pfHashSetAdd(pfHashSet *set, const char *key);
bool pfHashSetDelete(pfHashSet *set, const char *key);
bool pfHashSetContains(const pfHashSet *set, const char *key);

/* Transfers all source nodes into destination; source remains owned and empty. */
void pfHashSetMoveEntries(pfHashSet *destination, pfHashSet *source);

pfHashMap *pfHashMapCreate(pfHashFunction fn, uint32_t bucketCount);
void pfHashMapDestroy(pfHashMap *map);
bool pfHashMapAdd(pfHashMap *map, const char *key, const char *value);
bool pfHashMapContains(const pfHashMap *map, const char *key,
                       const char *value);

/* Returns a borrowed value set whose lifetime is bounded by map. */
const pfHashSet *pfHashMapFind(const pfHashMap *map, const char *key);

/* Preallocates any value-set growth needed for a subsequent move. */
bool pfHashMapPrepareMoveEntries(pfHashMap *destination,
                                 const pfHashMap *source);

/* Transfers all source entries into destination; source remains owned/empty. */
void pfHashMapMoveEntries(pfHashMap *destination, pfHashMap *source);

#endif
