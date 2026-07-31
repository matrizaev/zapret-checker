#include "allheaders.h"

#include "pfhash.h"

#include "errorstrings.h"

#define INITIAL_VALUE_BUCKET_COUNT 1U

static uint32_t DefaultHash(const char *key) {
  uint32_t hash = 0;

  if (key == NULL)
    return 0;
  while (*key != '\0') {
    hash = (uint32_t)(unsigned char)*key + 31U * hash;
    key++;
  }
  return hash;
}

static bool HashAllocationSize(size_t headerSize, size_t bucketSize,
                               uint32_t bucketCount, size_t *allocationSize) {
  size_t bucketsSize = 0;

  if (allocationSize == NULL || bucketCount == 0 ||
      bucketCount > SIZE_MAX / bucketSize)
    return false;
  bucketsSize = (size_t)bucketCount * bucketSize;
  if (bucketsSize > SIZE_MAX - headerSize)
    return false;
  *allocationSize = headerSize + bucketsSize;
  return true;
}

static pfHashSetNode *FindSetNode(const pfHashSet *set, const char *key,
                                  uint32_t hash, uint32_t *bucket) {
  pfHashSetNode *node = NULL;
  uint32_t entry = 0;

  if (set == NULL || key == NULL || set->bucketCount == 0)
    return NULL;
  entry = hash % set->bucketCount;
  if (bucket != NULL)
    *bucket = entry;
  node = set->lookup[entry];
  while (node != NULL) {
    if (node->hash == hash && strcmp(node->key, key) == 0)
      return node;
    node = node->next;
  }
  return NULL;
}

pfHashSet *pfHashSetCreate(pfHashFunction fn, uint32_t bucketCount) {
  pfHashSet *set = NULL;
  size_t allocationSize = 0;

  if (!HashAllocationSize(sizeof(*set), sizeof(set->lookup[0]), bucketCount,
                          &allocationSize))
    return NULL;
  set = calloc(1, allocationSize);
  if (set == NULL)
    return NULL;
  set->fn = fn == NULL ? DefaultHash : fn;
  set->bucketCount = bucketCount;
  return set;
}

void pfHashSetDestroy(pfHashSet *set) {
  if (set == NULL)
    return;
  for (uint32_t i = 0; i < set->bucketCount; i++) {
    pfHashSetNode *node = set->lookup[i];
    while (node != NULL) {
      pfHashSetNode *next = node->next;
      free(node->key);
      free(node);
      node = next;
    }
  }
  free(set);
}

bool pfHashSetAdd(pfHashSet *set, const char *key) {
  pfHashSetNode *node = NULL;
  uint32_t bucket = 0;
  uint32_t hash = 0;

  if (set == NULL || key == NULL || set->keyCount == SIZE_MAX)
    return false;
  hash = set->fn(key);
  if (FindSetNode(set, key, hash, &bucket) != NULL)
    return true;

  node = calloc(1, sizeof(*node));
  if (node == NULL)
    return false;
  node->key = strdup(key);
  if (node->key == NULL) {
    free(node);
    return false;
  }
  node->hash = hash;
  node->next = set->lookup[bucket];
  set->lookup[bucket] = node;
  set->keyCount++;
  return true;
}

bool pfHashSetDelete(pfHashSet *set, const char *key) {
  pfHashSetNode *node = NULL;
  pfHashSetNode *previous = NULL;
  uint32_t bucket = 0;
  uint32_t hash = 0;

  if (set == NULL || key == NULL || set->bucketCount == 0)
    return false;
  hash = set->fn(key);
  bucket = hash % set->bucketCount;
  node = set->lookup[bucket];
  while (node != NULL) {
    if (node->hash == hash && strcmp(node->key, key) == 0)
      break;
    previous = node;
    node = node->next;
  }
  if (node == NULL)
    return false;
  if (previous == NULL)
    set->lookup[bucket] = node->next;
  else
    previous->next = node->next;
  free(node->key);
  free(node);
  set->keyCount--;
  return true;
}

bool pfHashSetContains(const pfHashSet *set, const char *key) {
  if (set == NULL || key == NULL)
    return false;
  return FindSetNode(set, key, set->fn(key), NULL) != NULL;
}

void pfHashSetMoveEntries(pfHashSet *destination, pfHashSet *source) {
  if (destination == NULL || source == NULL || destination == source ||
      destination->bucketCount == 0)
    return;

  for (uint32_t i = 0; i < source->bucketCount; i++) {
    while (source->lookup[i] != NULL) {
      pfHashSetNode *node = source->lookup[i];
      uint32_t hash = destination->fn(node->key);
      uint32_t bucket = hash % destination->bucketCount;

      source->lookup[i] = node->next;
      source->keyCount--;
      if (FindSetNode(destination, node->key, hash, NULL) != NULL) {
        free(node->key);
        free(node);
        continue;
      }
      node->hash = hash;
      node->next = destination->lookup[bucket];
      destination->lookup[bucket] = node;
      destination->keyCount++;
    }
  }
}

static bool GrowHashSet(pfHashSet **setPointer) {
  pfHashSet *grown = NULL;
  pfHashSet *set = NULL;
  uint32_t grownBucketCount = 0;

  if (setPointer == NULL || *setPointer == NULL)
    return false;
  set = *setPointer;
  if (set->bucketCount > (UINT32_MAX - 1U) / 2U)
    return true;
  grownBucketCount = set->bucketCount * 2U + 1U;
  grown = pfHashSetCreate(set->fn, grownBucketCount);
  if (grown == NULL)
    return false;
  pfHashSetMoveEntries(grown, set);
  pfHashSetDestroy(set);
  *setPointer = grown;
  return true;
}

static bool EnsureHashSetCapacity(pfHashSet **setPointer,
                                  size_t requiredKeyCount) {
  if (setPointer == NULL || *setPointer == NULL)
    return false;
  while ((size_t)(*setPointer)->bucketCount < requiredKeyCount) {
    uint32_t previousBucketCount = (*setPointer)->bucketCount;
    if (!GrowHashSet(setPointer))
      return false;
    if ((*setPointer)->bucketCount == previousBucketCount)
      break;
  }
  return true;
}

static bool AddResizableHashSetValue(pfHashSet **setPointer,
                                     const char *value) {
  pfHashSet *set = NULL;

  if (setPointer == NULL || *setPointer == NULL || value == NULL)
    return false;
  set = *setPointer;
  if (pfHashSetContains(set, value))
    return true;
  if (set->keyCount >= set->bucketCount) {
    if (!GrowHashSet(setPointer))
      return false;
    set = *setPointer;
  }
  return pfHashSetAdd(set, value);
}

static pfHashMapNode *FindMapNode(const pfHashMap *map, const char *key,
                                  uint32_t hash, uint32_t *bucket) {
  pfHashMapNode *node = NULL;
  uint32_t entry = 0;

  if (map == NULL || key == NULL || map->bucketCount == 0)
    return NULL;
  entry = hash % map->bucketCount;
  if (bucket != NULL)
    *bucket = entry;
  node = map->lookup[entry];
  while (node != NULL) {
    if (node->hash == hash && strcmp(node->key, key) == 0)
      return node;
    node = node->next;
  }
  return NULL;
}

pfHashMap *pfHashMapCreate(pfHashFunction fn, uint32_t bucketCount) {
  pfHashMap *map = NULL;
  size_t allocationSize = 0;

  if (!HashAllocationSize(sizeof(*map), sizeof(map->lookup[0]), bucketCount,
                          &allocationSize))
    return NULL;
  map = calloc(1, allocationSize);
  if (map == NULL)
    return NULL;
  map->fn = fn == NULL ? DefaultHash : fn;
  map->bucketCount = bucketCount;
  return map;
}

void pfHashMapDestroy(pfHashMap *map) {
  if (map == NULL)
    return;
  for (uint32_t i = 0; i < map->bucketCount; i++) {
    pfHashMapNode *node = map->lookup[i];
    while (node != NULL) {
      pfHashMapNode *next = node->next;
      free(node->key);
      pfHashSetDestroy(node->values);
      free(node);
      node = next;
    }
  }
  free(map);
}

bool pfHashMapAdd(pfHashMap *map, const char *key, const char *value) {
  pfHashMapNode *node = NULL;
  uint32_t bucket = 0;
  uint32_t hash = 0;

  if (map == NULL || key == NULL || value == NULL ||
      map->keyCount == SIZE_MAX)
    return false;
  hash = map->fn(key);
  node = FindMapNode(map, key, hash, &bucket);
  if (node != NULL)
    return AddResizableHashSetValue(&node->values, value);

  node = calloc(1, sizeof(*node));
  if (node == NULL)
    return false;
  node->key = strdup(key);
  node->values = pfHashSetCreate(NULL, INITIAL_VALUE_BUCKET_COUNT);
  if (node->key == NULL || node->values == NULL ||
      !AddResizableHashSetValue(&node->values, value)) {
    free(node->key);
    pfHashSetDestroy(node->values);
    free(node);
    return false;
  }
  node->hash = hash;
  node->next = map->lookup[bucket];
  map->lookup[bucket] = node;
  map->keyCount++;
  return true;
}

bool pfHashMapContains(const pfHashMap *map, const char *key,
                       const char *value) {
  const pfHashSet *values = pfHashMapFind(map, key);

  return value != NULL && pfHashSetContains(values, value);
}

const pfHashSet *pfHashMapFind(const pfHashMap *map, const char *key) {
  pfHashMapNode *node = NULL;

  if (map == NULL || key == NULL)
    return NULL;
  node = FindMapNode(map, key, map->fn(key), NULL);
  return node == NULL ? NULL : node->values;
}

static void MergeOwnedValueSets(pfHashSet **destination,
                                pfHashSet **source) {
  pfHashSet *temporary = NULL;

  if (destination == NULL || source == NULL || *destination == NULL ||
      *source == NULL)
    return;
  if ((*source)->bucketCount > (*destination)->bucketCount) {
    temporary = *destination;
    *destination = *source;
    *source = temporary;
  }
  pfHashSetMoveEntries(*destination, *source);
  pfHashSetDestroy(*source);
  *source = NULL;
}

bool pfHashMapPrepareMoveEntries(pfHashMap *destination,
                                 const pfHashMap *source) {
  if (destination == NULL || source == NULL || destination == source)
    return false;

  for (uint32_t i = 0; i < source->bucketCount; i++) {
    for (const pfHashMapNode *sourceNode = source->lookup[i];
         sourceNode != NULL; sourceNode = sourceNode->next) {
      pfHashMapNode *destinationNode = FindMapNode(
          destination, sourceNode->key, destination->fn(sourceNode->key), NULL);
      size_t requiredKeyCount = 0;

      if (destinationNode == NULL)
        continue;
      if (sourceNode->values == NULL || destinationNode->values == NULL ||
          sourceNode->values->keyCount >
              SIZE_MAX - destinationNode->values->keyCount)
        return false;
      requiredKeyCount = destinationNode->values->keyCount +
                         sourceNode->values->keyCount;
      if (!EnsureHashSetCapacity(&destinationNode->values, requiredKeyCount))
        return false;
    }
  }
  return true;
}

void pfHashMapMoveEntries(pfHashMap *destination, pfHashMap *source) {
  if (destination == NULL || source == NULL || destination == source ||
      destination->bucketCount == 0)
    return;

  for (uint32_t i = 0; i < source->bucketCount; i++) {
    while (source->lookup[i] != NULL) {
      pfHashMapNode *sourceNode = source->lookup[i];
      pfHashMapNode *destinationNode = NULL;
      uint32_t hash = destination->fn(sourceNode->key);
      uint32_t bucket = hash % destination->bucketCount;

      source->lookup[i] = sourceNode->next;
      source->keyCount--;
      destinationNode =
          FindMapNode(destination, sourceNode->key, hash, NULL);
      if (destinationNode == NULL) {
        sourceNode->hash = hash;
        sourceNode->next = destination->lookup[bucket];
        destination->lookup[bucket] = sourceNode;
        destination->keyCount++;
        continue;
      }

      MergeOwnedValueSets(&destinationNode->values, &sourceNode->values);
      free(sourceNode->key);
      free(sourceNode);
    }
  }
}
