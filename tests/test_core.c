#include "allheaders.h"

#include "pfhash.h"
#include "util.h"
#include "vendor/munit/munit.h"

static MunitResult TestBase64KnownVectors(const MunitParameter parameters[],
                                          void *fixture) {
  static const struct {
    const char *plain;
    const char *encoded;
  } vectors[] = {
      {"M", "TQ=="},
      {"Ma", "TWE="},
      {"Man", "TWFu"},
      {"hello world", "aGVsbG8gd29ybGQ="},
  };

  (void)parameters;
  (void)fixture;

  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    size_t encodedLength = 0;
    char *encoded =
        Base64Encode(vectors[i].plain, strlen(vectors[i].plain), &encodedLength);

    munit_assert_not_null(encoded);
    munit_assert_size(encodedLength, ==, strlen(vectors[i].encoded));
    munit_assert_string_equal(encoded, vectors[i].encoded);

    size_t decodedLength = 0;
    void *decoded = Base64Decode(encoded, encodedLength, &decodedLength);
    munit_assert_not_null(decoded);
    munit_assert_size(decodedLength, ==, strlen(vectors[i].plain));
    munit_assert_memory_equal(decodedLength, decoded, vectors[i].plain);

    free(decoded);
    free(encoded);
  }

  Base64Cleanup();
  return MUNIT_OK;
}

static MunitResult TestStringUtilities(const MunitParameter parameters[],
                                       void *fixture) {
  char padded[] = " \t hello world \r\n";
  char whitespace[] = " \t\r\n";
  char encodedUrl[] = "hello%20world+again%2Fok";
  char mixedCase[] = "AbC-123_XyZ";

  (void)parameters;
  (void)fixture;

  munit_assert_string_equal(TrimWhiteSpaces(padded), "hello world");
  munit_assert_null(TrimWhiteSpaces(whitespace));

  DecodeURL(encodedUrl);
  munit_assert_string_equal(encodedUrl, "hello world again/ok");

  LowerStringCase(mixedCase);
  munit_assert_string_equal(mixedCase, "abc-123_xyz");

  return MUNIT_OK;
}

static MunitResult TestHexConversion(const MunitParameter parameters[],
                                     void *fixture) {
  const unsigned char expected[] = {0x00, 0x7f, 0xa5, 0xff};
  unsigned char output[sizeof(expected)] = {0};
  size_t outputLength = 0;

  (void)parameters;
  (void)fixture;

  munit_assert_int(hex_to_bytes("00 7fA5 ff", output, &outputLength), ==, 0);
  munit_assert_size(outputLength, ==, sizeof(expected));
  munit_assert_memory_equal(sizeof(expected), output, expected);

  munit_assert_int(hex_to_bytes("0", output, &outputLength), ==, -1);
  munit_assert_int(hex_to_bytes("gg", output, &outputLength), ==, -1);

  return MUNIT_OK;
}

static MunitResult TestDnsNotationRoundTrip(
    const MunitParameter parameters[], void *fixture) {
  static const uint8_t expected[] = {
      3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm',
      'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
  };
  uint8_t invalid[] = {64, 'a', 0};
  char domain[] = ".WWW.Example.COM";
  uint8_t *notation = String2DNSNotation(domain);

  (void)parameters;
  (void)fixture;

  munit_assert_not_null(notation);
  munit_assert_memory_equal(sizeof(expected), notation, expected);
  munit_assert_true(DNSNotation2String(notation));
  munit_assert_string_equal((char *)notation, ".www.example.com");
  free(notation);

  munit_assert_false(DNSNotation2String(invalid));
  return MUNIT_OK;
}

static uint32_t CollidingHash(const char *key) {
  (void)key;
  return 1;
}

static MunitResult TestHashTableOperationsAndCollisions(
    const MunitParameter parameters[], void *fixture) {
  pfHashSet *set = pfHashSetCreate(CollidingHash, 4);
  pfHashSet *sourceSet = pfHashSetCreate(CollidingHash, 4);
  pfHashMap *map = pfHashMapCreate(CollidingHash, 4);
  pfHashMap *sourceMap = pfHashMapCreate(CollidingHash, 4);
  const pfHashSet *values = NULL;

  (void)parameters;
  (void)fixture;

  munit_assert_not_null(set);
  munit_assert_not_null(sourceSet);
  munit_assert_not_null(map);
  munit_assert_not_null(sourceMap);
  munit_assert_true(pfHashSetAdd(set, "alpha"));
  munit_assert_true(pfHashSetAdd(set, "beta"));
  munit_assert_true(pfHashSetAdd(set, "alpha"));
  munit_assert_size(set->keyCount, ==, 2);
  munit_assert_true(pfHashSetContains(set, "alpha"));
  munit_assert_true(pfHashSetContains(set, "beta"));
  munit_assert_false(pfHashSetContains(set, "missing"));
  munit_assert_true(pfHashSetDelete(set, "alpha"));
  munit_assert_false(pfHashSetContains(set, "alpha"));
  munit_assert_false(pfHashSetDelete(set, "alpha"));
  munit_assert_true(pfHashSetAdd(sourceSet, "gamma"));
  pfHashSetMoveEntries(set, sourceSet);
  munit_assert_true(pfHashSetContains(set, "gamma"));
  munit_assert_size(sourceSet->keyCount, ==, 0);

  munit_assert_true(pfHashMapAdd(map, "example.com", "one"));
  munit_assert_true(pfHashMapAdd(map, "example.com", "two"));
  munit_assert_true(pfHashMapAdd(map, "example.com", "one"));
  munit_assert_true(pfHashMapContains(map, "example.com", "one"));
  munit_assert_true(pfHashMapContains(map, "example.com", "two"));
  munit_assert_false(pfHashMapContains(map, "example.com", "missing"));
  values = pfHashMapFind(map, "example.com");
  munit_assert_not_null(values);
  munit_assert_size(values->keyCount, ==, 2);
  munit_assert_null(pfHashMapFind(map, "missing.example"));
  munit_assert_true(pfHashMapAdd(sourceMap, "example.com", "three"));
  munit_assert_true(pfHashMapAdd(sourceMap, "other.example", "/"));
  munit_assert_true(pfHashMapPrepareMoveEntries(map, sourceMap));
  pfHashMapMoveEntries(map, sourceMap);
  munit_assert_true(pfHashMapContains(map, "example.com", "three"));
  munit_assert_true(pfHashMapContains(map, "other.example", "/"));
  munit_assert_size(sourceMap->keyCount, ==, 0);

  pfHashMapDestroy(sourceMap);
  pfHashMapDestroy(map);
  pfHashSetDestroy(sourceSet);
  pfHashSetDestroy(set);
  return MUNIT_OK;
}

static MunitTest CoreTests[] = {
    {"/base64-known-vectors", TestBase64KnownVectors, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/string-utilities", TestStringUtilities, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/hex-conversion", TestHexConversion, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/dns-notation-round-trip", TestDnsNotationRoundTrip, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/hash-table-operations-and-collisions",
     TestHashTableOperationsAndCollisions, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite CoreSuite = {
    "/core", CoreTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&CoreSuite, NULL, argc, argv);
}
