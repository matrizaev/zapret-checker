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

static size_t StringListLength(const TStringList *list) {
  size_t length = 0;

  while (list != NULL) {
    length++;
    list = list->next;
  }
  return length;
}

static MunitResult TestHashTableOperationsAndCollisions(
    const MunitParameter parameters[], void *fixture) {
  pfHashTable *table = pfHashCreate(CollidingHash, 4);

  (void)parameters;
  (void)fixture;

  munit_assert_not_null(table);
  munit_assert_true(pfHashSet(table, "alpha", "one"));
  munit_assert_true(pfHashSet(table, "alpha", "two"));
  munit_assert_true(pfHashSet(table, "alpha", "one"));
  munit_assert_true(pfHashSet(table, "beta", NULL));

  munit_assert_true(pfHashCheckKey(table, "alpha"));
  munit_assert_true(pfHashCheckExists(table, "alpha", "one"));
  munit_assert_true(pfHashCheckExists(table, "alpha", "two"));
  munit_assert_size(StringListLength(pfHashFind(table, "alpha")), ==, 2);

  munit_assert_true(pfHashCheckKey(table, "beta"));
  munit_assert_null(pfHashFind(table, "beta"));
  munit_assert_false(pfHashCheckKey(table, "missing"));

  munit_assert_true(pfHashDel(table, "alpha"));
  munit_assert_false(pfHashCheckKey(table, "alpha"));
  munit_assert_true(pfHashCheckKey(table, "beta"));
  munit_assert_false(pfHashDel(table, "alpha"));

  pfHashDestroy(table);
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
