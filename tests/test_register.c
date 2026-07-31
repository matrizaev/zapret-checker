#include "allheaders.h"

#include <libxml/parser.h>

#include "pfhash.h"
#include "util.h"
#include "vendor/munit/munit.h"
#include "zapret-structures.h"

#define REGISTER_FIXTURE_DIRECTORY "tests/fixtures/register"

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

pfHashTable **ProcessRegisterZipArchive(char *registerZipArchive,
                                        bool makeNSLookup,
                                        char *timestampFile);
bool ProcessRegisterCustomBlacklist(bool makeNSLookup, char *customBlackList,
                                    pfHashTable **result);

static char *ReadRegisterFixture(const char *filename, size_t *length) {
  char path[PATH_MAX];
  struct stat status;
  char *contents = NULL;
  size_t offset = 0;
  int file = -1;
  int written = 0;

  if (filename == NULL || length == NULL)
    return NULL;
  *length = 0;
  written = snprintf(path, sizeof(path), "%s/%s",
                     REGISTER_FIXTURE_DIRECTORY, filename);
  if (written <= 0 || (size_t)written >= sizeof(path))
    return NULL;
  file = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (file == -1 || fstat(file, &status) != 0 ||
      !S_ISREG(status.st_mode) || status.st_size <= 0 ||
      (uintmax_t)status.st_size > SIZE_MAX - 1)
    goto error;
  contents = malloc((size_t)status.st_size + 1);
  if (contents == NULL)
    goto error;
  while (offset < (size_t)status.st_size) {
    ssize_t bytesRead =
        read(file, contents + offset, (size_t)status.st_size - offset);
    if (bytesRead < 0 && errno == EINTR)
      continue;
    if (bytesRead <= 0)
      goto error;
    offset += (size_t)bytesRead;
  }
  contents[offset] = '\0';
  close(file);
  *length = offset;
  return contents;

error:
  if (file != -1)
    close(file);
  free(contents);
  return NULL;
}

static bool InitializeHashTables(pfHashTable *tables[NETFILTER_TYPE_COUNT]) {
  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    tables[i] = pfHashCreate(NULL, 31);
    if (tables[i] == NULL) {
      for (size_t previous = 0; previous < i; previous++) {
        pfHashDestroy(tables[previous]);
        tables[previous] = NULL;
      }
      return false;
    }
  }
  return true;
}

static void DestroyHashTables(pfHashTable *tables[NETFILTER_TYPE_COUNT]) {
  if (tables == NULL)
    return;
  for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++) {
    pfHashDestroy(tables[i]);
    tables[i] = NULL;
  }
}

static bool ContainsDomain(pfHashTable *table, const char *domain) {
  char buffer[256];
  uint8_t *dnsName = NULL;
  bool found = false;
  int written = 0;

  if (table == NULL || domain == NULL)
    return false;
  written = snprintf(buffer, sizeof(buffer), ".%s", domain);
  if (written <= 0 || (size_t)written >= sizeof(buffer))
    return false;
  dnsName = String2DNSNotation(buffer);
  if (dnsName == NULL)
    return false;
  found = pfHashCheckKey(table, (char *)dnsName);
  free(dnsName);
  return found;
}

static void AssertSanitizedRegisterContents(
    pfHashTable *tables[NETFILTER_TYPE_COUNT]) {
  munit_assert_true(pfHashCheckExists(
      tables[NETFILTER_TYPE_HTTP], "example.com", "/blocked path"));
  munit_assert_false(
      ContainsDomain(tables[NETFILTER_TYPE_DNS],
                     "ignored-because-url-was-present.example"));
  munit_assert_false(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.1"));
  munit_assert_true(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "standalone.example"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "198.51.100.2"));
}

static MunitResult TestPlainRegisterDocuments(
    const MunitParameter parameters[], void *fixture) {
  static char blacklistPath[] = REGISTER_FIXTURE_DIRECTORY "/blacklist.xml";
  static char socialPath[] = REGISTER_FIXTURE_DIRECTORY "/social.xml";
  pfHashTable *tables[NETFILTER_TYPE_COUNT] = {0};

  (void)parameters;
  (void)fixture;

  munit_assert_true(InitializeHashTables(tables));
  munit_assert_true(
      ProcessRegisterCustomBlacklist(false, blacklistPath, tables));
  AssertSanitizedRegisterContents(tables);

  munit_assert_true(ProcessRegisterCustomBlacklist(false, socialPath, tables));
  munit_assert_true(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "social.example"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "203.0.113.0/24"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "2001:db8::/32"));

  DestroyHashTables(tables);
  return MUNIT_OK;
}

static MunitResult TestBase64ZipRegister(
    const MunitParameter parameters[], void *fixture) {
  char *encodedArchive = NULL;
  size_t encodedLength = 0;
  pfHashTable **tables = NULL;

  (void)parameters;
  (void)fixture;

  encodedArchive =
      ReadRegisterFixture("blacklist.zip.base64", &encodedLength);
  munit_assert_not_null(encodedArchive);
  while (encodedLength > 0 &&
         isspace((unsigned char)encodedArchive[encodedLength - 1]))
    encodedArchive[--encodedLength] = '\0';

  tables = ProcessRegisterZipArchive(encodedArchive, false, NULL);
  munit_assert_not_null(tables);
  munit_assert_uint32(tables[NETFILTER_TYPE_HTTP]->numEntries, ==,
                      ZAPRET_HTTP_HASH_BUCKET_COUNT);
  munit_assert_uint32(tables[NETFILTER_TYPE_DNS]->numEntries, ==,
                      ZAPRET_DNS_HASH_BUCKET_COUNT);
  munit_assert_uint32(tables[NETFILTER_TYPE_IP]->numEntries, ==,
                      ZAPRET_IP_HASH_BUCKET_COUNT);
  AssertSanitizedRegisterContents(tables);

  DestroyHashTables(tables);
  free(tables);
  free(encodedArchive);
  Base64Cleanup();
  return MUNIT_OK;
}

static MunitResult TestInvalidArchiveIsRejected(
    const MunitParameter parameters[], void *fixture) {
  char invalidArchive[] = "bm90IGEgemlwIGFyY2hpdmU=";

  (void)parameters;
  (void)fixture;

  munit_assert_null(
      ProcessRegisterZipArchive(invalidArchive, false, NULL));
  Base64Cleanup();
  return MUNIT_OK;
}

static MunitTest RegisterTests[] = {
    {"/plain-register-documents", TestPlainRegisterDocuments, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/base64-zip-register", TestBase64ZipRegister, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-archive-is-rejected", TestInvalidArchiveIsRejected, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite RegisterSuite = {
    "/register", RegisterTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&RegisterSuite, NULL, argc, argv);
}
