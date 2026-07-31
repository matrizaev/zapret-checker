#include "allheaders.h"

#include <arpa/inet.h>
#include <libxml/parser.h>
#include <netdb.h>
#include <zip.h>

#include "pfhash.h"
#include "util.h"
#include "vendor/munit/munit.h"
#include "zapret-structures.h"

#define REGISTER_FIXTURE_DIRECTORY "tests/fixtures/register"

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

static size_t nsLookupCount = 0;

void __wrap_freeaddrinfo(struct addrinfo *result) {
  while (result != NULL) {
    struct addrinfo *next = result->ai_next;
    free(result->ai_addr);
    free(result);
    result = next;
  }
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **result) {
  static const char *addresses[] = {"203.0.113.7", "203.0.113.8"};
  struct addrinfo *head = NULL;
  struct addrinfo *tail = NULL;

  (void)service;
  (void)hints;
  if (result == NULL)
    return EAI_FAIL;
  *result = NULL;
  nsLookupCount++;
  if (node == NULL || strcmp(node, "standalone.example") != 0)
    return EAI_NONAME;

  for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++) {
    struct addrinfo *entry = calloc(1, sizeof(*entry));
    struct sockaddr_in *address = calloc(1, sizeof(*address));
    if (entry == NULL || address == NULL) {
      free(entry);
      free(address);
      __wrap_freeaddrinfo(head);
      return EAI_MEMORY;
    }
    address->sin_family = AF_INET;
    if (inet_pton(AF_INET, addresses[i], &address->sin_addr) != 1) {
      free(entry);
      free(address);
      __wrap_freeaddrinfo(head);
      return EAI_FAIL;
    }
    entry->ai_family = AF_INET;
    entry->ai_socktype = SOCK_STREAM;
    entry->ai_addrlen = sizeof(*address);
    entry->ai_addr = (struct sockaddr *)address;
    if (tail == NULL)
      head = entry;
    else
      tail->ai_next = entry;
    tail = entry;
  }
  *result = head;
  return 0;
}

pfHashTable **ProcessRegisterZipArchive(char *registerZipArchive,
                                        bool makeNSLookup,
                                        char *timestampFile);
bool ProcessRegisterCustomBlacklist(bool makeNSLookup, char *customBlackList,
                                    pfHashTable **result);

static char *ReadFileContents(const char *path, size_t *length) {
  struct stat status;
  char *contents = NULL;
  size_t offset = 0;
  int file = -1;

  if (path == NULL || length == NULL)
    return NULL;
  *length = 0;
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
  if (close(file) != 0)
    goto close_error;
  file = -1;
  *length = offset;
  return contents;

error:
  if (file != -1)
    close(file);
close_error:
  free(contents);
  return NULL;
}

static char *ReadRegisterFixture(const char *filename, size_t *length) {
  char path[PATH_MAX];
  int written = 0;

  if (filename == NULL || length == NULL)
    return NULL;
  written = snprintf(path, sizeof(path), "%s/%s",
                     REGISTER_FIXTURE_DIRECTORY, filename);
  if (written <= 0 || (size_t)written >= sizeof(path))
    return NULL;
  return ReadFileContents(path, length);
}

static bool WriteTemporaryFile(char path[PATH_MAX], const void *contents,
                               size_t length) {
  const uint8_t *bytes = contents;
  size_t offset = 0;
  int file = -1;

  if (path == NULL || contents == NULL)
    return false;
  file = mkstemp(path);
  if (file == -1)
    return false;
  while (offset < length) {
    ssize_t written = write(file, bytes + offset, length - offset);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      goto error;
    offset += (size_t)written;
  }
  int closeResult = close(file);
  file = -1;
  if (closeResult != 0)
    goto close_error;
  return true;

error:
  close(file);
close_error:
  unlink(path);
  return false;
}

static char *CreateZipFixture(const char *entryName, const char *xml,
                              size_t *encodedLength) {
  char zipPath[] = "/tmp/zapret-register-zip-XXXXXX";
  struct zip *archive = NULL;
  struct zip_source *source = NULL;
  char *zipBytes = NULL;
  char *encoded = NULL;
  size_t zipLength = 0;
  int file = -1;
  int zipError = 0;

  if (entryName == NULL || xml == NULL || encodedLength == NULL)
    return NULL;
  *encodedLength = 0;
  file = mkstemp(zipPath);
  if (file == -1)
    return NULL;
  int closeResult = close(file);
  file = -1;
  if (closeResult != 0)
    goto error;
  if (unlink(zipPath) != 0)
    goto error;

  archive = zip_open(zipPath, ZIP_CREATE | ZIP_TRUNCATE, &zipError);
  if (archive == NULL)
    goto error;
  source = zip_source_buffer(archive, xml, strlen(xml), 0);
  if (source == NULL)
    goto error;
  if (zip_file_add(archive, entryName, source,
                   ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE) < 0)
    goto error;
  source = NULL;
  if (zip_close(archive) != 0)
    goto error;
  archive = NULL;

  zipBytes = ReadFileContents(zipPath, &zipLength);
  if (zipBytes == NULL)
    goto error;
  encoded = Base64Encode(zipBytes, zipLength, encodedLength);

error:
  if (source != NULL)
    zip_source_free(source);
  if (archive != NULL)
    zip_discard(archive);
  if (file != -1)
    close(file);
  unlink(zipPath);
  free(zipBytes);
  return encoded;
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

static MunitResult TestStreamingPreservesFieldOrder(
    const MunitParameter parameters[], void *fixture) {
  static char orderingPath[] =
      REGISTER_FIXTURE_DIRECTORY "/streaming-order.xml";
  pfHashTable *tables[NETFILTER_TYPE_COUNT] = {0};

  (void)parameters;
  (void)fixture;

  munit_assert_true(InitializeHashTables(tables));
  munit_assert_true(pfHashSet(tables[NETFILTER_TYPE_HTTP], "order.example",
                              "/existing"));
  munit_assert_true(
      ProcessRegisterCustomBlacklist(false, orderingPath, tables));
  munit_assert_true(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "before-url.example"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.10"));
  munit_assert_true(pfHashCheckExists(
      tables[NETFILTER_TYPE_HTTP], "order.example", "/blocked path"));
  munit_assert_true(pfHashCheckExists(
      tables[NETFILTER_TYPE_HTTP], "order.example", "/existing"));
  munit_assert_false(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "after-url.example"));
  munit_assert_false(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.11"));
  munit_assert_true(ContainsDomain(tables[NETFILTER_TYPE_DNS],
                                   "after-unsupported-url.example"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "198.51.100.0/24"));
  munit_assert_true(
      ProcessRegisterCustomBlacklist(false, orderingPath, tables));
  munit_assert_true(pfHashCheckExists(
      tables[NETFILTER_TYPE_HTTP], "order.example", "/blocked path"));
  munit_assert_true(pfHashCheckExists(
      tables[NETFILTER_TYPE_HTTP], "order.example", "/existing"));

  DestroyHashTables(tables);
  return MUNIT_OK;
}

static MunitResult TestInvalidCustomBlacklistIsAtomic(
    const MunitParameter parameters[], void *fixture) {
  static char malformedPath[] =
      REGISTER_FIXTURE_DIRECTORY "/malformed.xml";
  static char emptyFieldPath[] =
      REGISTER_FIXTURE_DIRECTORY "/empty-field.xml";
  pfHashTable *tables[NETFILTER_TYPE_COUNT] = {0};

  (void)parameters;
  (void)fixture;

  munit_assert_true(InitializeHashTables(tables));
  munit_assert_true(pfHashSet(tables[NETFILTER_TYPE_IP], "192.0.2.99", NULL));
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, malformedPath, tables));
  munit_assert_false(ContainsDomain(tables[NETFILTER_TYPE_DNS],
                                    "must-not-be-committed.example"));
  munit_assert_false(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "203.0.113.20"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.99"));

  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, emptyFieldPath, tables));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.99"));

  DestroyHashTables(tables);
  return MUNIT_OK;
}

static MunitResult TestDNSLookupAndRegisterEdgeCases(
    const MunitParameter parameters[], void *fixture) {
  static const char xml[] =
      "<?xml version=\"1.0\" encoding=\"windows-1251\"?>\n"
      "<!-- comment before the root element -->\n"
      "<register updateTime=\"2024-02-03T04:05:06+00:00\">\n"
      "  <content/>\n"
      "  <content><url>http://Root.Example</url></content>\n"
      "  <content>\n"
      "    <url>http://Split.Example/blocked<![CDATA[%20path]]></url>\n"
      "  </content>\n"
      "  <content><url>http://Long.Example/"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaa</url></content>\n"
      "  <content><url>http://"
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "bbbb.example/path</url></content>\n"
      "  <content><domain>"
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "bbbb.example</domain></content>\n"
      "  <content>\n"
      "    <url>http://invalid.example:8080/path</url>\n"
      "    <domain>fallback.example</domain>\n"
      "    <ip>  203.0.113.40  </ip>\n"
      "    <ignored>not-a-register-field</ignored>\n"
      "  </content>\n"
      "  <content><domain>Standalone.Example</domain></content>\n"
      "</register>\n";
  char xmlPath[PATH_MAX] = "/tmp/zapret-register-edges-XXXXXX";
  pfHashTable *tables[NETFILTER_TYPE_COUNT] = {0};

  (void)parameters;
  (void)fixture;
  nsLookupCount = 0;
  munit_assert_true(WriteTemporaryFile(xmlPath, xml, sizeof(xml) - 1));
  munit_assert_true(InitializeHashTables(tables));
  munit_assert_true(ProcessRegisterCustomBlacklist(true, xmlPath, tables));

  munit_assert_true(
      pfHashCheckExists(tables[NETFILTER_TYPE_HTTP], "root.example", "/"));
  munit_assert_true(pfHashCheckExists(tables[NETFILTER_TYPE_HTTP],
                                      "split.example", "/blocked path"));
  munit_assert_true(pfHashCheckExists(
      tables[NETFILTER_TYPE_HTTP], "long.example",
      "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaa"));
  munit_assert_false(
      pfHashCheckKey(
          tables[NETFILTER_TYPE_HTTP],
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          "bbbb.example"));
  munit_assert_false(
      ContainsDomain(
          tables[NETFILTER_TYPE_DNS],
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          "bbbb.example"));
  munit_assert_true(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "fallback.example"));
  munit_assert_true(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "standalone.example"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "203.0.113.40"));
  munit_assert_true(pfHashCheckExists(tables[NETFILTER_TYPE_IP],
                                      "203.0.113.7", "standalone.example"));
  munit_assert_true(pfHashCheckExists(tables[NETFILTER_TYPE_IP],
                                      "203.0.113.8", "standalone.example"));
  munit_assert_size(nsLookupCount, ==, 2);

  DestroyHashTables(tables);
  munit_assert_int(unlink(xmlPath), ==, 0);
  return MUNIT_OK;
}

static MunitResult TestCustomBlacklistInputsAndInterruption(
    const MunitParameter parameters[], void *fixture) {
  static char blacklistPath[] = REGISTER_FIXTURE_DIRECTORY "/blacklist.xml";
  static const char emptyElementXml[] =
      "<register updateTime=\"2024-01-01T00:00:00+00:00\">"
      "<content><domain/></content></register>";
  char emptyElementPath[PATH_MAX] =
      "/tmp/zapret-register-empty-element-XXXXXX";
  char emptyFilePath[PATH_MAX] = "/tmp/zapret-register-empty-file-XXXXXX";
  char missingPath[] = "/tmp/zapret-register-file-does-not-exist";
  pfHashTable *tables[NETFILTER_TYPE_COUNT] = {0};
  pfHashTable *savedTable = NULL;

  (void)parameters;
  (void)fixture;
  unlink(missingPath);
  munit_assert_true(InitializeHashTables(tables));
  munit_assert_true(pfHashSet(tables[NETFILTER_TYPE_IP], "192.0.2.99", NULL));

  munit_assert_true(ProcessRegisterCustomBlacklist(false, NULL, tables));
  munit_assert_true(ProcessRegisterCustomBlacklist(false, NULL, NULL));
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, missingPath, tables));
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, blacklistPath, NULL));

  savedTable = tables[NETFILTER_TYPE_DNS];
  tables[NETFILTER_TYPE_DNS] = NULL;
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, blacklistPath, tables));
  tables[NETFILTER_TYPE_DNS] = savedTable;

  savedTable = tables[NETFILTER_TYPE_DNS];
  tables[NETFILTER_TYPE_DNS] = pfHashCreate(NULL, 0);
  munit_assert_not_null(tables[NETFILTER_TYPE_DNS]);
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, blacklistPath, tables));
  pfHashDestroy(tables[NETFILTER_TYPE_DNS]);
  tables[NETFILTER_TYPE_DNS] = savedTable;

  flagMatrixShutdown = 1;
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, blacklistPath, tables));
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 1;
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, blacklistPath, tables));
  flagMatrixReconfigure = 0;
  munit_assert_false(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "standalone.example"));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.99"));

  munit_assert_true(WriteTemporaryFile(emptyElementPath, emptyElementXml,
                                       sizeof(emptyElementXml) - 1));
  munit_assert_false(ProcessRegisterCustomBlacklist(
      false, emptyElementPath, tables));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.99"));

  munit_assert_true(WriteTemporaryFile(emptyFilePath, "", 0));
  munit_assert_false(
      ProcessRegisterCustomBlacklist(false, emptyFilePath, tables));
  munit_assert_true(
      pfHashCheckKey(tables[NETFILTER_TYPE_IP], "192.0.2.99"));

  DestroyHashTables(tables);
  munit_assert_int(unlink(emptyElementPath), ==, 0);
  munit_assert_int(unlink(emptyFilePath), ==, 0);
  return MUNIT_OK;
}

static MunitResult TestZipArchiveFailureModes(
    const MunitParameter parameters[], void *fixture) {
  static const char validXml[] =
      "<register updateTime=\"2024-03-04T05:06:07+00:00\">"
      "<content/><content><domain>zip.example</domain></content></register>";
  static const char missingTimestampXml[] =
      "<register><content><domain>missing-time.example</domain></content>"
      "</register>";
  static const char malformedXml[] =
      "<register updateTime=\"2024-01-01T00:00:00+00:00\">"
      "<content><domain>truncated.example</domain>";
  char timestampPath[PATH_MAX] =
      "/tmp/zapret-register-missing-time-XXXXXX";
  char missingTimestampPath[PATH_MAX] =
      "/tmp/zapret-register-no-output-XXXXXX";
  char timestampDirectory[PATH_MAX] =
      "/tmp/zapret-register-timestamp-dir-XXXXXX";
  char *encoded = NULL;
  char *validEncoded = NULL;
  char *fileContents = NULL;
  size_t encodedLength = 0;
  size_t contentsLength = 0;
  pfHashTable **tables = NULL;
  int temporaryFD = -1;

  (void)parameters;
  (void)fixture;
  munit_assert_null(ProcessRegisterZipArchive(NULL, false, NULL));

  encoded = CreateZipFixture("other.xml", validXml, &encodedLength);
  munit_assert_not_null(encoded);
  munit_assert_null(ProcessRegisterZipArchive(encoded, false, NULL));
  free(encoded);
  encoded = NULL;

  encoded = CreateZipFixture("dump.xml", malformedXml, &encodedLength);
  munit_assert_not_null(encoded);
  munit_assert_null(ProcessRegisterZipArchive(encoded, false, NULL));
  free(encoded);
  encoded = NULL;

  munit_assert_true(WriteTemporaryFile(timestampPath, "sentinel", 8));
  encoded =
      CreateZipFixture("dump.xml", missingTimestampXml, &encodedLength);
  munit_assert_not_null(encoded);
  munit_assert_null(
      ProcessRegisterZipArchive(encoded, false, timestampPath));
  fileContents = ReadFileContents(timestampPath, &contentsLength);
  munit_assert_not_null(fileContents);
  munit_assert_size(contentsLength, ==, 8);
  munit_assert_memory_equal(8, fileContents, "sentinel");
  free(fileContents);
  fileContents = NULL;
  free(encoded);
  encoded = NULL;
  munit_assert_int(unlink(timestampPath), ==, 0);

  validEncoded = CreateZipFixture("DUMP.XML", validXml, &encodedLength);
  munit_assert_not_null(validEncoded);
  tables = ProcessRegisterZipArchive(validEncoded, false, NULL);
  munit_assert_not_null(tables);
  munit_assert_true(
      ContainsDomain(tables[NETFILTER_TYPE_DNS], "zip.example"));
  DestroyHashTables(tables);
  free(tables);
  tables = NULL;

  temporaryFD = mkstemp(missingTimestampPath);
  munit_assert_int(temporaryFD, >=, 0);
  munit_assert_int(close(temporaryFD), ==, 0);
  temporaryFD = -1;
  munit_assert_int(unlink(missingTimestampPath), ==, 0);
  munit_assert_null(ProcessRegisterZipArchive(validEncoded, false,
                                               missingTimestampPath));

  munit_assert_not_null(mkdtemp(timestampDirectory));
  munit_assert_null(ProcessRegisterZipArchive(validEncoded, false,
                                               timestampDirectory));
  munit_assert_int(rmdir(timestampDirectory), ==, 0);

  free(validEncoded);
  Base64Cleanup();
  return MUNIT_OK;
}

static MunitResult TestBase64ZipRegister(
    const MunitParameter parameters[], void *fixture) {
  char *encodedArchive = NULL;
  char timestamp[64] = {0};
  char timestampPath[] = "/tmp/zapret-register-timestamp-XXXXXX";
  size_t encodedLength = 0;
  ssize_t timestampLength = 0;
  int timestampFD = -1;
  pfHashTable **tables = NULL;

  (void)parameters;
  (void)fixture;

  encodedArchive =
      ReadRegisterFixture("blacklist.zip.base64", &encodedLength);
  munit_assert_not_null(encodedArchive);
  while (encodedLength > 0 &&
         isspace((unsigned char)encodedArchive[encodedLength - 1]))
    encodedArchive[--encodedLength] = '\0';

  timestampFD = mkstemp(timestampPath);
  munit_assert_int(timestampFD, >=, 0);
  munit_assert_int(close(timestampFD), ==, 0);
  timestampFD = -1;

  tables = ProcessRegisterZipArchive(encodedArchive, false, timestampPath);
  munit_assert_not_null(tables);
  munit_assert_uint32(tables[NETFILTER_TYPE_HTTP]->numEntries, ==,
                      ZAPRET_HTTP_HASH_BUCKET_COUNT);
  munit_assert_uint32(tables[NETFILTER_TYPE_DNS]->numEntries, ==,
                      ZAPRET_DNS_HASH_BUCKET_COUNT);
  munit_assert_uint32(tables[NETFILTER_TYPE_IP]->numEntries, ==,
                      ZAPRET_IP_HASH_BUCKET_COUNT);
  AssertSanitizedRegisterContents(tables);
  timestampFD = open(timestampPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  munit_assert_int(timestampFD, >=, 0);
  timestampLength = read(timestampFD, timestamp, sizeof(timestamp) - 1);
  munit_assert_int64(timestampLength, >, 0);
  munit_assert_int(close(timestampFD), ==, 0);
  timestampFD = -1;
  timestamp[timestampLength] = '\0';
  munit_assert_string_equal(timestamp, "2024-01-02T03:04:05+00:00");
  munit_assert_int(unlink(timestampPath), ==, 0);

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
    {"/streaming-preserves-field-order", TestStreamingPreservesFieldOrder,
     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-custom-blacklist-is-atomic",
     TestInvalidCustomBlacklistIsAtomic, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/dns-lookup-and-register-edge-cases", TestDNSLookupAndRegisterEdgeCases,
     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/custom-blacklist-inputs-and-interruption",
     TestCustomBlacklistInputsAndInterruption, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/zip-archive-failure-modes", TestZipArchiveFailureModes, NULL, NULL,
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
  int result = munit_suite_main(&RegisterSuite, NULL, argc, argv);
  Base64Cleanup();
  xmlCleanupParser();
  return result;
}
