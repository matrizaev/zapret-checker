#include "allheaders.h"

#include <libxml/parser.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#define CONFIGURATION_FIXTURE \
  "tests/fixtures/configuration/zapret-checker.xml"

typedef struct {
  char directory[PATH_MAX];
  char configurationFile[PATH_MAX];
  char customBlacklist[PATH_MAX];
  char timestampFile[PATH_MAX];
} ConfigurationFixture;

static size_t netfilterInitializationCount = 0;

TNetfilterContext **
InitNetfilterConfiguration(size_t count, char *redirectIface,
                           char *redirectHost, size_t netfilterQueue,
                           TNetfilterType threadType) {
  (void)redirectIface;
  (void)redirectHost;
  (void)netfilterQueue;
  (void)threadType;

  netfilterInitializationCount++;
  return calloc(count, sizeof(TNetfilterContext *));
}

static bool WriteTextFile(const char *path, const char *contents) {
  FILE *file = NULL;
  size_t contentsLength = 0;
  bool result = false;

  if (path == NULL || contents == NULL)
    return false;
  file = fopen(path, "wb");
  if (file == NULL)
    return false;
  contentsLength = strlen(contents);
  result = fwrite(contents, 1, contentsLength, file) == contentsLength;
  if (!result) {
    fclose(file);
    return false;
  }
  return fclose(file) == 0;
}

static bool CopyFile(const char *sourcePath, const char *destinationPath) {
  unsigned char buffer[4096];
  FILE *source = NULL;
  FILE *destination = NULL;
  bool result = false;
  size_t bytesRead = 0;

  if (sourcePath == NULL || destinationPath == NULL)
    return false;
  source = fopen(sourcePath, "rb");
  if (source == NULL)
    goto error;
  destination = fopen(destinationPath, "wb");
  if (destination == NULL)
    goto error;
  while ((bytesRead = fread(buffer, 1, sizeof(buffer), source)) > 0) {
    if (fwrite(buffer, 1, bytesRead, destination) != bytesRead)
      goto error;
  }
  if (ferror(source))
    goto error;
  result = true;

error:
  if (destination != NULL && fclose(destination) != 0)
    result = false;
  if (source != NULL && fclose(source) != 0)
    result = false;
  return result;
}

static void FreeConfiguration(TZapretContext *context) {
  if (context == NULL)
    return;
  if (context->smtpContext != NULL) {
    free(context->smtpContext->smtpHost);
    free(context->smtpContext->smtpSender);
    for (size_t i = 0; i < SMTP_RECIPIENTS_LIST_COUNT; i++)
      curl_slist_free_all(context->smtpContext->recipients[i]);
    free(context->smtpContext);
  }
  free(context->httpThreadsContext);
  free(context->dnsThreadsContext);
  free(context->redirectHost);
  free(context->redirectIface);
  free(context->redirectIpsetList);
  free(context->blacklistHost);
  free(context->timestampFile);
  free(context->customBlacklist);
  free(context->privateKeyId);
  free(context->privateKeyPassword);
  if (context->requestXmlDoc != NULL)
    xmlFreeDoc(context->requestXmlDoc);
  memset(context, 0, sizeof(*context));
}

static void *ConfigurationSetup(const MunitParameter parameters[],
                                void *userData) {
  ConfigurationFixture *fixture = calloc(1, sizeof(*fixture));
  char directoryTemplate[] = "/tmp/zapret-configuration-XXXXXX";
  int written = 0;

  (void)parameters;
  (void)userData;

  munit_assert_not_null(fixture);
  munit_assert_not_null(mkdtemp(directoryTemplate));
  written = snprintf(fixture->directory, sizeof(fixture->directory), "%s",
                     directoryTemplate);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(fixture->directory));
  written = snprintf(fixture->configurationFile,
                     sizeof(fixture->configurationFile), "%s/config.xml",
                     fixture->directory);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(fixture->configurationFile));
  written = snprintf(fixture->customBlacklist,
                     sizeof(fixture->customBlacklist), "%s/custom.xml",
                     fixture->directory);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(fixture->customBlacklist));
  written = snprintf(fixture->timestampFile, sizeof(fixture->timestampFile),
                     "%s/timestamp", fixture->directory);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(fixture->timestampFile));
  munit_assert_true(
      WriteTextFile(fixture->customBlacklist, "<customBlacklist/>"));
  return fixture;
}

static void ConfigurationTearDown(void *fixtureData) {
  ConfigurationFixture *fixture = fixtureData;

  if (fixture == NULL)
    return;
  unlink(fixture->timestampFile);
  unlink(fixture->customBlacklist);
  unlink(fixture->configurationFile);
  rmdir(fixture->directory);
  free(fixture);
}

static MunitResult TestLoadsConfigurationFromExplicitPath(
    const MunitParameter parameters[], void *fixtureData) {
  ConfigurationFixture *fixture = fixtureData;
  TZapretContext context = {0};
  char currentDirectoryBefore[PATH_MAX];
  char currentDirectoryAfter[PATH_MAX];

  (void)parameters;

  munit_assert_not_null(getcwd(currentDirectoryBefore,
                               sizeof(currentDirectoryBefore)));
  munit_assert_true(
      CopyFile(CONFIGURATION_FIXTURE, fixture->configurationFile));
  netfilterInitializationCount = 0;
  munit_assert_true(
      ReadZapretConfiguration(&context, fixture->configurationFile));
  munit_assert_not_null(
      getcwd(currentDirectoryAfter, sizeof(currentDirectoryAfter)));

  munit_assert_string_equal(currentDirectoryAfter, currentDirectoryBefore);
  munit_assert_string_equal(context.redirectHost, "192.0.2.10");
  munit_assert_string_equal(context.redirectIface, "eth0");
  munit_assert_string_equal(context.redirectIpsetList, "blocked");
  munit_assert_true(context.redirectNSLookup);
  munit_assert_size(context.redirectHTTPQueue, ==, 10);
  munit_assert_size(context.redirectHTTPCount, ==, 2);
  munit_assert_size(context.redirectDNSQueue, ==, 20);
  munit_assert_size(context.redirectDNSCount, ==, 1);
  munit_assert_size(netfilterInitializationCount, ==, 2);
  munit_assert_not_null(context.httpThreadsContext);
  munit_assert_not_null(context.dnsThreadsContext);

  munit_assert_not_null(context.smtpContext);
  munit_assert_string_equal(context.smtpContext->smtpHost,
                            "smtp://mail.example.test/");
  munit_assert_string_equal(context.smtpContext->smtpSender,
                            "sender@example.test");
  munit_assert_string_equal(context.smtpContext->recipients[0]->data,
                            "archive@example.test");
  munit_assert_string_equal(context.smtpContext->recipients[1]->data,
                            "notice@example.test");

  munit_assert_string_equal(context.blacklistHost,
                            "https://soap.example.test/");
  munit_assert_size(context.privateKeyIdLen, ==, 2);
  munit_assert_uchar((unsigned char)context.privateKeyId[0], ==, 0x0a);
  munit_assert_uchar((unsigned char)context.privateKeyId[1], ==, 0x0b);
  munit_assert_string_equal(context.privateKeyPassword, "secret");
  munit_assert_int64(context.blacklistCooldownPositive, ==, 60);
  munit_assert_int64(context.blacklistCooldownNegative, ==, 30);
  munit_assert_string_equal(context.timestampFile, fixture->timestampFile);
  munit_assert_int(access(context.timestampFile, F_OK), ==, 0);
  munit_assert_not_null(context.requestXmlDoc);
  munit_assert_string_equal(context.customBlacklist,
                            fixture->customBlacklist);

  FreeConfiguration(&context);
  return MUNIT_OK;
}

static MunitResult TestRejectsMissingConfiguration(
    const MunitParameter parameters[], void *fixtureData) {
  ConfigurationFixture *fixture = fixtureData;
  TZapretContext context = {0};

  (void)parameters;

  munit_assert_false(
      ReadZapretConfiguration(&context, fixture->configurationFile));
  FreeConfiguration(&context);
  return MUNIT_OK;
}

static MunitResult TestRejectsInvalidConfiguration(
    const MunitParameter parameters[], void *fixtureData) {
  ConfigurationFixture *fixture = fixtureData;
  TZapretContext context = {0};

  (void)parameters;

  munit_assert_true(WriteTextFile(
      fixture->configurationFile,
      "<zapret-checker><smtp/></zapret-checker>"));
  munit_assert_false(
      ReadZapretConfiguration(&context, fixture->configurationFile));
  FreeConfiguration(&context);
  return MUNIT_OK;
}

static MunitResult TestRejectsInvalidArguments(
    const MunitParameter parameters[], void *fixtureData) {
  ConfigurationFixture *fixture = fixtureData;
  TZapretContext context = {0};

  (void)parameters;

  munit_assert_false(ReadZapretConfiguration(NULL, fixture->configurationFile));
  munit_assert_false(ReadZapretConfiguration(&context, NULL));
  munit_assert_false(ReadZapretConfiguration(&context, ""));
  return MUNIT_OK;
}

static MunitTest configurationTests[] = {
    {"/explicit-path", TestLoadsConfigurationFromExplicitPath,
     ConfigurationSetup, ConfigurationTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/missing-file", TestRejectsMissingConfiguration, ConfigurationSetup,
     ConfigurationTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-file", TestRejectsInvalidConfiguration, ConfigurationSetup,
     ConfigurationTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-arguments", TestRejectsInvalidArguments, ConfigurationSetup,
     ConfigurationTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite configurationSuite = {
    "/configuration", configurationTests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  int result = 0;

  LIBXML_TEST_VERSION
  xmlInitParser();
  result = munit_suite_main(&configurationSuite, NULL, argc, argv);
  xmlCleanupParser();
  return result;
}
