#include "allheaders.h"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libxml/parser.h>

#include "vendor/munit/munit.h"

#define main ZapretCheckerMain
#include "../zapret-checker.c"
#undef main

#define SOAP_FIXTURE_DIRECTORY "tests/fixtures/soap"
#define REGISTER_ARCHIVE_FIXTURE \
  "tests/fixtures/register/blacklist.zip.base64"

typedef struct {
  char directory[PATH_MAX];
  char configurationFile[PATH_MAX];
  char customBlacklist[PATH_MAX];
  char timestampFile[PATH_MAX];
  char *soapResponses[4];
  size_t soapResponseLengths[4];
} TComponentFixture;

static TComponentFixture *activeFixture = NULL;
static TNetfilterContext **httpContexts = NULL;
static TNetfilterContext **dnsContexts = NULL;
static size_t netfilterInitializationCount = 0;
static size_t startCount = 0;
static size_t stopCount = 0;
static size_t smtpCount = 0;
static size_t signingCount = 0;
static size_t httpCount = 0;
static size_t sleepCount = 0;
static size_t archiveProcessingCount = 0;
static bool finalHTTPTableObserved = false;
static bool finalDNSTableObserved = false;
static bool finalIPTableObserved = false;

static bool BufferContains(const void *buffer, size_t bufferLength,
                           const char *needle) {
  return buffer != NULL && needle != NULL &&
         memmem(buffer, bufferLength, needle, strlen(needle)) != NULL;
}

static char *ReadFile(const char *path, size_t *length) {
  struct stat status;
  char *contents = NULL;
  int descriptor = -1;
  size_t offset = 0;

  if (path == NULL || length == NULL)
    return NULL;
  *length = 0;
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
      !S_ISREG(status.st_mode) || status.st_size < 0 ||
      (uintmax_t)status.st_size > SIZE_MAX - 1)
    goto error;
  contents = malloc((size_t)status.st_size + 1);
  if (contents == NULL)
    goto error;
  while (offset < (size_t)status.st_size) {
    ssize_t bytesRead =
        read(descriptor, contents + offset, (size_t)status.st_size - offset);
    if (bytesRead < 0 && errno == EINTR)
      continue;
    if (bytesRead <= 0)
      goto error;
    offset += (size_t)bytesRead;
  }
  contents[offset] = '\0';
  close(descriptor);
  *length = offset;
  return contents;

error:
  if (descriptor >= 0)
    close(descriptor);
  free(contents);
  return NULL;
}

static bool WriteFile(const char *path, const char *contents) {
  FILE *file = NULL;
  size_t length = 0;
  bool result = false;

  if (path == NULL || contents == NULL)
    return false;
  file = fopen(path, "wb");
  if (file == NULL)
    return false;
  length = strlen(contents);
  result = fwrite(contents, 1, length, file) == length;
  if (fclose(file) != 0)
    result = false;
  return result;
}

static char *ReadSOAPFixture(const char *filename, size_t *length) {
  char path[PATH_MAX];
  int written = snprintf(path, sizeof(path), "%s/%s", SOAP_FIXTURE_DIRECTORY,
                         filename);
  if (written <= 0 || (size_t)written >= sizeof(path))
    return NULL;
  return ReadFile(path, length);
}

static char *ReadArchiveBase64(void) {
  size_t length = 0;
  char *contents = ReadFile(REGISTER_ARCHIVE_FIXTURE, &length);
  size_t output = 0;

  if (contents == NULL)
    return NULL;
  for (size_t i = 0; i < length; i++) {
    if (!isspace((unsigned char)contents[i]))
      contents[output++] = contents[i];
  }
  contents[output] = '\0';
  return contents;
}

static char *BuildCompleteResponse(const char *archive, size_t *length) {
  static const char responseTemplate[] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/"
      "envelope/\"><SOAP-ENV:Body>"
      "<ns1:getResultResponse xmlns:ns1=\"urn:zapret-checker:test\">"
      "<result>true</result><registerZipArchive>%s</registerZipArchive>"
      "<resultCode>1</resultCode><dumpFormatVersion>synthetic-format</"
      "dumpFormatVersion><operatorName>Synthetic Operator</operatorName>"
      "<inn>0000000000</inn></ns1:getResultResponse>"
      "</SOAP-ENV:Body></SOAP-ENV:Envelope>";
  char *result = NULL;
  int required = 0;

  if (archive == NULL || length == NULL)
    return NULL;
  required = snprintf(NULL, 0, responseTemplate, archive);
  if (required < 0)
    return NULL;
  result = malloc((size_t)required + 1);
  if (result == NULL)
    return NULL;
  if (snprintf(result, (size_t)required + 1, responseTemplate, archive) !=
      required) {
    free(result);
    return NULL;
  }
  *length = (size_t)required;
  return result;
}

static bool WriteSyntheticInputs(TComponentFixture *fixture) {
  static const char customBlacklist[] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<register updateTime=\"2026-07-31T12:00:00+00:00\">"
      "<content><url>http://Custom.Example/local%20path</url>"
      "<ip>203.0.113.99</ip></content></register>";
  static const char configurationTemplate[] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<zapret-checker><redirect><host>192.0.2.10</host>"
      "<http queue=\"10\" count=\"1\"/><dns queue=\"20\" count=\"1\"/>"
      "<iface>synthetic0</iface></redirect><smtp>"
      "<host>mail.example.test</host><sender>sender@example.test</sender>"
      "<recipient attachments=\"true\">recipient@example.test</recipient>"
      "</smtp><rknBlacklist><host>soap.example.test</host>"
      "<privateKey password=\"secret\">0a0b</privateKey>"
      "<cooldown positive=\"1\" negative=\"1\"/>"
      "<timestampFile>timestamp</timestampFile><request>"
      "<requestTime>2026-07-31T12:00:00Z</requestTime>"
      "<operatorName>Synthetic Operator</operatorName><inn>0000000000</inn>"
      "<ogrn>0000000000000</ogrn><email>operator@example.test</email>"
      "</request></rknBlacklist><customBlacklist>custom.xml</customBlacklist>"
      "</zapret-checker>";

  return WriteFile(fixture->customBlacklist, customBlacklist) &&
         WriteFile(fixture->configurationFile, configurationTemplate);
}

static void *ComponentSetup(const MunitParameter parameters[],
                            void *userData) {
  static const char *const responseNames[] = {
      "get-last-dump-date-response.xml",
      "send-request-response.xml",
      NULL,
      "get-social-result-response.xml",
  };
  TComponentFixture *fixture = calloc(1, sizeof(*fixture));
  char directoryTemplate[] = "/tmp/zapret-components-XXXXXX";
  char *archive = NULL;
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
  munit_assert_true(WriteSyntheticInputs(fixture));

  archive = ReadArchiveBase64();
  munit_assert_not_null(archive);
  for (size_t i = 0; i < 4; i++) {
    if (i == 2)
      fixture->soapResponses[i] =
          BuildCompleteResponse(archive, &fixture->soapResponseLengths[i]);
    else
      fixture->soapResponses[i] = ReadSOAPFixture(
          responseNames[i], &fixture->soapResponseLengths[i]);
    munit_assert_not_null(fixture->soapResponses[i]);
  }
  free(archive);
  activeFixture = fixture;
  return fixture;
}

static void ComponentTearDown(void *fixtureData) {
  TComponentFixture *fixture = fixtureData;

  activeFixture = NULL;
  httpContexts = NULL;
  dnsContexts = NULL;
  if (fixture == NULL)
    return;
  for (size_t i = 0; i < 4; i++)
    free(fixture->soapResponses[i]);
  unlink(fixture->timestampFile);
  unlink(fixture->customBlacklist);
  unlink(fixture->configurationFile);
  rmdir(fixture->directory);
  free(fixture);
}

TNetfilterContext **
InitNetfilterConfiguration(size_t count, char *redirectIface,
                           char *redirectHost, size_t netfilterQueue,
                           TNetfilterType threadType) {
  munit_assert_size(count, ==, 1);
  munit_assert_string_equal(redirectIface, "synthetic0");
  munit_assert_string_equal(redirectHost, "192.0.2.10");
  if (threadType == NETFILTER_TYPE_HTTP)
    munit_assert_size(netfilterQueue, ==, 10);
  else {
    munit_assert_int(threadType, ==, NETFILTER_TYPE_DNS);
    munit_assert_size(netfilterQueue, ==, 20);
  }
  TNetfilterContext **result = calloc(count, sizeof(*result));
  munit_assert_not_null(result);
  if (threadType == NETFILTER_TYPE_HTTP)
    httpContexts = result;
  else
    dnsContexts = result;
  netfilterInitializationCount++;
  return result;
}

static bool HasDNSDomain(const pfHashSet *dnsNames, const char *domain) {
  char buffer[128];
  uint8_t *notation = NULL;
  bool result = false;
  int written = snprintf(buffer, sizeof(buffer), "%s", domain);

  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(buffer));
  notation = String2DNSNotation(buffer);
  munit_assert_not_null(notation);
  result = pfHashSetContains(dnsNames, (char *)notation);
  free(notation);
  return result;
}

void StartHTTPNetfilterProcessing(TNetfilterContext **contexts, size_t count,
                                  const pfHashMap *httpRules) {
  munit_assert_size(count, ==, 1);
  munit_assert_ptr_equal(contexts, httpContexts);
  munit_assert_not_null(httpRules);
  munit_assert_true(
      pfHashMapContains(httpRules, "custom.example", "/local path"));
  if (startCount >= 2) {
    munit_assert_true(
        pfHashMapContains(httpRules, "example.com", "/blocked path"));
    finalHTTPTableObserved = true;
  }
  startCount++;
}

void StartDNSNetfilterProcessing(TNetfilterContext **contexts, size_t count,
                                 const pfHashSet *dnsNames) {
  munit_assert_size(count, ==, 1);
  munit_assert_ptr_equal(contexts, dnsContexts);
  munit_assert_not_null(dnsNames);
  if (startCount >= 2) {
    munit_assert_true(HasDNSDomain(dnsNames, "standalone.example"));
    finalDNSTableObserved = true;
  }
  startCount++;
}

void StopNetfilterProcessing(TNetfilterContext **contexts, size_t count) {
  munit_assert_size(count, ==, 1);
  munit_assert_true(contexts == httpContexts || contexts == dnsContexts);
  stopCount++;
}

int nfq_destroy_queue(struct nfq_q_handle *queue) {
  (void)queue;
  return 0;
}

int nfq_close(struct nfq_handle *handle) {
  (void)handle;
  return 0;
}

bool SendSMTPMessage(TSMTPContext *smtpContext, TSOAPContext *soapContext) {
  munit_assert_not_null(smtpContext);
  munit_assert_string_equal(smtpContext->smtpHost,
                            "smtp://mail.example.test/");
  munit_assert_string_equal(smtpContext->smtpSender,
                            "sender@example.test");
  munit_assert_not_null(smtpContext->recipients[0]);
  munit_assert_string_equal(smtpContext->recipients[0]->data,
                            "recipient@example.test");
  munit_assert_not_null(soapContext);
  munit_assert_true(soapContext->soapResult);
  munit_assert_not_null(soapContext->registerZipArchive);
  smtpCount++;
  return true;
}

uint8_t *SigningPerform(void *input, size_t inputLength, size_t *outputLength,
                        uint8_t *userPIN, size_t userPINLength,
                        uint8_t *keyPairId, size_t keyPairIdLength,
                        size_t slot) {
  static const uint8_t syntheticSignature[] = {0x53, 0x49, 0x47, 0x00};
  uint8_t *result = NULL;

  munit_assert_not_null(input);
  munit_assert_size(inputLength, >, 0);
  munit_assert_true(
      BufferContains(input, inputLength, "Synthetic Operator"));
  munit_assert_true(BufferContains(input, inputLength, "0000000000"));
  munit_assert_memory_equal(strlen("secret"), userPIN, "secret");
  munit_assert_size(userPINLength, ==, strlen("secret"));
  static const uint8_t expectedKeyId[] = {0x0a, 0x0b};
  munit_assert_memory_equal(sizeof(expectedKeyId), keyPairId, expectedKeyId);
  munit_assert_size(keyPairIdLength, ==, sizeof(expectedKeyId));
  munit_assert_size(slot, ==, 0);
  munit_assert_not_null(outputLength);
  result = malloc(sizeof(syntheticSignature));
  munit_assert_not_null(result);
  memcpy(result, syntheticSignature, sizeof(syntheticSignature));
  *outputLength = sizeof(syntheticSignature);
  signingCount++;
  return result;
}

void *__wrap_SendHTTPPost(const char *url, const void *payload,
                          char *httpHeaders[], size_t httpHeadersCount,
                          size_t inputLength, size_t *outputLength) {
  static const char *const methods[] = {
      "getLastDumpDateEx", "sendRequest", "getResult",
      "getResultSocResources",
  };
  char methodTag[96];
  void *result = NULL;
  int written = 0;

  munit_assert_not_null(activeFixture);
  munit_assert_size(httpCount, <, 4);
  munit_assert_string_equal(
      url, "https://soap.example.test/services/OperatorRequest/");
  munit_assert_not_null(payload);
  munit_assert_size(inputLength, >, 0);
  munit_assert_size(httpHeadersCount, ==, 5);
  munit_assert_not_null(httpHeaders);
  munit_assert_not_null(httpHeaders[4]);
  written = snprintf(methodTag, sizeof(methodTag), ":%s", methods[httpCount]);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof(methodTag));
  munit_assert_true(BufferContains(payload, inputLength, methodTag));
  munit_assert_not_null(strstr(httpHeaders[4], methods[httpCount]));
  if (httpCount == 1) {
    munit_assert_true(BufferContains(payload, inputLength, "requestFile"));
    munit_assert_true(BufferContains(payload, inputLength, "signatureFile"));
  }

  result = malloc(activeFixture->soapResponseLengths[httpCount] + 1);
  munit_assert_not_null(result);
  memcpy(result, activeFixture->soapResponses[httpCount],
         activeFixture->soapResponseLengths[httpCount] + 1);
  *outputLength = activeFixture->soapResponseLengths[httpCount];
  httpCount++;
  return result;
}

TZapretBlacklist *__real_ProcessRegisterZipArchive(char *registerZipArchive,
                                                   bool makeNSLookup,
                                                   char *timestampFile);
TZapretBlacklist *__wrap_ProcessRegisterZipArchive(char *registerZipArchive,
                                                   bool makeNSLookup,
                                                   char *timestampFile) {
  munit_assert_not_null(activeFixture);
  munit_assert_false(makeNSLookup);
  munit_assert_string_equal(timestampFile, activeFixture->timestampFile);
  TZapretBlacklist *result = __real_ProcessRegisterZipArchive(
      registerZipArchive, makeNSLookup, timestampFile);
  munit_assert_not_null(result);
  munit_assert_true(
      pfHashMapContains(result->httpRules, "example.com", "/blocked path"));
  munit_assert_true(
      HasDNSDomain(result->dnsNames, "standalone.example"));
  munit_assert_true(
      pfHashSetContains(result->ipAddresses, "198.51.100.2"));
  finalIPTableObserved = true;
  archiveProcessingCount++;
  return result;
}

unsigned int __wrap_sleep(unsigned int seconds) {
  munit_assert_uint(seconds, ==, 1);
  sleepCount++;
  if (sleepCount == 3)
    flagMatrixShutdown = 1;
  return 0;
}

static MunitResult TestSyntheticProductionComponentReplay(
    const MunitParameter parameters[], void *fixtureData) {
  TComponentFixture *fixture = fixtureData;
  char *arguments[] = {"zapret-checker", "--config",
                       fixture->configurationFile, NULL};

  (void)parameters;
  activeFixture = fixture;
  httpContexts = NULL;
  dnsContexts = NULL;
  netfilterInitializationCount = 0;
  startCount = 0;
  stopCount = 0;
  smtpCount = 0;
  signingCount = 0;
  httpCount = 0;
  sleepCount = 0;
  archiveProcessingCount = 0;
  finalHTTPTableObserved = false;
  finalDNSTableObserved = false;
  finalIPTableObserved = false;
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 1;
  flagMatrixReload = 0;

  munit_assert_int(ZapretCheckerMain(3, arguments), ==, EXIT_SUCCESS);
  munit_assert_size(netfilterInitializationCount, ==, 2);
  munit_assert_size(signingCount, ==, 1);
  munit_assert_size(httpCount, ==, 4);
  munit_assert_size(archiveProcessingCount, ==, 1);
  munit_assert_size(smtpCount, ==, 1);
  munit_assert_size(startCount, ==, 4);
  munit_assert_size(stopCount, ==, 4);
  munit_assert_size(sleepCount, ==, 3);
  munit_assert_true(finalHTTPTableObserved);
  munit_assert_true(finalDNSTableObserved);
  munit_assert_true(finalIPTableObserved);
  munit_assert_int(access(fixture->timestampFile, R_OK), ==, 0);
  return MUNIT_OK;
}

static MunitTest componentTests[] = {
    {"/synthetic-production-replay", TestSyntheticProductionComponentReplay,
     ComponentSetup, ComponentTearDown, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite componentSuite = {
    "/checker-components", componentTests, NULL, 1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&componentSuite, NULL, argc, argv);
}
