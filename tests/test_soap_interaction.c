#include "allheaders.h"

#include <libxml/parser.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#define SOAP_FIXTURE_DIRECTORY "tests/fixtures/soap"
#define REPLAY_EXCHANGE_COUNT 18
#define REPLAY_PENDING_COUNT 14

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

typedef struct {
  size_t exchange;
  size_t sleeps;
  bool failed;
  char error[256];
} TSoapReplay;

static TSoapReplay replay;
static const unsigned char preparedRequest[] =
    "<request><synthetic>true</synthetic></request>";
static const unsigned char preparedSignature[] = {
    0x30, 0x08, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x00,
};

static void ReplayFail(const char *message) {
  if (!replay.failed) {
    replay.failed = true;
    snprintf(replay.error, sizeof(replay.error), "%s",
             message != NULL ? message : "SOAP replay failed");
  }
}

static char *ReadReplayFixture(const char *filename, size_t *length) {
  char path[PATH_MAX];
  struct stat status;
  char *contents = NULL;
  size_t offset = 0;
  int file = -1;
  int written = 0;

  if (filename == NULL || length == NULL)
    return NULL;
  *length = 0;
  written = snprintf(path, sizeof(path), "%s/%s", SOAP_FIXTURE_DIRECTORY,
                     filename);
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

static const char *ExpectedMethod(size_t exchange) {
  if (exchange == 0)
    return "getLastDumpDateEx";
  if (exchange == 1)
    return "sendRequest";
  if (exchange < REPLAY_EXCHANGE_COUNT - 1)
    return "getResult";
  if (exchange == REPLAY_EXCHANGE_COUNT - 1)
    return "getResultSocResources";
  return NULL;
}

static const char *ResponseFixture(size_t exchange) {
  if (exchange == 0)
    return "get-last-dump-date-response.xml";
  if (exchange == 1)
    return "send-request-response.xml";
  if (exchange < 2 + REPLAY_PENDING_COUNT)
    return "get-result-pending-response.xml";
  if (exchange == 2 + REPLAY_PENDING_COUNT)
    return "get-result-complete-response.xml";
  if (exchange == REPLAY_EXCHANGE_COUNT - 1)
    return "get-social-result-response.xml";
  return NULL;
}

static xmlNodePtr FindChild(xmlNodePtr parent, const char *name) {
  if (parent == NULL || name == NULL)
    return NULL;
  for (xmlNodePtr child = parent->children; child != NULL;
       child = child->next) {
    if (child->type == XML_ELEMENT_NODE &&
        !xmlStrcmp(child->name, BAD_CAST name))
      return child;
  }
  return NULL;
}

static bool Base64ChildEquals(xmlNodePtr methodNode, const char *childName,
                              const void *expected, size_t expectedLength) {
  xmlNodePtr child = FindChild(methodNode, childName);
  xmlChar *encoded = NULL;
  void *decoded = NULL;
  size_t decodedLength = 0;
  bool matches = false;

  if (child == NULL || expected == NULL)
    return false;
  encoded = xmlNodeGetContent(child);
  if (encoded == NULL)
    return false;
  decoded =
      Base64Decode((char *)encoded, xmlStrlen(encoded), &decodedLength);
  if (decoded != NULL && decodedLength == expectedLength)
    matches = memcmp(decoded, expected, expectedLength) == 0;
  free(decoded);
  xmlFree(encoded);
  return matches;
}

static bool VerifyRequestPayload(const void *payload, size_t payloadLength,
                                 const char *expectedMethod) {
  xmlDocPtr doc = NULL;
  xmlNodePtr envelope = NULL;
  xmlNodePtr body = NULL;
  xmlNodePtr method = NULL;
  xmlNodePtr code = NULL;
  xmlChar *content = NULL;
  bool valid = false;

  if (payload == NULL || payloadLength == 0 || payloadLength > INT_MAX ||
      expectedMethod == NULL)
    return false;
  doc = xmlReadMemory(payload, (int)payloadLength, NULL, "UTF-8",
                      XML_PARSE_NONET | XML_PARSE_NOBLANKS);
  if (doc == NULL)
    goto cleanup;
  envelope = xmlDocGetRootElement(doc);
  if (envelope == NULL || xmlStrcmp(envelope->name, BAD_CAST "Envelope"))
    goto cleanup;
  body = FindChild(envelope, "Body");
  if (body == NULL)
    goto cleanup;
  for (method = body->children; method != NULL; method = method->next) {
    if (method->type == XML_ELEMENT_NODE)
      break;
  }
  if (method == NULL ||
      xmlStrcmp(method->name, BAD_CAST expectedMethod) != 0)
    goto cleanup;

  if (!strcmp(expectedMethod, "sendRequest")) {
    xmlNodePtr format = FindChild(method, "dumpFormatVersion");
    if (!Base64ChildEquals(method, "requestFile", preparedRequest,
                           sizeof(preparedRequest) - 1) ||
        !Base64ChildEquals(method, "signatureFile", preparedSignature,
                           sizeof(preparedSignature)) ||
        format == NULL)
      goto cleanup;
    content = xmlNodeGetContent(format);
    if (content == NULL ||
        xmlStrcmp(content, BAD_CAST "test-format-2") != 0)
      goto cleanup;
  } else if (!strcmp(expectedMethod, "getResult") ||
             !strcmp(expectedMethod, "getResultSocResources")) {
    code = FindChild(method, "code");
    if (code == NULL)
      goto cleanup;
    content = xmlNodeGetContent(code);
    if (content == NULL ||
        xmlStrcmp(content, BAD_CAST "TEST-REQUEST-CODE") != 0)
      goto cleanup;
  }

  valid = true;
cleanup:
  if (content != NULL)
    xmlFree(content);
  if (doc != NULL)
    xmlFreeDoc(doc);
  return valid;
}

void *__wrap_SendHTTPPost(const char *url, const void *payload,
                          char *httpHeaders[], size_t httpHeadersCount,
                          size_t inputLength, size_t *outputLength) {
  static const char serviceUrl[] =
      "https://soap.example.test/services/OperatorRequest/";
  const char *method = NULL;
  const char *fixture = NULL;
  char expectedAction[256];
  char *response = NULL;
  size_t responseLength = 0;
  int written = 0;

  if (outputLength != NULL)
    *outputLength = 0;
  if (replay.failed)
    return NULL;
  if (replay.exchange >= REPLAY_EXCHANGE_COUNT) {
    ReplayFail("unexpected extra SOAP exchange");
    return NULL;
  }
  method = ExpectedMethod(replay.exchange);
  fixture = ResponseFixture(replay.exchange);
  if (method == NULL || fixture == NULL || url == NULL ||
      strcmp(url, serviceUrl) != 0) {
    ReplayFail("unexpected SOAP URL or exchange");
    return NULL;
  }
  if (httpHeaders == NULL || httpHeadersCount != 5 ||
      httpHeaders[0] == NULL || httpHeaders[1] == NULL ||
      httpHeaders[2] == NULL || httpHeaders[3] == NULL ||
      httpHeaders[4] == NULL ||
      strcmp(httpHeaders[0], "Accept: application/soap; text/xml") != 0 ||
      strcmp(httpHeaders[1], "Content-Type: text/xml; charset=utf-8") != 0 ||
      strcmp(httpHeaders[2], "Connection: close") != 0 ||
      strcmp(httpHeaders[3], "Expect:") != 0) {
    ReplayFail("unexpected SOAP header list");
    return NULL;
  }
  written = snprintf(expectedAction, sizeof(expectedAction),
                     "SOAPAction: \"%s%s\"", serviceUrl, method);
  if (written <= 0 || (size_t)written >= sizeof(expectedAction) ||
      strcmp(httpHeaders[4], expectedAction) != 0) {
    ReplayFail("unexpected SOAPAction header");
    return NULL;
  }
  if (!VerifyRequestPayload(payload, inputLength, method)) {
    ReplayFail("generated SOAP request did not match the replay");
    return NULL;
  }

  response = ReadReplayFixture(fixture, &responseLength);
  if (response == NULL || outputLength == NULL) {
    free(response);
    ReplayFail("unable to load replay response");
    return NULL;
  }
  *outputLength = responseLength;
  replay.exchange++;
  return response;
}

unsigned int __wrap_sleep(unsigned int seconds) {
  if (seconds != 0)
    ReplayFail("SOAP replay attempted a real delay");
  replay.sleeps++;
  return 0;
}

static void FreeReplaySoapContext(TSOAPContext *context) {
  if (context == NULL)
    return;
  free(context->lastDumpDate);
  free(context->lastDumpDateUrgently);
  free(context->lastDumpDateSocResources);
  free(context->dumpFormatVersion);
  free(context->dumpFormatVersionSocResources);
  free(context->webServiceVersion);
  free(context->docVersion);
  free(context->requestCode);
  free(context->requestResult);
  free(context->requestComment);
  free(context->registerZipArchive);
  free(context->socialZipArchive);
  free(context->resultResult);
  free(context->resultComment);
  free(context->operatorName);
  free(context->operatorINN);
  free(context);
}

static MunitResult TestPreparedInteractionReplay(
    const MunitParameter parameters[], void *fixture) {
  TZapretContext context = {
      .blacklistHost = "soap.example.test",
      .blacklistCooldownNegative = 0,
  };
  bool completed = false;
  bool archivesMatch = false;

  (void)parameters;
  (void)fixture;

  memset(&replay, 0, sizeof(replay));
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 0;
  PerformSOAPCommunicationPrepared(
      &context, preparedRequest, sizeof(preparedRequest) - 1,
      preparedSignature, sizeof(preparedSignature));

  completed = !replay.failed && replay.exchange == REPLAY_EXCHANGE_COUNT &&
              replay.sleeps == REPLAY_PENDING_COUNT + 1 &&
              context.soapContext != NULL &&
              context.soapContext->soapResult &&
              context.soapContext->resultCode == 1;
  archivesMatch =
      context.soapContext != NULL &&
      context.soapContext->registerZipArchive != NULL &&
      context.soapContext->socialZipArchive != NULL &&
      !strcmp(context.soapContext->registerZipArchive,
              "U0FOSVRJWkVEX0JMQUNLTElTVF9BUkNISVZF") &&
      !strcmp(context.soapContext->socialZipArchive,
              "U0FOSVRJWkVEX1NPQ0lBTF9BUkNISVZF");

  FreeReplaySoapContext(context.soapContext);
  Base64Cleanup();
  if (replay.failed)
    munit_error(replay.error);
  munit_assert_true(completed);
  munit_assert_true(archivesMatch);
  return MUNIT_OK;
}

static MunitTest SoapInteractionTests[] = {
    {"/prepared-captured-sequence", TestPreparedInteractionReplay, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite SoapInteractionSuite = {
    "/soap-interaction", SoapInteractionTests, NULL, 1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  int result = 0;

  LIBXML_TEST_VERSION
  xmlInitParser();
  result = munit_suite_main(&SoapInteractionSuite, NULL, argc, argv);
  xmlCleanupParser();
  return result;
}
