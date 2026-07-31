#include "allheaders.h"

#include <libxml/parser.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#define SOAP_FIXTURE_DIRECTORY "tests/fixtures/soap"

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

typedef enum {
  REPLAY_NO_UPDATE,
  REPLAY_IMMEDIATE_RESULT,
  REPLAY_POLL_TIMEOUT,
  REPLAY_HTTP_FAILURE,
  REPLAY_SOAP_FAULT,
  REPLAY_MALFORMED_SEND_RESPONSE
} TReplayScenario;

typedef struct {
  TReplayScenario scenario;
  size_t requests;
  size_t sleeps;
  bool validationFailed;
} TScenarioReplay;

typedef struct {
  size_t requests;
  size_t sleeps;
  bool validationFailed;
  bool soapResult;
  int resultCode;
  bool blacklistReceived;
  bool socialReceived;
} TScenarioOutcome;

static TScenarioReplay replay;
static const char preparedRequest[] = "<request>synthetic</request>";
static const unsigned char preparedSignature[] = {
    0x30, 0x06, 0x02, 0x01, 0x01, 0x00,
};

static char *ReadScenarioFixture(const char *filename, size_t *length) {
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

static xmlNodePtr FindElementChild(xmlNodePtr parent, const char *name) {
  if (parent == NULL)
    return NULL;
  for (xmlNodePtr child = parent->children; child != NULL;
       child = child->next) {
    if (child->type != XML_ELEMENT_NODE)
      continue;
    if (name == NULL || !xmlStrcmp(child->name, BAD_CAST name))
      return child;
  }
  return NULL;
}

static bool RequestMethodEquals(const void *payload, size_t payloadLength,
                                const char *expectedMethod) {
  xmlDocPtr doc = NULL;
  xmlNodePtr envelope = NULL;
  xmlNodePtr body = NULL;
  xmlNodePtr method = NULL;
  bool matches = false;

  if (payload == NULL || payloadLength == 0 || payloadLength > INT_MAX ||
      expectedMethod == NULL)
    return false;
  doc = xmlReadMemory(payload, (int)payloadLength, NULL, "UTF-8",
                      XML_PARSE_NONET | XML_PARSE_NOBLANKS);
  if (doc == NULL)
    return false;
  envelope = xmlDocGetRootElement(doc);
  body = FindElementChild(envelope, "Body");
  method = FindElementChild(body, NULL);
  matches = method != NULL &&
            !xmlStrcmp(method->name, BAD_CAST expectedMethod);
  xmlFreeDoc(doc);
  return matches;
}

static const char *ExpectedMethod(void) {
  if (replay.requests == 0)
    return "getLastDumpDateEx";
  if (replay.requests == 1)
    return "sendRequest";
  if (replay.scenario == REPLAY_IMMEDIATE_RESULT && replay.requests == 3)
    return "getResultSocResources";
  return "getResult";
}

static const char *ExpectedFixture(void) {
  if (replay.requests == 0)
    return "get-last-dump-date-response.xml";
  if (replay.requests == 1)
    return "send-request-response.xml";
  if (replay.scenario == REPLAY_IMMEDIATE_RESULT && replay.requests == 2)
    return "get-result-complete-response.xml";
  if (replay.scenario == REPLAY_IMMEDIATE_RESULT && replay.requests == 3)
    return "get-social-result-response.xml";
  return "get-result-pending-response.xml";
}

void *__wrap_SendHTTPPost(const char *url, const void *payload,
                          char *httpHeaders[], size_t httpHeadersCount,
                          size_t inputLength, size_t *outputLength) {
  static const char serviceUrl[] =
      "https://soap.example.test/services/OperatorRequest/";
  static const char soapFault[] =
      "<SOAP-ENV:Envelope "
      "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
      "<SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode>"
      "<faultstring>synthetic fault</faultstring></SOAP-ENV:Fault>"
      "</SOAP-ENV:Body></SOAP-ENV:Envelope>";
  static const char malformedSendResponse[] =
      "<Envelope><Body><sendRequestResponse><result>true</result>"
      "</sendRequestResponse></Body></Envelope>";
  const char *method = ExpectedMethod();
  const char *fixture = ExpectedFixture();
  char *response = NULL;
  size_t responseLength = 0;

  if (outputLength != NULL)
    *outputLength = 0;
  if (url == NULL || strcmp(url, serviceUrl) != 0 ||
      httpHeaders == NULL || httpHeadersCount != 5 ||
      !RequestMethodEquals(payload, inputLength, method)) {
    replay.validationFailed = true;
    return NULL;
  }

  if (replay.scenario == REPLAY_HTTP_FAILURE && replay.requests == 2) {
    replay.requests++;
    return NULL;
  }
  if (replay.scenario == REPLAY_SOAP_FAULT && replay.requests == 0) {
    replay.requests++;
    response = strdup(soapFault);
  } else if (replay.scenario == REPLAY_MALFORMED_SEND_RESPONSE &&
             replay.requests == 1) {
    replay.requests++;
    response = strdup(malformedSendResponse);
  } else {
    replay.requests++;
    response = ReadScenarioFixture(fixture, &responseLength);
  }
  if (response == NULL || outputLength == NULL) {
    free(response);
    replay.validationFailed = true;
    return NULL;
  }
  if (responseLength == 0)
    responseLength = strlen(response);
  *outputLength = responseLength;
  return response;
}

unsigned int __wrap_sleep(unsigned int seconds) {
  if (seconds != 0)
    replay.validationFailed = true;
  replay.sleeps++;
  return 0;
}

static void FreeScenarioSoapContext(TSOAPContext *context) {
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

static TScenarioOutcome RunScenario(TReplayScenario scenario) {
  TZapretContext context = {
      .blacklistHost = "soap.example.test",
      .blacklistCooldownNegative = 0,
  };
  TScenarioOutcome outcome = {0};

  memset(&replay, 0, sizeof(replay));
  replay.scenario = scenario;
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 0;
  if (scenario == REPLAY_NO_UPDATE) {
    context.soapContext = calloc(1, sizeof(*context.soapContext));
    if (context.soapContext != NULL) {
      context.soapContext->lastDumpDate =
          strdup("2024-01-02T03:04:05+00:00");
      context.soapContext->lastDumpDateUrgently =
          strdup("2024-01-02T04:05:06+00:00");
    }
  }

  PerformSOAPCommunicationPrepared(
      &context, preparedRequest, sizeof(preparedRequest) - 1,
      preparedSignature, sizeof(preparedSignature));

  outcome.requests = replay.requests;
  outcome.sleeps = replay.sleeps;
  outcome.validationFailed = replay.validationFailed;
  if (context.soapContext != NULL) {
    outcome.soapResult = context.soapContext->soapResult;
    outcome.resultCode = context.soapContext->resultCode;
    outcome.blacklistReceived =
        context.soapContext->registerZipArchive != NULL;
    outcome.socialReceived = context.soapContext->socialZipArchive != NULL;
  }
  FreeScenarioSoapContext(context.soapContext);
  Base64Cleanup();
  return outcome;
}

static MunitResult TestNoUpdateStopsAfterDateCheck(
    const MunitParameter parameters[], void *fixture) {
  TScenarioOutcome outcome = RunScenario(REPLAY_NO_UPDATE);

  (void)parameters;
  (void)fixture;

  munit_assert_false(outcome.validationFailed);
  munit_assert_size(outcome.requests, ==, 1);
  munit_assert_size(outcome.sleeps, ==, 0);
  munit_assert_true(outcome.soapResult);
  munit_assert_false(outcome.blacklistReceived);
  return MUNIT_OK;
}

static MunitResult TestImmediateResult(
    const MunitParameter parameters[], void *fixture) {
  TScenarioOutcome outcome = RunScenario(REPLAY_IMMEDIATE_RESULT);

  (void)parameters;
  (void)fixture;

  munit_assert_false(outcome.validationFailed);
  munit_assert_size(outcome.requests, ==, 4);
  munit_assert_size(outcome.sleeps, ==, 1);
  munit_assert_true(outcome.soapResult);
  munit_assert_true(outcome.blacklistReceived);
  munit_assert_true(outcome.socialReceived);
  return MUNIT_OK;
}

static MunitResult TestPollTimeout(
    const MunitParameter parameters[], void *fixture) {
  TScenarioOutcome outcome = RunScenario(REPLAY_POLL_TIMEOUT);

  (void)parameters;
  (void)fixture;

  munit_assert_false(outcome.validationFailed);
  munit_assert_size(outcome.requests, ==, 52);
  munit_assert_size(outcome.sleeps, ==, 50);
  munit_assert_false(outcome.soapResult);
  munit_assert_int(outcome.resultCode, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestHttpFailureStopsInteraction(
    const MunitParameter parameters[], void *fixture) {
  TScenarioOutcome outcome = RunScenario(REPLAY_HTTP_FAILURE);

  (void)parameters;
  (void)fixture;

  munit_assert_false(outcome.validationFailed);
  munit_assert_size(outcome.requests, ==, 3);
  munit_assert_size(outcome.sleeps, ==, 1);
  munit_assert_false(outcome.soapResult);
  return MUNIT_OK;
}

static MunitResult TestSoapFaultIsRejected(
    const MunitParameter parameters[], void *fixture) {
  TScenarioOutcome outcome = RunScenario(REPLAY_SOAP_FAULT);

  (void)parameters;
  (void)fixture;

  munit_assert_false(outcome.validationFailed);
  munit_assert_size(outcome.requests, ==, 1);
  munit_assert_size(outcome.sleeps, ==, 0);
  munit_assert_false(outcome.soapResult);
  return MUNIT_OK;
}

static MunitResult TestMalformedSendResponseIsRejected(
    const MunitParameter parameters[], void *fixture) {
  TScenarioOutcome outcome = RunScenario(REPLAY_MALFORMED_SEND_RESPONSE);

  (void)parameters;
  (void)fixture;

  munit_assert_false(outcome.validationFailed);
  munit_assert_size(outcome.requests, ==, 2);
  munit_assert_size(outcome.sleeps, ==, 0);
  munit_assert_false(outcome.soapResult);
  return MUNIT_OK;
}

static MunitTest SoapScenarioTests[] = {
    {"/no-update", TestNoUpdateStopsAfterDateCheck, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/immediate-result", TestImmediateResult, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/poll-timeout", TestPollTimeout, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/http-failure", TestHttpFailureStopsInteraction, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/soap-fault", TestSoapFaultIsRejected, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed-send-response", TestMalformedSendResponseIsRejected, NULL,
     NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite SoapScenarioSuite = {
    "/soap-scenarios", SoapScenarioTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  int result = 0;

  LIBXML_TEST_VERSION
  xmlInitParser();
  result = munit_suite_main(&SoapScenarioSuite, NULL, argc, argv);
  xmlCleanupParser();
  return result;
}
