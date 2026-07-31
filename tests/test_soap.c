#include "allheaders.h"

#include <libxml/parser.h>

#include "pfhash.h"
#include "vendor/munit/munit.h"
#include "zapret-structures.h"

#define SOAP_FIXTURE_DIRECTORY "tests/fixtures/soap"

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

bool GetLastDumpDateResponse(TSOAPContext *context, const char *soapXml,
                             size_t inputLength);
bool SendRequestResponse(TSOAPContext *context, const char *soapXml,
                         size_t inputLength);
bool GetResultResponse(TSOAPContext *context, const char *soapXml,
                       size_t inputLength);
bool GetResultSocResourcesResponse(TSOAPContext *context, const char *soapXml,
                                   size_t inputLength);
xmlChar *GenerateRequestXml(xmlDocPtr requestXmlDoc, size_t *outputLength);

static char *ReadSoapFixture(const char *filename, size_t *length) {
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

static void FreeSoapContextFields(TSOAPContext *context) {
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
  memset(context, 0, sizeof(*context));
}

static MunitResult TestLastDumpDateResponse(
    const MunitParameter parameters[], void *fixture) {
  TSOAPContext context = {0};
  size_t responseLength = 0;
  char *response =
      ReadSoapFixture("get-last-dump-date-response.xml", &responseLength);

  (void)parameters;
  (void)fixture;

  munit_assert_not_null(response);
  munit_assert_true(
      GetLastDumpDateResponse(&context, response, responseLength));
  munit_assert_string_equal(context.lastDumpDate,
                            "2024-01-02T03:04:05+00:00");
  munit_assert_string_equal(context.lastDumpDateUrgently,
                            "2024-01-02T04:05:06+00:00");
  munit_assert_string_equal(context.lastDumpDateSocResources,
                            "2024-01-02T05:06:07+00:00");
  munit_assert_string_equal(context.webServiceVersion, "test-service-1");
  munit_assert_string_equal(context.dumpFormatVersion, "test-format-2");
  munit_assert_string_equal(context.dumpFormatVersionSocResources,
                            "test-social-format-3");
  munit_assert_string_equal(context.docVersion, "test-document-4");

  munit_assert_false(
      GetLastDumpDateResponse(&context, response, responseLength));

  free(response);
  FreeSoapContextFields(&context);
  return MUNIT_OK;
}

static MunitResult TestCapturedSoapSequence(
    const MunitParameter parameters[], void *fixture) {
  static const char *const fixtureNames[] = {
      "get-last-dump-date-response.xml",
      "send-request-response.xml",
      "get-result-pending-response.xml",
      "get-result-complete-response.xml",
      "get-social-result-response.xml",
  };
  char *responses[sizeof(fixtureNames) / sizeof(fixtureNames[0])] = {0};
  size_t lengths[sizeof(fixtureNames) / sizeof(fixtureNames[0])] = {0};
  TSOAPContext context = {0};

  (void)parameters;
  (void)fixture;

  for (size_t i = 0; i < sizeof(fixtureNames) / sizeof(fixtureNames[0]); i++) {
    responses[i] = ReadSoapFixture(fixtureNames[i], &lengths[i]);
    munit_assert_not_null(responses[i]);
  }

  munit_assert_true(GetLastDumpDateResponse(&context, responses[0],
                                            lengths[0]));
  munit_assert_true(
      SendRequestResponse(&context, responses[1], lengths[1]));
  munit_assert_string_equal(context.requestResult, "true");
  munit_assert_string_equal(context.requestCode, "TEST-REQUEST-CODE");
  munit_assert_string_equal(context.requestComment,
                            "synthetic request accepted");

  for (size_t poll = 0; poll < 14; poll++) {
    munit_assert_true(
        GetResultResponse(&context, responses[2], lengths[2]));
    munit_assert_int(context.resultCode, ==, 0);
    munit_assert_string_equal(context.resultComment,
                              "synthetic result is pending");
  }

  munit_assert_true(GetResultResponse(&context, responses[3], lengths[3]));
  munit_assert_int(context.resultCode, ==, 1);
  munit_assert_string_equal(context.registerZipArchive,
                            "U0FOSVRJWkVEX0JMQUNLTElTVF9BUkNISVZF");
  munit_assert_string_equal(context.operatorName, "Synthetic Operator");
  munit_assert_string_equal(context.operatorINN, "0000000000");

  munit_assert_true(GetResultSocResourcesResponse(
      &context, responses[4], lengths[4]));
  munit_assert_string_equal(context.socialZipArchive,
                            "U0FOSVRJWkVEX1NPQ0lBTF9BUkNISVZF");

  for (size_t i = 0; i < sizeof(responses) / sizeof(responses[0]); i++)
    free(responses[i]);
  FreeSoapContextFields(&context);
  return MUNIT_OK;
}

static MunitResult TestCompletedResultInFreshContext(
    const MunitParameter parameters[], void *fixture) {
  TSOAPContext context = {0};
  size_t responseLength = 0;
  char *response =
      ReadSoapFixture("get-result-complete-response.xml", &responseLength);

  (void)parameters;
  (void)fixture;

  munit_assert_not_null(response);
  munit_assert_true(GetResultResponse(&context, response, responseLength));
  munit_assert_string_equal(context.resultResult, "true");
  munit_assert_int(context.resultCode, ==, 1);

  free(response);
  FreeSoapContextFields(&context);
  return MUNIT_OK;
}

static MunitResult TestMalformedResponsesAreRejected(
    const MunitParameter parameters[], void *fixture) {
  static const char malformed[] =
      "<Envelope><Body><getResultResponse><resultCode>0</resultCode>"
      "</getResultResponse></Body></Envelope>";
  TSOAPContext context = {0};

  (void)parameters;
  (void)fixture;

  munit_assert_false(
      GetResultResponse(&context, malformed, sizeof(malformed) - 1));
  munit_assert_false(GetLastDumpDateResponse(&context, malformed,
                                             sizeof(malformed) - 1));
  munit_assert_false(
      SendRequestResponse(&context, malformed, sizeof(malformed) - 1));
  munit_assert_false(GetResultSocResourcesResponse(
      &context, malformed, sizeof(malformed) - 1));

  FreeSoapContextFields(&context);
  return MUNIT_OK;
}

static MunitResult TestOperatorRequestTimestampIsRegenerated(
    const MunitParameter parameters[], void *fixture) {
  static const char requestPath[] =
      SOAP_FIXTURE_DIRECTORY "/operator-request.xml";
  xmlDocPtr requestDoc = NULL;
  xmlDocPtr generatedDoc = NULL;
  xmlChar *generated = NULL;
  xmlChar *requestTime = NULL;
  size_t generatedLength = 0;

  (void)parameters;
  (void)fixture;

  requestDoc = xmlReadFile(requestPath, NULL, XML_PARSE_NONET);
  munit_assert_not_null(requestDoc);
  generated = GenerateRequestXml(requestDoc, &generatedLength);
  munit_assert_not_null(generated);
  munit_assert_size(generatedLength, >, 0);
  munit_assert_size(generatedLength, <=, INT_MAX);
  generatedDoc =
      xmlReadMemory((char *)generated, (int)generatedLength, NULL, NULL,
                    XML_PARSE_NONET | XML_PARSE_NOBLANKS);
  munit_assert_not_null(generatedDoc);

  xmlNodePtr root = xmlDocGetRootElement(generatedDoc);
  munit_assert_not_null(root);
  munit_assert_string_equal((char *)root->name, "request");
  for (xmlNodePtr node = root->children; node != NULL; node = node->next) {
    if (node->type == XML_ELEMENT_NODE &&
        !xmlStrcmp(node->name, BAD_CAST "requestTime")) {
      requestTime = xmlNodeGetContent(node);
      break;
    }
  }
  munit_assert_not_null(requestTime);
  munit_assert_size(xmlStrlen(requestTime), ==, 28);
  munit_assert_not_null(strstr((char *)requestTime, ".000"));
  munit_assert_string_not_equal((char *)requestTime,
                                "2000-01-01T00:00:00.000+0000");
  munit_assert_not_null(
      strstr((char *)generated, "Synthetic Operator"));
  munit_assert_not_null(
      strstr((char *)generated, "operator@example.test"));

  xmlFree(requestTime);
  xmlFreeDoc(generatedDoc);
  xmlFree(generated);
  xmlFreeDoc(requestDoc);
  return MUNIT_OK;
}

static MunitResult TestAlternateSocialResponseNames(
    const MunitParameter parameters[], void *fixture) {
  TSOAPContext context = {0};
  size_t responseLength = 0;
  char *response = ReadSoapFixture(
      "get-social-result-alternate-response.xml", &responseLength);

  (void)parameters;
  (void)fixture;

  munit_assert_not_null(response);
  munit_assert_true(GetResultSocResourcesResponse(
      &context, response, responseLength));
  munit_assert_string_equal(context.socialZipArchive,
                            "U0FOSVRJWkVEX0FMVEVSTkFURV9TT0NJQUw=");

  free(response);
  FreeSoapContextFields(&context);
  return MUNIT_OK;
}

static MunitTest SoapTests[] = {
    {"/last-dump-date-response", TestLastDumpDateResponse, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/captured-sequence", TestCapturedSoapSequence, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/completed-result-in-fresh-context", TestCompletedResultInFreshContext,
     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed-responses-are-rejected", TestMalformedResponsesAreRejected,
     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/operator-request-timestamp-is-regenerated",
     TestOperatorRequestTimestampIsRegenerated, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/alternate-social-response-names", TestAlternateSocialResponseNames,
     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite SoapSuite = {
    "/soap", SoapTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  int result = 0;

  LIBXML_TEST_VERSION
  xmlInitParser();
  result = munit_suite_main(&SoapSuite, NULL, argc, argv);
  xmlCleanupParser();
  return result;
}
