#include "allheaders.h"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libxml/parser.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

static size_t stopCount = 0;
static size_t destroyQueueCount = 0;
static size_t closeHandleCount = 0;
static size_t stoppedContextCount = 0;

void StopNetfilterProcessing(TNetfilterContext **context,
                             size_t contextCount) {
  munit_assert_not_null(context);
  stopCount++;
  stoppedContextCount += contextCount;
}

int nfq_destroy_queue(struct nfq_q_handle *queue) {
  munit_assert_not_null(queue);
  destroyQueueCount++;
  return 0;
}

int nfq_close(struct nfq_handle *handle) {
  munit_assert_not_null(handle);
  closeHandleCount++;
  return 0;
}

static char *Duplicate(const char *value) {
  char *result = strdup(value);
  munit_assert_not_null(result);
  return result;
}

static void FillOwnedSOAPFields(TSOAPContext *context) {
  context->lastDumpDate = Duplicate("last");
  context->lastDumpDateUrgently = Duplicate("urgent");
  context->lastDumpDateSocResources = Duplicate("social-date");
  context->dumpFormatVersion = Duplicate("format");
  context->dumpFormatVersionSocResources = Duplicate("social-format");
  context->webServiceVersion = Duplicate("service");
  context->docVersion = Duplicate("document");
  context->requestCode = Duplicate("request-code");
  context->requestResult = Duplicate("request-result");
  context->requestComment = Duplicate("request-comment");
  context->registerZipArchive = Duplicate("register");
  context->socialZipArchive = Duplicate("social");
  context->resultResult = Duplicate("result");
  context->resultComment = Duplicate("result-comment");
  context->operatorName = Duplicate("operator");
  context->operatorINN = Duplicate("inn");
  context->resultCode = 1;
  context->soapResult = true;
}

static MunitResult TestClearSOAPContext(const MunitParameter parameters[],
                                        void *fixture) {
  TSOAPContext context = {0};
  char borrowedKeyId[] = "key-id";
  char borrowedPassword[] = "password";

  (void)parameters;
  (void)fixture;
  FillOwnedSOAPFields(&context);
  context.privateKeyId = borrowedKeyId;
  context.privateKeyIdLen = strlen(borrowedKeyId);
  context.privateKeyPassword = borrowedPassword;

  ClearSOAPContext(&context);

  munit_assert_string_equal(context.lastDumpDate, "last");
  munit_assert_string_equal(context.lastDumpDateUrgently, "urgent");
  munit_assert_string_equal(context.lastDumpDateSocResources, "social-date");
  munit_assert_null(context.dumpFormatVersion);
  munit_assert_null(context.dumpFormatVersionSocResources);
  munit_assert_null(context.webServiceVersion);
  munit_assert_null(context.docVersion);
  munit_assert_null(context.requestCode);
  munit_assert_null(context.requestResult);
  munit_assert_null(context.requestComment);
  munit_assert_null(context.registerZipArchive);
  munit_assert_null(context.socialZipArchive);
  munit_assert_null(context.resultResult);
  munit_assert_null(context.resultComment);
  munit_assert_null(context.operatorName);
  munit_assert_null(context.operatorINN);
  munit_assert_null(context.privateKeyId);
  munit_assert_null(context.privateKeyPassword);
  munit_assert_size(context.privateKeyIdLen, ==, 0);
  munit_assert_false(context.soapResult);
  munit_assert_int(context.resultCode, ==, 0);

  ClearSOAPContext(&context);
  free(context.lastDumpDate);
  free(context.lastDumpDateUrgently);
  free(context.lastDumpDateSocResources);
  ClearSOAPContext(NULL);
  return MUNIT_OK;
}

static MunitResult TestClearNetfilterContext(
    const MunitParameter parameters[], void *fixture) {
  TNetfilterContext *contexts[3] = {0};
  int descriptors[2] = {-1, -1};

  (void)parameters;
  (void)fixture;
  stopCount = 0;
  stoppedContextCount = 0;
  destroyQueueCount = 0;
  closeHandleCount = 0;
  munit_assert_int(pipe(descriptors), ==, 0);

  contexts[0] = calloc(1, sizeof(*contexts[0]));
  contexts[2] = calloc(1, sizeof(*contexts[2]));
  munit_assert_not_null(contexts[0]);
  munit_assert_not_null(contexts[2]);
  contexts[0]->redirectSocket = descriptors[0];
  contexts[0]->redirectNetworkPacket = munit_malloc(32);
  contexts[0]->nfQueue = (struct nfq_q_handle *)(uintptr_t)1;
  contexts[0]->nfqHandle = (struct nfq_handle *)(uintptr_t)2;
  contexts[2]->redirectSocket = -1;
  contexts[2]->redirectNetworkPacket = munit_malloc(16);

  ClearNetfilterContext(contexts, 3);
  munit_assert_null(contexts[0]);
  munit_assert_null(contexts[1]);
  munit_assert_null(contexts[2]);
  munit_assert_size(stopCount, ==, 1);
  munit_assert_size(stoppedContextCount, ==, 3);
  munit_assert_size(destroyQueueCount, ==, 1);
  munit_assert_size(closeHandleCount, ==, 1);
  errno = 0;
  munit_assert_int(fcntl(descriptors[0], F_GETFD), ==, -1);
  munit_assert_int(errno, ==, EBADF);
  close(descriptors[1]);

  ClearNetfilterContext(NULL, 3);
  ClearNetfilterContext(contexts, 0);
  return MUNIT_OK;
}

static MunitResult TestClearSMTPContext(const MunitParameter parameters[],
                                        void *fixture) {
  TSMTPContext *context = calloc(1, sizeof(*context));

  (void)parameters;
  (void)fixture;
  munit_assert_not_null(context);
  context->smtpHost = Duplicate("smtp://mail.example/");
  context->smtpSender = Duplicate("sender@example.test");
  context->recipients[0] =
      curl_slist_append(NULL, "attachments@example.test");
  context->recipients[1] = curl_slist_append(NULL, "plain@example.test");
  munit_assert_not_null(context->recipients[0]);
  munit_assert_not_null(context->recipients[1]);

  ClearSMTPContext(context);
  ClearSMTPContext(NULL);
  return MUNIT_OK;
}

static MunitResult TestClearZapretContext(const MunitParameter parameters[],
                                          void *fixture) {
  TZapretContext context = {0};
  int descriptors[2] = {-1, -1};

  (void)parameters;
  (void)fixture;
  stopCount = 0;
  stoppedContextCount = 0;
  destroyQueueCount = 0;
  closeHandleCount = 0;

  context.redirectHost = Duplicate("redirect.example");
  context.redirectIface = Duplicate("eth-test");
  context.redirectIpsetList = Duplicate("ZAPRET");
  context.blacklistHost = Duplicate("soap.example");
  context.timestampFile = Duplicate("timestamp");
  context.customBlacklist = Duplicate("custom.xml");
  context.privateKeyId = Duplicate("key-id");
  context.privateKeyIdLen = strlen(context.privateKeyId);
  context.privateKeyPassword = Duplicate("password");
  context.requestXmlDoc = xmlNewDoc(BAD_CAST "1.0");
  munit_assert_not_null(context.requestXmlDoc);

  context.soapContext = calloc(1, sizeof(*context.soapContext));
  munit_assert_not_null(context.soapContext);
  FillOwnedSOAPFields(context.soapContext);
  context.smtpContext = calloc(1, sizeof(*context.smtpContext));
  munit_assert_not_null(context.smtpContext);
  context.smtpContext->smtpHost = Duplicate("smtp://mail.example/");
  context.smtpContext->smtpSender = Duplicate("sender@example.test");
  context.smtpContext->recipients[0] =
      curl_slist_append(NULL, "recipient@example.test");
  munit_assert_not_null(context.smtpContext->recipients[0]);

  context.redirectHTTPCount = 1;
  context.httpThreadsContext = calloc(1, sizeof(*context.httpThreadsContext));
  munit_assert_not_null(context.httpThreadsContext);
  context.httpThreadsContext[0] =
      calloc(1, sizeof(*context.httpThreadsContext[0]));
  munit_assert_not_null(context.httpThreadsContext[0]);
  munit_assert_int(pipe(descriptors), ==, 0);
  context.httpThreadsContext[0]->redirectSocket = descriptors[0];
  context.httpThreadsContext[0]->redirectNetworkPacket = munit_malloc(8);
  context.httpThreadsContext[0]->nfQueue =
      (struct nfq_q_handle *)(uintptr_t)3;
  context.httpThreadsContext[0]->nfqHandle =
      (struct nfq_handle *)(uintptr_t)4;

  context.redirectDNSCount = 1;
  context.dnsThreadsContext = calloc(1, sizeof(*context.dnsThreadsContext));
  munit_assert_not_null(context.dnsThreadsContext);
  context.dnsThreadsContext[0] =
      calloc(1, sizeof(*context.dnsThreadsContext[0]));
  munit_assert_not_null(context.dnsThreadsContext[0]);
  context.dnsThreadsContext[0]->redirectSocket = -1;

  const uint32_t bucketCounts[NETFILTER_TYPE_COUNT] = {7, 7, 7};
  munit_assert_true(
      InitializeZapretBlacklist(&context.blacklist, bucketCounts));
  munit_assert_true(
      pfHashMapAdd(context.blacklist.httpRules, "host", "/path"));
  munit_assert_true(pfHashSetAdd(context.blacklist.dnsNames, "dns"));
  munit_assert_true(pfHashSetAdd(context.blacklist.ipAddresses, "ip"));

  ClearZapretContext(&context);
  const TZapretContext empty = {0};
  munit_assert_memory_equal(sizeof(context), &context, &empty);
  munit_assert_size(stopCount, ==, 2);
  munit_assert_size(stoppedContextCount, ==, 2);
  munit_assert_size(destroyQueueCount, ==, 1);
  munit_assert_size(closeHandleCount, ==, 1);
  errno = 0;
  munit_assert_int(fcntl(descriptors[0], F_GETFD), ==, -1);
  munit_assert_int(errno, ==, EBADF);
  close(descriptors[1]);

  ClearZapretContext(&context);
  ClearZapretContext(NULL);
  return MUNIT_OK;
}

static MunitTest cleaningTests[] = {
    {"/soap-context", TestClearSOAPContext, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/netfilter-context", TestClearNetfilterContext, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/smtp-context", TestClearSMTPContext, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/zapret-context", TestClearZapretContext, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite cleaningSuite = {
    "/cleaning", cleaningTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&cleaningSuite, NULL, argc, argv);
}
