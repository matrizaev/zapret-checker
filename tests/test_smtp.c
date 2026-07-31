#include "allheaders.h"

#include <curl/curl.h>

#include "vendor/munit/munit.h"
#include "zapret-checker.h"

#undef curl_easy_setopt

#define MAX_MIME_PARTS 3
#define MAX_PERFORMS 2
#define MAX_HEADERS 5

typedef enum {
  SMTP_FAIL_NONE,
  SMTP_FAIL_EASY_INIT,
  SMTP_FAIL_MIME_INIT,
  SMTP_FAIL_MIME_ADDPART,
  SMTP_FAIL_MIME_DATA,
  SMTP_FAIL_MIME_FILENAME,
  SMTP_FAIL_MIME_TYPE,
  SMTP_FAIL_MIME_ENCODER,
  SMTP_FAIL_SLIST_APPEND,
  SMTP_FAIL_SETOPT,
  SMTP_FAIL_PERFORM,
  SMTP_FAIL_BASE64,
} TSMTPFailure;

struct curl_mimepart {
  char *data;
  size_t dataLength;
  char *filename;
  char *type;
  char *encoder;
};

struct curl_mime {
  size_t partCount;
  struct curl_mimepart *parts[MAX_MIME_PARTS];
};

struct Curl_easy {
  char *errorBuffer;
  curl_debug_callback debugCallback;
  void *debugData;
  const char *url;
  const char *mailFrom;
  struct curl_slist *recipients;
  struct curl_slist *headers;
  curl_mime *mime;
};

typedef struct {
  size_t partCount;
  char body[4096];
  char attachmentData[2][16];
  char attachmentFilename[2][32];
  char attachmentType[2][32];
  char attachmentEncoder[2][32];
  char headers[MAX_HEADERS][512];
  size_t headerCount;
  char recipients[4][128];
  size_t recipientCount;
} TPerformSnapshot;

static TSMTPFailure failure = SMTP_FAIL_NONE;
static CURLoption failingOption = CURLOPT_MIMEPOST;
static size_t easyInitCount = 0;
static size_t easyCleanupCount = 0;
static size_t mimeInitCount = 0;
static size_t mimeFreeCount = 0;
static size_t slistAllocationCount = 0;
static size_t slistFreeCount = 0;
static size_t slistAppendCallCount = 0;
static size_t failSlistAppendAt = SIZE_MAX;
static size_t performCount = 0;
static TPerformSnapshot snapshots[MAX_PERFORMS];

static void ResetSMTPMocks(void) {
  failure = SMTP_FAIL_NONE;
  failingOption = CURLOPT_MIMEPOST;
  easyInitCount = 0;
  easyCleanupCount = 0;
  mimeInitCount = 0;
  mimeFreeCount = 0;
  slistAllocationCount = 0;
  slistFreeCount = 0;
  slistAppendCallCount = 0;
  failSlistAppendAt = SIZE_MAX;
  performCount = 0;
  memset(snapshots, 0, sizeof(snapshots));
}

static char *CopyString(const char *value) {
  char *result = strdup(value);
  munit_assert_not_null(result);
  return result;
}

char *GetDateTime(const char *format) {
  munit_assert_string_equal(format, "%a, %d %b %Y %T %z");
  return CopyString("Fri, 31 Jul 2026 12:34:56 +0300");
}

void *Base64Decode(const char *data, size_t inputLength,
                   size_t *outputLength) {
  const char *decoded = NULL;

  munit_assert_not_null(data);
  munit_assert_not_null(outputLength);
  munit_assert_size(inputLength, ==, strlen(data));
  *outputLength = 0;
  if (failure == SMTP_FAIL_BASE64)
    return NULL;
  if (!strcmp(data, "UkVH"))
    decoded = "REG";
  else if (!strcmp(data, "U09D"))
    decoded = "SOC";
  else
    return NULL;
  *outputLength = strlen(decoded);
  void *result = malloc(*outputLength);
  if (result != NULL)
    memcpy(result, decoded, *outputLength);
  return result;
}

CURL *curl_easy_init(void) {
  easyInitCount++;
  if (failure == SMTP_FAIL_EASY_INIT)
    return NULL;
  return calloc(1, sizeof(struct Curl_easy));
}

void curl_easy_cleanup(CURL *handle) {
  munit_assert_not_null(handle);
  easyCleanupCount++;
  free(handle);
}

CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...) {
  struct Curl_easy *easy = (struct Curl_easy *)handle;
  va_list arguments;

  munit_assert_not_null(easy);
  if (failure == SMTP_FAIL_SETOPT && option == failingOption)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  va_start(arguments, option);
  switch (option) {
  case CURLOPT_VERBOSE:
    munit_assert_long(va_arg(arguments, long), ==, 1L);
    break;
  case CURLOPT_ERRORBUFFER:
    easy->errorBuffer = va_arg(arguments, char *);
    break;
  case CURLOPT_DEBUGFUNCTION:
    easy->debugCallback = va_arg(arguments, curl_debug_callback);
    break;
  case CURLOPT_DEBUGDATA:
    easy->debugData = va_arg(arguments, void *);
    break;
  case CURLOPT_URL:
    easy->url = va_arg(arguments, const char *);
    break;
  case CURLOPT_MAIL_FROM:
    easy->mailFrom = va_arg(arguments, const char *);
    break;
  case CURLOPT_MAIL_RCPT:
    easy->recipients = va_arg(arguments, struct curl_slist *);
    break;
  case CURLOPT_HTTPHEADER:
    easy->headers = va_arg(arguments, struct curl_slist *);
    break;
  case CURLOPT_MIMEPOST:
    easy->mime = va_arg(arguments, curl_mime *);
    break;
  default:
    munit_errorf("unexpected curl option: %d", (int)option);
  }
  va_end(arguments);
  return CURLE_OK;
}

const char *curl_easy_strerror(CURLcode code) {
  return code == CURLE_OK ? "OK" : "mock curl failure";
}

curl_mime *curl_mime_init(CURL *easy) {
  munit_assert_not_null(easy);
  mimeInitCount++;
  if (failure == SMTP_FAIL_MIME_INIT)
    return NULL;
  return calloc(1, sizeof(struct curl_mime));
}

curl_mimepart *curl_mime_addpart(curl_mime *mime) {
  munit_assert_not_null(mime);
  if (failure == SMTP_FAIL_MIME_ADDPART)
    return NULL;
  munit_assert_size(mime->partCount, <, MAX_MIME_PARTS);
  curl_mimepart *part = calloc(1, sizeof(*part));
  if (part == NULL)
    return NULL;
  mime->parts[mime->partCount++] = part;
  return part;
}

CURLcode curl_mime_data(curl_mimepart *part, const char *data,
                        size_t dataLength) {
  munit_assert_not_null(part);
  munit_assert_not_null(data);
  if (failure == SMTP_FAIL_MIME_DATA)
    return CURLE_READ_ERROR;
  if (dataLength == CURL_ZERO_TERMINATED)
    dataLength = strlen(data);
  part->data = malloc(dataLength + 1);
  if (part->data == NULL)
    return CURLE_OUT_OF_MEMORY;
  memcpy(part->data, data, dataLength);
  part->data[dataLength] = '\0';
  part->dataLength = dataLength;
  return CURLE_OK;
}

CURLcode curl_mime_filename(curl_mimepart *part, const char *filename) {
  munit_assert_not_null(part);
  munit_assert_not_null(filename);
  if (failure == SMTP_FAIL_MIME_FILENAME)
    return CURLE_READ_ERROR;
  part->filename = strdup(filename);
  return part->filename != NULL ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

CURLcode curl_mime_type(curl_mimepart *part, const char *type) {
  munit_assert_not_null(part);
  munit_assert_not_null(type);
  if (failure == SMTP_FAIL_MIME_TYPE)
    return CURLE_READ_ERROR;
  part->type = strdup(type);
  return part->type != NULL ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

CURLcode curl_mime_encoder(curl_mimepart *part, const char *encoder) {
  munit_assert_not_null(part);
  munit_assert_not_null(encoder);
  if (failure == SMTP_FAIL_MIME_ENCODER)
    return CURLE_READ_ERROR;
  part->encoder = strdup(encoder);
  return part->encoder != NULL ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

void curl_mime_free(curl_mime *mime) {
  if (mime == NULL)
    return;
  mimeFreeCount++;
  for (size_t i = 0; i < mime->partCount; i++) {
    curl_mimepart *part = mime->parts[i];
    free(part->data);
    free(part->filename);
    free(part->type);
    free(part->encoder);
    free(part);
  }
  free(mime);
}

struct curl_slist *curl_slist_append(struct curl_slist *list,
                                     const char *data) {
  size_t call = slistAppendCallCount++;
  if (failure == SMTP_FAIL_SLIST_APPEND && call == failSlistAppendAt)
    return NULL;
  struct curl_slist *item = calloc(1, sizeof(*item));
  if (item == NULL)
    return NULL;
  item->data = strdup(data);
  if (item->data == NULL) {
    free(item);
    return NULL;
  }
  slistAllocationCount++;
  if (list == NULL)
    return item;
  struct curl_slist *tail = list;
  while (tail->next != NULL)
    tail = tail->next;
  tail->next = item;
  return list;
}

void curl_slist_free_all(struct curl_slist *list) {
  while (list != NULL) {
    struct curl_slist *next = list->next;
    free(list->data);
    free(list);
    slistFreeCount++;
    list = next;
  }
}

static void CopySnapshotString(char *destination, size_t capacity,
                               const char *source) {
  int written = snprintf(destination, capacity, "%s", source);
  munit_assert_int(written, >=, 0);
  munit_assert_size((size_t)written, <, capacity);
}

CURLcode curl_easy_perform(CURL *handle) {
  struct Curl_easy *easy = (struct Curl_easy *)handle;
  munit_assert_not_null(easy);
  munit_assert_not_null(easy->url);
  munit_assert_not_null(easy->mailFrom);
  munit_assert_not_null(easy->recipients);
  munit_assert_not_null(easy->headers);
  munit_assert_not_null(easy->mime);

  if (failure == SMTP_FAIL_PERFORM) {
    if (easy->errorBuffer != NULL)
      snprintf(easy->errorBuffer, CURL_ERROR_SIZE, "mock detail");
    if (easy->debugCallback != NULL) {
      char ignored[] = "diagnostic";
      char longReply[CURL_ERROR_SIZE + 32];
      char reply[] = "550 rejected\r\n";
      memset(longReply, 'x', sizeof(longReply));
      easy->debugCallback(handle, CURLINFO_TEXT, ignored,
                          sizeof(ignored) - 1, easy->debugData);
      easy->debugCallback(handle, CURLINFO_HEADER_IN, longReply,
                          sizeof(longReply), easy->debugData);
      easy->debugCallback(handle, CURLINFO_HEADER_IN, reply,
                          sizeof(reply) - 1, easy->debugData);
    }
    return CURLE_SEND_ERROR;
  }

  munit_assert_size(performCount, <, MAX_PERFORMS);
  TPerformSnapshot *snapshot = &snapshots[performCount++];
  snapshot->partCount = easy->mime->partCount;
  munit_assert_size(snapshot->partCount, >=, 1);
  CopySnapshotString(snapshot->body, sizeof(snapshot->body),
                     easy->mime->parts[0]->data);
  for (size_t i = 1; i < easy->mime->partCount; i++) {
    size_t attachment = i - 1;
    CopySnapshotString(snapshot->attachmentData[attachment],
                       sizeof(snapshot->attachmentData[attachment]),
                       easy->mime->parts[i]->data);
    CopySnapshotString(snapshot->attachmentFilename[attachment],
                       sizeof(snapshot->attachmentFilename[attachment]),
                       easy->mime->parts[i]->filename);
    CopySnapshotString(snapshot->attachmentType[attachment],
                       sizeof(snapshot->attachmentType[attachment]),
                       easy->mime->parts[i]->type);
    CopySnapshotString(snapshot->attachmentEncoder[attachment],
                       sizeof(snapshot->attachmentEncoder[attachment]),
                       easy->mime->parts[i]->encoder);
  }
  for (const struct curl_slist *item = easy->headers; item != NULL;
       item = item->next) {
    munit_assert_size(snapshot->headerCount, <, MAX_HEADERS);
    CopySnapshotString(snapshot->headers[snapshot->headerCount++],
                       sizeof(snapshot->headers[0]), item->data);
  }
  for (const struct curl_slist *item = easy->recipients; item != NULL;
       item = item->next) {
    munit_assert_size(snapshot->recipientCount, <, 4);
    CopySnapshotString(snapshot->recipients[snapshot->recipientCount++],
                       sizeof(snapshot->recipients[0]), item->data);
  }
  return CURLE_OK;
}

static struct curl_slist *MakeRecipients(const char *first,
                                         const char *second) {
  struct curl_slist *result = curl_slist_append(NULL, first);
  munit_assert_not_null(result);
  if (second != NULL) {
    struct curl_slist *updated = curl_slist_append(result, second);
    munit_assert_not_null(updated);
    result = updated;
  }
  return result;
}

static void InitializeSMTPContext(TSMTPContext *smtp) {
  memset(smtp, 0, sizeof(*smtp));
  smtp->smtpHost = "smtp://mail.example.test/";
  smtp->smtpSender = "sender@example.test";
  smtp->recipients[0] = MakeRecipients("archive-one@example.test",
                                       "archive-two@example.test");
  smtp->recipients[1] = MakeRecipients("plain@example.test", NULL);
}

static void FreeSMTPRecipients(TSMTPContext *smtp) {
  for (size_t i = 0; i < SMTP_RECIPIENTS_LIST_COUNT; i++) {
    curl_slist_free_all(smtp->recipients[i]);
    smtp->recipients[i] = NULL;
  }
}

static TSOAPContext SuccessfulSOAPContext(void) {
  TSOAPContext context = {
      .lastDumpDate = "last-date",
      .lastDumpDateUrgently = "urgent-date",
      .dumpFormatVersion = "format-version",
      .webServiceVersion = "service-version",
      .docVersion = "document-version",
      .requestCode = "request-code",
      .requestResult = "request-result",
      .requestComment = "request-comment",
      .registerZipArchive = "UkVH",
      .socialZipArchive = "U09D",
      .resultResult = "result-result",
      .resultComment = "result-comment",
      .operatorName = "operator-name",
      .operatorINN = "operator-inn",
      .resultCode = 1,
      .soapResult = true,
  };
  return context;
}

static void AssertBalancedMockResources(void) {
  munit_assert_size(easyCleanupCount, ==,
                    failure == SMTP_FAIL_EASY_INIT ? 0 : easyInitCount);
  munit_assert_size(mimeFreeCount, ==, mimeInitCount -
                                         (failure == SMTP_FAIL_MIME_INIT ? 1 : 0));
}

static MunitResult TestSuccessfulMessages(const MunitParameter parameters[],
                                          void *fixture) {
  TSMTPContext smtp;
  TSOAPContext soap = SuccessfulSOAPContext();

  (void)parameters;
  (void)fixture;
  ResetSMTPMocks();
  InitializeSMTPContext(&smtp);
  munit_assert_true(SendSMTPMessage(&smtp, &soap));
  munit_assert_size(performCount, ==, 2);
  munit_assert_size(snapshots[0].partCount, ==, 3);
  munit_assert_size(snapshots[1].partCount, ==, 1);
  munit_assert_not_null(strstr(snapshots[0].body, "Successful iteration."));
  munit_assert_not_null(strstr(snapshots[0].body, "operator-name"));
  munit_assert_string_equal(snapshots[0].attachmentData[0], "REG");
  munit_assert_string_equal(snapshots[0].attachmentFilename[0],
                            "register.zip");
  munit_assert_string_equal(snapshots[0].attachmentData[1], "SOC");
  munit_assert_string_equal(snapshots[0].attachmentFilename[1], "social.zip");
  munit_assert_string_equal(snapshots[0].attachmentType[0], "application/zip");
  munit_assert_string_equal(snapshots[0].attachmentEncoder[0], "base64");
  munit_assert_size(snapshots[0].recipientCount, ==, 2);
  munit_assert_string_equal(snapshots[0].headers[0],
                            "From: <sender@example.test>");
  munit_assert_string_equal(
      snapshots[0].headers[1],
      "To: <archive-one@example.test>, <archive-two@example.test>");
  munit_assert_string_equal(snapshots[0].headers[2],
                            "Subject: Zapret-checker's periodical notification.");
  munit_assert_string_equal(snapshots[0].headers[3], "Mime-Version: 1.0");
  munit_assert_string_equal(
      snapshots[0].headers[4],
      "Date: Fri, 31 Jul 2026 12:34:56 +0300");

  FreeSMTPRecipients(&smtp);
  AssertBalancedMockResources();
  munit_assert_size(slistFreeCount, ==, slistAllocationCount);
  return MUNIT_OK;
}

static MunitResult TestIterationStatuses(const MunitParameter parameters[],
                                         void *fixture) {
  TSMTPContext smtp;
  TSOAPContext soap = {0};

  (void)parameters;
  (void)fixture;
  ResetSMTPMocks();
  InitializeSMTPContext(&smtp);
  curl_slist_free_all(smtp.recipients[1]);
  smtp.recipients[1] = NULL;
  soap.soapResult = true;
  munit_assert_true(SendSMTPMessage(&smtp, &soap));
  munit_assert_not_null(strstr(snapshots[0].body,
                               "Timestamp has not been changed."));
  FreeSMTPRecipients(&smtp);
  AssertBalancedMockResources();

  ResetSMTPMocks();
  InitializeSMTPContext(&smtp);
  curl_slist_free_all(smtp.recipients[1]);
  smtp.recipients[1] = NULL;
  soap.soapResult = false;
  munit_assert_true(SendSMTPMessage(&smtp, &soap));
  munit_assert_not_null(strstr(snapshots[0].body, "Unsuccessful iteration."));
  FreeSMTPRecipients(&smtp);
  munit_assert_size(easyCleanupCount, ==, easyInitCount);
  munit_assert_size(mimeFreeCount, ==, mimeInitCount);
  munit_assert_size(slistFreeCount, ==, slistAllocationCount);
  return MUNIT_OK;
}

static MunitResult TestFailuresCleanUp(const MunitParameter parameters[],
                                       void *fixture) {
  static const TSMTPFailure failures[] = {
      SMTP_FAIL_EASY_INIT,     SMTP_FAIL_MIME_INIT,
      SMTP_FAIL_MIME_ADDPART, SMTP_FAIL_MIME_DATA,
      SMTP_FAIL_MIME_FILENAME, SMTP_FAIL_MIME_TYPE,
      SMTP_FAIL_MIME_ENCODER, SMTP_FAIL_SLIST_APPEND,
      SMTP_FAIL_SETOPT,       SMTP_FAIL_PERFORM,
      SMTP_FAIL_BASE64,
  };

  (void)parameters;
  (void)fixture;
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    TSMTPContext smtp;
    TSOAPContext soap = SuccessfulSOAPContext();
    ResetSMTPMocks();
    InitializeSMTPContext(&smtp);
    failure = failures[i];
    if (failure == SMTP_FAIL_SLIST_APPEND)
      failSlistAppendAt = slistAppendCallCount + 1;
    munit_assert_false(SendSMTPMessage(&smtp, &soap));
    failure = SMTP_FAIL_NONE;
    FreeSMTPRecipients(&smtp);
    munit_assert_size(easyCleanupCount, ==,
                      failures[i] == SMTP_FAIL_EASY_INIT ? 0 : easyInitCount);
    munit_assert_size(mimeFreeCount, ==,
                      mimeInitCount -
                          (failures[i] == SMTP_FAIL_MIME_INIT ? 1 : 0));
    munit_assert_size(slistFreeCount, ==, slistAllocationCount);
  }
  return MUNIT_OK;
}

static MunitResult TestInvalidArguments(const MunitParameter parameters[],
                                        void *fixture) {
  TSMTPContext smtp = {0};
  TSOAPContext soap = {0};

  (void)parameters;
  (void)fixture;
  ResetSMTPMocks();
  munit_assert_true(SendSMTPMessage(NULL, NULL));
  munit_assert_false(SendSMTPMessage(&smtp, &soap));
  smtp.smtpHost = "smtp://mail.example/";
  munit_assert_false(SendSMTPMessage(&smtp, &soap));
  munit_assert_size(easyInitCount, ==, 0);
  return MUNIT_OK;
}

static MunitTest smtpTests[] = {
    {"/successful-messages", TestSuccessfulMessages, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/iteration-statuses", TestIterationStatuses, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/failure-cleanup", TestFailuresCleanUp, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid-arguments", TestInvalidArguments, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite smtpSuite = {
    "/smtp", smtpTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  return munit_suite_main(&smtpSuite, NULL, argc, argv);
}
