/*************************************************************************
 * SMTP notification and MIME attachment handling.                        *
 *************************************************************************/

#include "allheaders.h"

#include <curl/curl.h>

#include "zapret-checker.h"

#define SMTP_PAYLOAD_STRING_SUCCESSFUL "Successful iteration."
#define SMTP_PAYLOAD_STRING_UNSUCCESSFUL "Unsuccessful iteration."
#define SMTP_PAYLOAD_STRING_UNCHANGED "Timestamp has not been changed."
#define SMTP_TIME_FORMAT "%a, %d %b %Y %T %z"

typedef struct {
  char lastServerReply[CURL_ERROR_SIZE];
} TSMTPTrace;

static int SMTPDebugCallback(CURL *curlHandle, curl_infotype type, char *data,
                             size_t size, void *userData) {
  (void)curlHandle;
  TSMTPTrace *trace = userData;

  if (trace == NULL || type != CURLINFO_HEADER_IN || data == NULL || size == 0)
    return 0;
  size_t length = size;
  while (length > 0 && (data[length - 1] == '\r' || data[length - 1] == '\n'))
    length--;
  if (length >= sizeof(trace->lastServerReply))
    length = sizeof(trace->lastServerReply) - 1;
  memcpy(trace->lastServerReply, data, length);
  trace->lastServerReply[length] = '\0';
  return 0;
}

static const char *SafeString(const char *value) {
  return value != NULL ? value : "";
}

static const char *IterationStatus(const TSOAPContext *soapContext) {
  if (soapContext->soapResult && soapContext->registerZipArchive != NULL)
    return SMTP_PAYLOAD_STRING_SUCCESSFUL;
  if (soapContext->soapResult)
    return SMTP_PAYLOAD_STRING_UNCHANGED;
  return SMTP_PAYLOAD_STRING_UNSUCCESSFUL;
}

static char *BuildHtmlBody(const TSOAPContext *soapContext) {
  static const char bodyTemplate[] =
      "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body>"
      "<h1>%s</h1>"
      "<p><a href=\"http://vigruzki.rkn.gov.ru/docs/"
      "description_for_operators_actual.pdf\">ISP instructions version: "
      "%s</a></p>"
      "<p>Request comment: %s</p>"
      "<p>Result comment: %s</p>"
      "<p>Result code: %d</p>"
      "<p>Operator name: %s</p>"
      "<p>Operator INN: %s</p>"
      "<p>Dump format version: %s</p>"
      "<p>Web service version: %s</p>"
      "<p>Request code: %s</p>"
      "<p>Last dump date: %s</p>"
      "<p>Last dump date urgently: %s</p>"
      "<p>Request result: %s</p>"
      "<p>Response result: %s</p>"
      "<p>Техническая поддержка: "
      "<a href=\"mailto:zapret-support@rkn.gov.ru\">"
      "zapret-support@rkn.gov.ru</a></p>"
      "</body></html>";
  char *result = NULL;

  check(soapContext != NULL, ERROR_STR_INVALIDINPUT);
  int required = snprintf(
      NULL, 0, bodyTemplate, IterationStatus(soapContext),
      SafeString(soapContext->docVersion),
      SafeString(soapContext->requestComment),
      SafeString(soapContext->resultComment), soapContext->resultCode,
      SafeString(soapContext->operatorName),
      SafeString(soapContext->operatorINN),
      SafeString(soapContext->dumpFormatVersion),
      SafeString(soapContext->webServiceVersion),
      SafeString(soapContext->requestCode),
      SafeString(soapContext->lastDumpDate),
      SafeString(soapContext->lastDumpDateUrgently),
      SafeString(soapContext->requestResult),
      SafeString(soapContext->resultResult));
  check(required >= 0, ERROR_STR_INVALIDSTRING);

  result = calloc((size_t)required + 1, 1);
  check_mem(result);
  int written = snprintf(
      result, (size_t)required + 1, bodyTemplate, IterationStatus(soapContext),
      SafeString(soapContext->docVersion),
      SafeString(soapContext->requestComment),
      SafeString(soapContext->resultComment), soapContext->resultCode,
      SafeString(soapContext->operatorName),
      SafeString(soapContext->operatorINN),
      SafeString(soapContext->dumpFormatVersion),
      SafeString(soapContext->webServiceVersion),
      SafeString(soapContext->requestCode),
      SafeString(soapContext->lastDumpDate),
      SafeString(soapContext->lastDumpDateUrgently),
      SafeString(soapContext->requestResult),
      SafeString(soapContext->resultResult));
  check(written == required, ERROR_STR_INVALIDSTRING);
  return result;
error:
  if (result != NULL)
    free(result);
  return NULL;
}

static bool AddZipAttachment(curl_mime *message, const char *encodedArchive,
                             const char *filename) {
  void *archive = NULL;
  size_t archiveLength = 0;
  bool result = false;

  check(message != NULL && encodedArchive != NULL && filename != NULL,
        ERROR_STR_INVALIDINPUT);
  archive =
      Base64Decode(encodedArchive, strlen(encodedArchive), &archiveLength);
  check(archive != NULL && archiveLength > 0, ERROR_STR_INVALIDBASE64);
  log_info("SMTP attachment %s: %zu compressed bytes before MIME encoding.",
           filename, archiveLength);

  curl_mimepart *part = curl_mime_addpart(message);
  check(part != NULL, ERROR_STR_LIBCURL, "curl_mime_addpart");
  CURLcode curlResult =
      curl_mime_data(part, (const char *)archive, archiveLength);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_mime_filename(part, filename);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_mime_type(part, "application/zip");
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_mime_encoder(part, "base64");
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));

  result = true;
error:
  if (archive != NULL)
    free(archive);
  return result;
}

static curl_mime *BuildMimeMessage(CURL *curlHandle,
                                   const TSOAPContext *soapContext,
                                   bool includeAttachments) {
  curl_mime *message = NULL;
  char *htmlBody = NULL;

  check(curlHandle != NULL && soapContext != NULL, ERROR_STR_INVALIDINPUT);
  htmlBody = BuildHtmlBody(soapContext);
  check(htmlBody != NULL, ERROR_STR_INVALIDSTRING);

  message = curl_mime_init(curlHandle);
  check(message != NULL, ERROR_STR_LIBCURL, "curl_mime_init");
  curl_mimepart *part = curl_mime_addpart(message);
  check(part != NULL, ERROR_STR_LIBCURL, "curl_mime_addpart");
  CURLcode curlResult =
      curl_mime_data(part, htmlBody, CURL_ZERO_TERMINATED);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_mime_type(part, "text/html; charset=utf-8");
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_mime_encoder(part, "quoted-printable");
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));

  if (includeAttachments && soapContext->registerZipArchive != NULL)
    check(AddZipAttachment(message, soapContext->registerZipArchive,
                           "register.zip"),
          ERROR_STR_INITIALIZATION);
  if (includeAttachments && soapContext->socialZipArchive != NULL)
    check(AddZipAttachment(message, soapContext->socialZipArchive, "social.zip"),
          ERROR_STR_INITIALIZATION);

  free(htmlBody);
  return message;
error:
  if (htmlBody != NULL)
    free(htmlBody);
  if (message != NULL)
    curl_mime_free(message);
  return NULL;
}

static bool AppendHeader(struct curl_slist **headers, const char *header) {
  check(headers != NULL && header != NULL, ERROR_STR_INVALIDINPUT);
  struct curl_slist *updated = curl_slist_append(*headers, header);
  check(updated != NULL, ERROR_STR_LIBCURL, "curl_slist_append");
  *headers = updated;
  return true;
error:
  return false;
}

static char *BuildAddressHeader(const char *name,
                                const struct curl_slist *addresses) {
  static const char separator[] = ">, <";
  char *header = NULL;
  size_t length = 0;

  check(name != NULL && addresses != NULL, ERROR_STR_INVALIDINPUT);
  length = strlen(name) + strlen(": <>") + 1;
  for (const struct curl_slist *item = addresses; item != NULL;
       item = item->next) {
    check(item->data != NULL && item->data[0] != '\0',
          ERROR_STR_INVALIDSTRING);
    length += strlen(item->data);
    if (item != addresses)
      length += sizeof(separator) - 1;
  }

  header = calloc(length, 1);
  check_mem(header);
  int written = snprintf(header, length, "%s: <", name);
  check(written > 0 && (size_t)written < length, ERROR_STR_INVALIDSTRING);
  size_t offset = (size_t)written;
  for (const struct curl_slist *item = addresses; item != NULL;
       item = item->next) {
    if (item != addresses) {
      memcpy(header + offset, separator, sizeof(separator) - 1);
      offset += sizeof(separator) - 1;
    }
    size_t addressLength = strlen(item->data);
    memcpy(header + offset, item->data, addressLength);
    offset += addressLength;
  }
  header[offset++] = '>';
  header[offset] = '\0';
  return header;
error:
  if (header != NULL)
    free(header);
  return NULL;
}

static struct curl_slist *
BuildMessageHeaders(const TSMTPContext *smtpContext,
                    const struct curl_slist *recipients) {
  struct curl_slist *headers = NULL;
  char *fromHeader = NULL;
  char *toHeader = NULL;
  char *date = NULL;
  char *dateHeader = NULL;

  check(smtpContext != NULL && smtpContext->smtpSender != NULL &&
            recipients != NULL,
        ERROR_STR_INVALIDINPUT);

  struct curl_slist sender = {.data = smtpContext->smtpSender, .next = NULL};
  fromHeader = BuildAddressHeader("From", &sender);
  toHeader = BuildAddressHeader("To", recipients);
  date = GetDateTime(SMTP_TIME_FORMAT);
  check(fromHeader != NULL && toHeader != NULL && date != NULL,
        ERROR_STR_INVALIDSTRING);

  size_t dateHeaderLength = strlen("Date: ") + strlen(date) + 1;
  dateHeader = calloc(dateHeaderLength, 1);
  check_mem(dateHeader);
  int written =
      snprintf(dateHeader, dateHeaderLength, "Date: %s", date);
  check(written > 0 && (size_t)written < dateHeaderLength,
        ERROR_STR_INVALIDSTRING);

  check(AppendHeader(&headers, fromHeader), ERROR_STR_LIBCURL,
        "curl_slist_append");
  check(AppendHeader(&headers, toHeader), ERROR_STR_LIBCURL,
        "curl_slist_append");
  check(AppendHeader(
            &headers,
            "Subject: Zapret-checker's periodical notification."),
        ERROR_STR_LIBCURL, "curl_slist_append");
  check(AppendHeader(&headers, "Mime-Version: 1.0"), ERROR_STR_LIBCURL,
        "curl_slist_append");
  check(AppendHeader(&headers, dateHeader), ERROR_STR_LIBCURL,
        "curl_slist_append");

  free(fromHeader);
  free(toHeader);
  free(date);
  free(dateHeader);
  return headers;
error:
  if (fromHeader != NULL)
    free(fromHeader);
  if (toHeader != NULL)
    free(toHeader);
  if (date != NULL)
    free(date);
  if (dateHeader != NULL)
    free(dateHeader);
  if (headers != NULL)
    curl_slist_free_all(headers);
  return NULL;
}

/*************************************************************************
 * Form and send notification messages.                                   *
 *************************************************************************/
bool SendSMTPMessage(TSMTPContext *smtpContext, TSOAPContext *soapContext) {
  CURL *curlHandle = NULL;
  curl_mime *message = NULL;
  struct curl_slist *headers = NULL;
  char curlError[CURL_ERROR_SIZE] = {0};
  TSMTPTrace trace = {0};
  bool result = false;

  if (smtpContext == NULL)
    return true;
  check(soapContext != NULL && smtpContext->smtpHost != NULL &&
            smtpContext->smtpSender != NULL,
        ERROR_STR_INVALIDINPUT);

  curlHandle = curl_easy_init();
  check(curlHandle != NULL, ERROR_STR_LIBCURL, "curl_easy_init");
  CURLcode curlResult =
      curl_easy_setopt(curlHandle, CURLOPT_ERRORBUFFER, curlError);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_easy_setopt(curlHandle, CURLOPT_DEBUGFUNCTION,
                                SMTPDebugCallback);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_easy_setopt(curlHandle, CURLOPT_DEBUGDATA, &trace);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_easy_setopt(curlHandle, CURLOPT_VERBOSE, 1L);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult = curl_easy_setopt(curlHandle, CURLOPT_URL, smtpContext->smtpHost);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));
  curlResult =
      curl_easy_setopt(curlHandle, CURLOPT_MAIL_FROM, smtpContext->smtpSender);
  check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
        curl_easy_strerror(curlResult));

  for (int i = 0; i < SMTP_RECIPIENTS_LIST_COUNT; i++) {
    if (smtpContext->recipients[i] == NULL)
      continue;

    bool includeAttachments = (i == 0);
    message = BuildMimeMessage(curlHandle, soapContext, includeAttachments);
    headers =
        BuildMessageHeaders(smtpContext, smtpContext->recipients[i]);
    check(message != NULL && headers != NULL, ERROR_STR_INITIALIZATION);

    curlResult = curl_easy_setopt(curlHandle, CURLOPT_MAIL_RCPT,
                                  smtpContext->recipients[i]);
    check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
          curl_easy_strerror(curlResult));
    curlResult =
        curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, headers);
    check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
          curl_easy_strerror(curlResult));
    curlResult =
        curl_easy_setopt(curlHandle, CURLOPT_MIMEPOST, message);
    check(curlResult == CURLE_OK, ERROR_STR_LIBCURL,
          curl_easy_strerror(curlResult));

    curlError[0] = '\0';
    trace.lastServerReply[0] = '\0';
    curlResult = curl_easy_perform(curlHandle);
    if (curlResult != CURLE_OK) {
      errno = 0;
      log_err("SMTP transfer failed: %s%s%s%s%s",
              curl_easy_strerror(curlResult),
              curlError[0] != '\0' ? ": " : "", curlError,
              trace.lastServerReply[0] != '\0' ? "; last server reply: " : "",
              trace.lastServerReply);
      goto error;
    }

    curl_easy_setopt(curlHandle, CURLOPT_MIMEPOST, NULL);
    curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, NULL);
    curl_mime_free(message);
    message = NULL;
    curl_slist_free_all(headers);
    headers = NULL;
  }
  result = true;

error:
  if (curlHandle != NULL) {
    curl_easy_setopt(curlHandle, CURLOPT_MIMEPOST, NULL);
    curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, NULL);
  }
  if (message != NULL)
    curl_mime_free(message);
  if (headers != NULL)
    curl_slist_free_all(headers);
  if (curlHandle != NULL)
    curl_easy_cleanup(curlHandle);
  return result;
}
