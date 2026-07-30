/*************************************************************************
 * One-shot blacklist downloader using the daemon's SOAP implementation.  *
 *************************************************************************/

#include "allheaders.h"

#include <curl/curl.h>
#include <libxml/parser.h>
#include <limits.h>
#include <zip.h>

#include "zapret-checker.h"

#define DEFAULT_POLL_INTERVAL 10

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 0;
volatile sig_atomic_t flagMatrixReload = 0;

typedef enum {
  EMAIL_MODE_DISABLED,
  EMAIL_MODE_WITH_ATTACHMENTS,
  EMAIL_MODE_WITHOUT_ATTACHMENTS
} TEmailMode;

typedef struct {
  const char *host;
  const char *requestFile;
  const char *signatureFile;
  const char *outputDirectory;
  const char *smtpHost;
  const char *smtpSender;
  struct curl_slist *smtpRecipients;
  TEmailMode emailMode;
  time_t pollInterval;
} TDownloadOptions;

static void SignalHandler(int signalNumber) {
  (void)signalNumber;
  flagMatrixShutdown = 1;
}

static void PrintUsage(const char *program) {
  fprintf(stderr,
          "Usage: %s --host HOST --request-file FILE "
          "--signature-file FILE [options]\n"
          "\n"
          "Options:\n"
          "  --output-dir DIR       Output directory (default: .)\n"
          "  --poll-interval SEC    Delay between getResult calls (default: %d)\n"
          "  --smtp-host HOST       SMTP host or URL\n"
          "  --smtp-sender ADDRESS  Envelope and From address\n"
          "  --smtp-recipient ADDR  Recipient address; may be repeated\n"
          "  --email-with-attachments\n"
          "                         Send the notification with both ZIP files\n"
          "  --email-without-attachments\n"
          "                         Send the notification without ZIP files\n"
          "  -h, --help             Show this help\n",
          program, DEFAULT_POLL_INTERVAL);
}

static bool ParseNonNegativeTime(const char *value, time_t *result) {
  char *end = NULL;

  check(value != NULL && result != NULL, ERROR_STR_INVALIDINPUT);
  errno = 0;
  long parsed = strtol(value, &end, 10);
  check(errno == 0 && end != value && *end == '\0' && parsed >= 0,
        ERROR_STR_INVALIDINPUT);
  *result = (time_t)parsed;
  return true;
error:
  return false;
}

static bool ParseOptions(int argc, char **argv, TDownloadOptions *options) {
  check(argv != NULL && options != NULL, ERROR_STR_INVALIDINPUT);
  memset(options, 0, sizeof(*options));
  options->outputDirectory = ".";
  options->pollInterval = DEFAULT_POLL_INTERVAL;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      PrintUsage(argv[0]);
      exit(EXIT_SUCCESS);
    } else if (!strcmp(argv[i], "--host") && i + 1 < argc) {
      options->host = argv[++i];
    } else if (!strcmp(argv[i], "--request-file") && i + 1 < argc) {
      options->requestFile = argv[++i];
    } else if (!strcmp(argv[i], "--signature-file") && i + 1 < argc) {
      options->signatureFile = argv[++i];
    } else if (!strcmp(argv[i], "--output-dir") && i + 1 < argc) {
      options->outputDirectory = argv[++i];
    } else if (!strcmp(argv[i], "--poll-interval") && i + 1 < argc) {
      check(ParseNonNegativeTime(argv[++i], &options->pollInterval),
            ERROR_STR_INVALIDINPUT);
    } else if (!strcmp(argv[i], "--smtp-host") && i + 1 < argc) {
      options->smtpHost = argv[++i];
    } else if (!strcmp(argv[i], "--smtp-sender") && i + 1 < argc) {
      options->smtpSender = argv[++i];
    } else if (!strcmp(argv[i], "--smtp-recipient") && i + 1 < argc) {
      struct curl_slist *updated =
          curl_slist_append(options->smtpRecipients, argv[++i]);
      check(updated != NULL, ERROR_STR_LIBCURL, "curl_slist_append");
      options->smtpRecipients = updated;
    } else if (!strcmp(argv[i], "--email-with-attachments")) {
      check(options->emailMode == EMAIL_MODE_DISABLED,
            ERROR_STR_INVALIDINPUT);
      options->emailMode = EMAIL_MODE_WITH_ATTACHMENTS;
    } else if (!strcmp(argv[i], "--email-without-attachments")) {
      check(options->emailMode == EMAIL_MODE_DISABLED,
            ERROR_STR_INVALIDINPUT);
      options->emailMode = EMAIL_MODE_WITHOUT_ATTACHMENTS;
    } else {
      log_err("Unknown or incomplete argument: %s", argv[i]);
      goto error;
    }
  }

  check(options->host != NULL && options->host[0] != '\0' &&
            options->requestFile != NULL && options->signatureFile != NULL &&
            options->outputDirectory != NULL &&
            options->outputDirectory[0] != '\0',
        ERROR_STR_INVALIDINPUT);
  if (options->emailMode == EMAIL_MODE_DISABLED) {
    check(options->smtpHost == NULL && options->smtpSender == NULL &&
              options->smtpRecipients == NULL,
          ERROR_STR_INVALIDINPUT);
  } else {
    check(options->smtpHost != NULL && options->smtpHost[0] != '\0' &&
              options->smtpSender != NULL &&
              options->smtpSender[0] != '\0' &&
              options->smtpRecipients != NULL,
          ERROR_STR_INVALIDINPUT);
  }
  return true;
error:
  return false;
}

static char *NormalizeHost(const char *host) {
  char *result = NULL;

  check(host != NULL, ERROR_STR_INVALIDINPUT);
  if (!strncasecmp(host, "https://", strlen("https://")))
    host += strlen("https://");
  else if (!strncasecmp(host, "http://", strlen("http://")))
    host += strlen("http://");

  size_t length = strlen(host);
  while (length > 0 && host[length - 1] == '/')
    length--;
  check(length > 0 && memchr(host, '/', length) == NULL,
        ERROR_STR_INVALIDSTRING);

  result = strndup(host, length);
  check_mem(result);
  return result;
error:
  if (result != NULL)
    free(result);
  return NULL;
}

static char *NormalizeSmtpHost(const char *host) {
  char *result = NULL;

  check(host != NULL && host[0] != '\0', ERROR_STR_INVALIDINPUT);
  bool hasScheme = strstr(host, "://") != NULL;
  size_t length = strlen(host);
  bool hasTrailingSlash = host[length - 1] == '/';
  size_t resultLength =
      length + (hasScheme ? 0 : strlen("smtp://")) +
      (hasTrailingSlash ? 0 : 1) + 1;
  result = calloc(resultLength, 1);
  check_mem(result);
  int written = snprintf(result, resultLength, "%s%s%s",
                         hasScheme ? "" : "smtp://", host,
                         hasTrailingSlash ? "" : "/");
  check(written > 0 && (size_t)written < resultLength,
        ERROR_STR_INVALIDSTRING);
  return result;
error:
  free(result);
  return NULL;
}

static bool ReadFile(const char *path, void **data, size_t *length) {
  int file = -1;
  struct stat fileInfo;
  unsigned char *buffer = NULL;
  bool result = false;

  check(path != NULL && data != NULL && length != NULL,
        ERROR_STR_INVALIDINPUT);
  file = open(path, O_RDONLY);
  check(file >= 0, ERROR_STR_FILEFAIL);
  check(fstat(file, &fileInfo) == 0 && fileInfo.st_size > 0,
        ERROR_STR_FILEFAIL);
  check((uintmax_t)fileInfo.st_size <= SIZE_MAX, ERROR_STR_TOOLONG);

  *length = (size_t)fileInfo.st_size;
  buffer = malloc(*length);
  check_mem(buffer);
  size_t offset = 0;
  while (offset < *length) {
    ssize_t bytesRead = read(file, buffer + offset, *length - offset);
    check(bytesRead > 0, ERROR_STR_FILEFAIL);
    offset += (size_t)bytesRead;
  }

  *data = buffer;
  buffer = NULL;
  result = true;
error:
  if (file >= 0)
    close(file);
  if (buffer != NULL)
    free(buffer);
  return result;
}

static bool ValidateXml(const void *data, size_t length) {
  xmlDocPtr document = NULL;
  bool result = false;

  check(data != NULL && length > 0 && length <= INT_MAX,
        ERROR_STR_INVALIDINPUT);
  document =
      xmlReadMemory(data, (int)length, NULL, NULL,
                    XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_COMPACT);
  check(document != NULL && xmlDocGetRootElement(document) != NULL,
        ERROR_STR_INVALIDXML);
  result = true;
error:
  if (document != NULL)
    xmlFreeDoc(document);
  return result;
}

static bool EnsureDirectory(const char *path) {
  char *copy = NULL;
  bool result = false;

  check(path != NULL && path[0] != '\0', ERROR_STR_INVALIDINPUT);
  copy = strdup(path);
  check_mem(copy);
  size_t length = strlen(copy);
  while (length > 1 && copy[length - 1] == '/')
    copy[--length] = '\0';

  for (char *cursor = copy + 1; *cursor != '\0'; cursor++) {
    if (*cursor != '/')
      continue;
    *cursor = '\0';
    if (mkdir(copy, 0755) != 0)
      check(errno == EEXIST, ERROR_STR_FILEFAIL);
    *cursor = '/';
  }
  if (mkdir(copy, 0755) != 0)
    check(errno == EEXIST, ERROR_STR_FILEFAIL);
  result = true;
error:
  if (copy != NULL)
    free(copy);
  return result;
}

static bool HasXmlSuffix(const char *filename) {
  if (filename == NULL)
    return false;
  size_t length = strlen(filename);
  return length >= 4 && !strcasecmp(filename + length - 4, ".xml");
}

static bool WriteAtomically(const char *directory, const char *filename,
                            const void *data, size_t length) {
  char *destination = NULL;
  char *temporary = NULL;
  int file = -1;
  bool result = false;

  check(directory != NULL && filename != NULL && data != NULL && length > 0,
        ERROR_STR_INVALIDINPUT);
  size_t destinationLength = strlen(directory) + strlen(filename) + 2;
  destination = calloc(destinationLength, 1);
  check_mem(destination);
  int written = snprintf(destination, destinationLength, "%s/%s", directory,
                         filename);
  check(written > 0 && (size_t)written < destinationLength,
        ERROR_STR_INVALIDSTRING);

  size_t temporaryLength =
      strlen(directory) + strlen(filename) + strlen("/..tmp") + 32;
  temporary = calloc(temporaryLength, 1);
  check_mem(temporary);
  written = snprintf(temporary, temporaryLength, "%s/.%s.%ld.tmp", directory,
                     filename, (long)getpid());
  check(written > 0 && (size_t)written < temporaryLength,
        ERROR_STR_INVALIDSTRING);

  file = open(temporary, O_CREAT | O_EXCL | O_WRONLY, 0644);
  check(file >= 0, ERROR_STR_FILEFAIL);
  size_t offset = 0;
  while (offset < length) {
    ssize_t bytesWritten =
        write(file, (const unsigned char *)data + offset, length - offset);
    check(bytesWritten > 0, ERROR_STR_FILEFAIL);
    offset += (size_t)bytesWritten;
  }
  check(fsync(file) == 0, ERROR_STR_FILEFAIL);
  check(close(file) == 0, ERROR_STR_FILEFAIL);
  file = -1;
  check(rename(temporary, destination) == 0, ERROR_STR_FILEFAIL);
  log_info("Saved %s (%zu bytes).", destination, length);
  result = true;
error:
  if (file >= 0)
    close(file);
  if (!result && temporary != NULL)
    unlink(temporary);
  free(destination);
  free(temporary);
  return result;
}

static bool SaveArchiveXml(const char *encodedArchive, const char *directory,
                           const char *outputFilename) {
  void *decodedArchive = NULL;
  size_t decodedArchiveLength = 0;
  zip_error_t zipError;
  zip_source_t *source = NULL;
  zip_t *archive = NULL;
  zip_file_t *xmlFile = NULL;
  void *xmlData = NULL;
  bool result = false;
  bool zipErrorInitialized = false;

  check(encodedArchive != NULL && directory != NULL && outputFilename != NULL,
        ERROR_STR_INVALIDINPUT);
  decodedArchive = Base64Decode(encodedArchive, strlen(encodedArchive),
                                &decodedArchiveLength);
  check(decodedArchive != NULL && decodedArchiveLength > 0,
        ERROR_STR_INVALIDBASE64);

  zip_error_init(&zipError);
  zipErrorInitialized = true;
  source = zip_source_buffer_create(decodedArchive, decodedArchiveLength, 0,
                                    &zipError);
  check(source != NULL, ERROR_STR_ZIPERROR, zip_error_strerror(&zipError));
  archive = zip_open_from_source(source, ZIP_RDONLY, &zipError);
  check(archive != NULL, ERROR_STR_ZIPERROR, zip_error_strerror(&zipError));
  source = NULL;

  zip_int64_t selectedIndex = -1;
  zip_int64_t firstXmlIndex = -1;
  zip_int64_t entryCount = zip_get_num_entries(archive, 0);
  check(entryCount >= 0, ERROR_STR_ZIPERROR, zip_strerror(archive));
  for (zip_int64_t i = 0; i < entryCount; i++) {
    const char *entryName = zip_get_name(archive, (zip_uint64_t)i, 0);
    if (!HasXmlSuffix(entryName))
      continue;
    if (firstXmlIndex < 0)
      firstXmlIndex = i;
    const char *baseName = strrchr(entryName, '/');
    baseName = baseName != NULL ? baseName + 1 : entryName;
    if (!strcasecmp(baseName, "dump.xml")) {
      selectedIndex = i;
      break;
    }
  }
  if (selectedIndex < 0)
    selectedIndex = firstXmlIndex;
  check(selectedIndex >= 0, ERROR_STR_ZIPERROR,
        "archive contains no XML document");

  struct zip_stat xmlInfo;
  zip_stat_init(&xmlInfo);
  check(zip_stat_index(archive, (zip_uint64_t)selectedIndex, 0, &xmlInfo) == 0,
        ERROR_STR_ZIPERROR, zip_strerror(archive));
  check((xmlInfo.valid & ZIP_STAT_SIZE) != 0 && xmlInfo.size > 0 &&
            xmlInfo.size <= SIZE_MAX && xmlInfo.size <= INT_MAX,
        ERROR_STR_TOOLONG);

  xmlData = malloc((size_t)xmlInfo.size);
  check_mem(xmlData);
  xmlFile = zip_fopen_index(archive, (zip_uint64_t)selectedIndex, 0);
  check(xmlFile != NULL, ERROR_STR_ZIPERROR, zip_strerror(archive));
  zip_uint64_t offset = 0;
  while (offset < xmlInfo.size) {
    zip_int64_t bytesRead =
        zip_fread(xmlFile, (unsigned char *)xmlData + offset,
                  xmlInfo.size - offset);
    check(bytesRead > 0, ERROR_STR_ZIPERROR, zip_file_strerror(xmlFile));
    offset += (zip_uint64_t)bytesRead;
  }
  check(ValidateXml(xmlData, (size_t)xmlInfo.size), ERROR_STR_INVALIDXML);
  check(WriteAtomically(directory, outputFilename, xmlData,
                        (size_t)xmlInfo.size),
        ERROR_STR_FILEFAIL);
  result = true;
error:
  if (xmlFile != NULL)
    zip_fclose(xmlFile);
  if (archive != NULL)
    zip_close(archive);
  if (source != NULL)
    zip_source_free(source);
  if (zipErrorInitialized)
    zip_error_fini(&zipError);
  free(decodedArchive);
  free(xmlData);
  return result;
}

static void FreeSOAPResult(TSOAPContext *context) {
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

int main(int argc, char **argv) {
  TDownloadOptions options;
  TZapretContext context;
  TSMTPContext smtpContext;
  void *requestFile = NULL;
  size_t requestFileLength = 0;
  void *signatureFile = NULL;
  size_t signatureFileLength = 0;
  char *smtpHost = NULL;
  int exitCode = EXIT_FAILURE;
  bool curlInitialized = false;

  memset(&options, 0, sizeof(options));
  memset(&context, 0, sizeof(context));
  memset(&smtpContext, 0, sizeof(smtpContext));
  check(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK,
        ERROR_STR_INITIALIZATION);
  curlInitialized = true;
  if (!ParseOptions(argc, argv, &options)) {
    PrintUsage(argv[0]);
    goto error;
  }
  context.blacklistHost = NormalizeHost(options.host);
  check(context.blacklistHost != NULL, ERROR_STR_INVALIDSTRING);
  context.blacklistCooldownNegative = options.pollInterval;

  check(ReadFile(options.requestFile, &requestFile, &requestFileLength),
        ERROR_STR_FILEFAIL);
  check(ValidateXml(requestFile, requestFileLength), ERROR_STR_INVALIDXML);
  check(ReadFile(options.signatureFile, &signatureFile, &signatureFileLength),
        ERROR_STR_FILEFAIL);
  check(EnsureDirectory(options.outputDirectory), ERROR_STR_FILEFAIL);

  signal(SIGINT, SignalHandler);
  signal(SIGTERM, SignalHandler);
  LIBXML_TEST_VERSION
  xmlInitParser();

  PerformSOAPCommunicationPrepared(
      &context, requestFile, requestFileLength, signatureFile,
      signatureFileLength);
  check(!flagMatrixShutdown && context.soapContext != NULL &&
            context.soapContext->soapResult &&
            context.soapContext->registerZipArchive != NULL &&
            context.soapContext->socialZipArchive != NULL,
        ERROR_STR_SOAP, "download");

  check(SaveArchiveXml(context.soapContext->registerZipArchive,
                       options.outputDirectory, "blacklist.xml"),
        ERROR_STR_FILEFAIL);
  check(SaveArchiveXml(context.soapContext->socialZipArchive,
                       options.outputDirectory, "social.xml"),
        ERROR_STR_FILEFAIL);
  if (options.emailMode != EMAIL_MODE_DISABLED) {
    smtpHost = NormalizeSmtpHost(options.smtpHost);
    check(smtpHost != NULL, ERROR_STR_INVALIDSTRING);
    smtpContext.smtpHost = smtpHost;
    smtpContext.smtpSender = (char *)options.smtpSender;
    size_t recipientList =
        options.emailMode == EMAIL_MODE_WITH_ATTACHMENTS ? 0 : 1;
    smtpContext.recipients[recipientList] = options.smtpRecipients;
    check(SendSMTPMessage(&smtpContext, context.soapContext),
          ERROR_STR_LIBCURL, "SMTP notification");
    smtpContext.recipients[recipientList] = NULL;
  }
  exitCode = EXIT_SUCCESS;
error:
  free(requestFile);
  free(signatureFile);
  free(context.blacklistHost);
  free(smtpHost);
  if (options.smtpRecipients != NULL)
    curl_slist_free_all(options.smtpRecipients);
  FreeSOAPResult(context.soapContext);
  Base64Cleanup();
  xmlCleanupParser();
  if (curlInitialized)
    curl_global_cleanup();
  return exitCode;
}
