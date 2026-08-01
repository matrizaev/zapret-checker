/*************************************************************************
 * Модуль обработки дампа реестра запрещенных сайтов РосКомНадзора.       *
 *************************************************************************/

#include "allheaders.h"
#include <arpa/inet.h>
#include <idn2.h>
#include <libxml/xmlreader.h>
#include <netdb.h>
#include <netinet/in.h>
#include <zip.h>

#include "zapret-checker.h"

#define DUMP_XML_FILENAME "dump.xml"

static int ZipReadCallback(void *context, char *buffer, int len) {
  if (context == NULL || buffer == NULL || len <= 0)
    return 0;
  zip_int64_t bytesRead =
      zip_fread((struct zip_file *)context, buffer, (zip_uint64_t)len);
  if (bytesRead < 0)
    return -1;
  return (int)bytesRead;
}

static int FDReadCallback(void *context, char *buffer, int len) {
  ssize_t bytesRead = -1;

  if (context == NULL || buffer == NULL || len <= 0)
    return 0;
  int fd = *((int *)context);
  do {
    bytesRead = read(fd, buffer, (size_t)len);
  } while (bytesRead < 0 && errno == EINTR);
  if (bytesRead < 0)
    return -1;
  return (int)bytesRead;
}

static void MakeNSLookup(char *host, pfHashSet *ipAddresses) {
  struct addrinfo aiHints;
  struct addrinfo *aiResult = NULL, *aiPointer = NULL;

  if (host == NULL || ipAddresses == NULL)
    return;
  memset(&aiHints, 0, sizeof(struct addrinfo));
  aiHints.ai_family = AF_INET;
  aiHints.ai_socktype = SOCK_STREAM;
  aiHints.ai_flags = AI_PASSIVE;
  aiHints.ai_protocol = 0;
  aiHints.ai_canonname = NULL;
  aiHints.ai_addr = NULL;
  aiHints.ai_next = NULL;
  if (getaddrinfo(host, NULL, &aiHints, &aiResult) == 0) {
    for (aiPointer = aiResult; aiPointer != NULL;
         aiPointer = aiPointer->ai_next) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)aiPointer->ai_addr;
      char *ipAddr = inet_ntoa(saddr->sin_addr);
      if (!pfHashSetAdd(ipAddresses, ipAddr)) {
        log_err(ERROR_STR_HASHERROR);
      }
    }
  }
  if (aiResult != NULL)
    freeaddrinfo(aiResult);
  return;
}

typedef enum {
  REGISTER_FIELD_NONE,
  REGISTER_FIELD_URL,
  REGISTER_FIELD_DOMAIN,
  REGISTER_FIELD_IP,
  REGISTER_FIELD_IP_SUBNET
} TRegisterFieldType;

typedef struct TRegisterFieldStruct {
  TRegisterFieldType type;
  char *value;
  struct TRegisterFieldStruct *next;
} TRegisterField;

typedef struct {
  TRegisterField *head;
  TRegisterField *tail;
} TRegisterRecord;

typedef struct {
  char *data;
  size_t length;
  size_t capacity;
} TRegisterText;

static void ClearRegisterText(TRegisterText *text) {
  if (text == NULL)
    return;
  free(text->data);
  memset(text, 0, sizeof(*text));
}

static void ClearRegisterRecord(TRegisterRecord *record) {
  TRegisterField *field = NULL;

  if (record == NULL)
    return;
  field = record->head;
  while (field != NULL) {
    TRegisterField *next = field->next;
    free(field->value);
    free(field);
    field = next;
  }
  memset(record, 0, sizeof(*record));
}

static bool AppendRegisterText(TRegisterText *text, const xmlChar *value) {
  size_t valueLength = 0;
  size_t required = 0;
  size_t newCapacity = 0;
  char *resized = NULL;

  if (text == NULL || value == NULL)
    return false;
  valueLength = strlen((const char *)value);
  if (valueLength > SIZE_MAX - text->length - 1)
    return false;
  required = text->length + valueLength + 1;
  if (required > text->capacity) {
    newCapacity = text->capacity == 0 ? 64 : text->capacity;
    while (newCapacity < required) {
      if (newCapacity > SIZE_MAX / 2) {
        newCapacity = required;
        break;
      }
      newCapacity *= 2;
    }
    resized = realloc(text->data, newCapacity);
    if (resized == NULL)
      return false;
    text->data = resized;
    text->capacity = newCapacity;
  }
  memcpy(text->data + text->length, value, valueLength);
  text->length += valueLength;
  text->data[text->length] = '\0';
  return true;
}

static bool AddRegisterField(TRegisterRecord *record, TRegisterFieldType type,
                             TRegisterText *text) {
  TRegisterField *field = NULL;
  char *trimmed = NULL;
  size_t trimmedLength = 0;

  if (record == NULL || text == NULL || type == REGISTER_FIELD_NONE ||
      text->data == NULL)
    return false;
  trimmed = TrimWhiteSpaces(text->data);
  if (trimmed == NULL)
    return false;
  trimmedLength = strlen(trimmed);
  if (trimmed != text->data)
    memmove(text->data, trimmed, trimmedLength + 1);

  field = calloc(1, sizeof(*field));
  if (field == NULL)
    return false;
  field->type = type;
  field->value = text->data;
  text->data = NULL;
  text->length = 0;
  text->capacity = 0;
  if (record->tail == NULL)
    record->head = field;
  else
    record->tail->next = field;
  record->tail = field;
  return true;
}

static TRegisterFieldType RegisterFieldType(const xmlChar *name) {
  if (name == NULL)
    return REGISTER_FIELD_NONE;
  if (xmlStrEqual(name, BAD_CAST "url"))
    return REGISTER_FIELD_URL;
  if (xmlStrEqual(name, BAD_CAST "domain"))
    return REGISTER_FIELD_DOMAIN;
  if (xmlStrEqual(name, BAD_CAST "ip"))
    return REGISTER_FIELD_IP;
  if (xmlStrEqual(name, BAD_CAST "ipSubnet"))
    return REGISTER_FIELD_IP_SUBNET;
  return REGISTER_FIELD_NONE;
}

static bool ProcessRegisterURL(char *value, pfHashMap *httpRules) {
  static const char httpPrefix[] = "http://";
  uint8_t *asciiHost = NULL;
  char *host = NULL;
  char *url = NULL;
  bool result = false;

  if (value == NULL || httpRules == NULL ||
      strncasecmp(httpPrefix, value, sizeof(httpPrefix) - 1) != 0)
    return false;
  host = value + sizeof(httpPrefix) - 1;
  url = index(host, '/');
  if (url != NULL)
    *url = '\0';
  if (index(host, ':') != NULL)
    return false;
  if (idn2_lookup_u8((uint8_t *)host, &asciiHost, 0) != IDN2_OK ||
      asciiHost == NULL)
    goto cleanup;

  if (url == NULL)
    url = "/";
  else {
    char *fragment = NULL;
    *url = '/';
    fragment = index(url, '#');
    if (fragment != NULL)
      *fragment = '\0';
    DecodeURL(url);
  }
  LowerStringCase((char *)asciiHost);
  if (!pfHashMapAdd(httpRules, (char *)asciiHost, url))
    log_err(ERROR_STR_HASHERROR);
  else
    result = true;

cleanup:
  if (asciiHost != NULL)
    idn2_free(asciiHost);
  return result;
}

static void ProcessRegisterDomain(char *value, bool makeNSLookup,
                                  TZapretBlacklist *blacklist) {
  uint8_t *host = NULL;
  uint8_t *dnsNotation = NULL;

  if (value == NULL || blacklist == NULL)
    return;
  if (idn2_lookup_u8((uint8_t *)value, &host, 0) != IDN2_OK || host == NULL)
    goto cleanup;
  if (makeNSLookup)
    MakeNSLookup((char *)host, blacklist->ipAddresses);
  dnsNotation = String2DNSNotation((char *)host);
  if (dnsNotation != NULL &&
      !pfHashSetAdd(blacklist->dnsNames, (char *)dnsNotation))
    log_err(ERROR_STR_HASHERROR);

cleanup:
  free(dnsNotation);
  if (host != NULL)
    idn2_free(host);
}

static void ProcessRegisterIP(char *value, pfHashSet *ipAddresses) {
  if (value != NULL && ipAddresses != NULL &&
      !pfHashSetAdd(ipAddresses, value))
    log_err(ERROR_STR_HASHERROR);
}

static void ProcessRegisterRecord(TRegisterRecord *record, bool makeNSLookup,
                                  TZapretBlacklist *blacklist) {
  bool httpURLFound = false;

  if (record == NULL || blacklist == NULL)
    return;
  for (TRegisterField *field = record->head; field != NULL;
       field = field->next) {
    switch (field->type) {
    case REGISTER_FIELD_URL:
      if (ProcessRegisterURL(field->value, blacklist->httpRules))
        httpURLFound = true;
      break;
    case REGISTER_FIELD_DOMAIN:
      if (!httpURLFound)
        ProcessRegisterDomain(field->value, makeNSLookup, blacklist);
      break;
    case REGISTER_FIELD_IP:
    case REGISTER_FIELD_IP_SUBNET:
      if (!httpURLFound)
        ProcessRegisterIP(field->value, blacklist->ipAddresses);
      break;
    default:
      break;
    }
  }
}

static bool WriteRegisterTimestamp(const xmlChar *updateTime,
                                   const char *timestampFile) {
  FILE *file = NULL;
  size_t updateTimeLength = 0;
  int closeResult = -1;
  bool result = false;

  if (timestampFile == NULL)
    return true;
  check(updateTime != NULL && access(timestampFile, W_OK) == 0,
        ERROR_STR_INVALIDINPUT);
  updateTimeLength = strlen((const char *)updateTime);
  check(updateTimeLength > 0, ERROR_STR_INVALIDXML);
  file = fopen(timestampFile, "w");
  check(file != NULL, ERROR_STR_FILEFAIL);
  check(fwrite(updateTime, 1, updateTimeLength, file) == updateTimeLength,
        ERROR_STR_FILEFAIL);
  closeResult = fclose(file);
  file = NULL;
  check(closeResult == 0, ERROR_STR_FILEFAIL);
  result = true;

error:
  if (file != NULL && fclose(file) != 0)
    log_err(ERROR_STR_FILEFAIL);
  return result;
}

static bool ParseRegisterXml(xmlInputReadCallback readCallback, void *readCtx,
                             bool makeNSLookup, char *timestampFile,
                             TZapretBlacklist *blacklist) {
  xmlTextReaderPtr reader = NULL;
  TRegisterRecord record = {0};
  TRegisterText fieldText = {0};
  TRegisterFieldType fieldType = REGISTER_FIELD_NONE;
  int fieldDepth = -1;
  int recordDepth = -1;
  int rootDepth = -1;
  int readResult = 0;
  xmlChar *updateTime = NULL;
  bool inRecord = false;
  bool rootSeen = false;
  bool result = false;

  check(readCtx != NULL && readCallback != NULL && blacklist != NULL,
        ERROR_STR_INVALIDINPUT);
  check(blacklist->httpRules != NULL && blacklist->dnsNames != NULL &&
            blacklist->ipAddresses != NULL,
        ERROR_STR_INVALIDINPUT);
  reader = xmlReaderForIO(readCallback, NULL, readCtx, NULL, "windows-1251",
                          XML_PARSE_NOBLANKS | XML_PARSE_NONET |
                              XML_PARSE_COMPACT);
  check(reader != NULL, ERROR_STR_INVALIDXML);

  while ((readResult = xmlTextReaderRead(reader)) == 1) {
    int nodeType = xmlTextReaderNodeType(reader);
    int depth = xmlTextReaderDepth(reader);

    check(flagMatrixShutdown == 0 && flagMatrixReconfigure == 0,
          ERROR_STR_STOPRECONF);

    if (!rootSeen) {
      if (nodeType != XML_READER_TYPE_ELEMENT)
        continue;
      rootSeen = true;
      rootDepth = depth;
      if (timestampFile != NULL) {
        check(access(timestampFile, W_OK) == 0, ERROR_STR_INVALIDINPUT);
        updateTime =
            xmlTextReaderGetAttribute(reader, BAD_CAST "updateTime");
        check(updateTime != NULL && updateTime[0] != '\0',
              ERROR_STR_INVALIDXML);
      }
      continue;
    }

    if (!inRecord) {
      if (nodeType == XML_READER_TYPE_ELEMENT && depth == rootDepth + 1) {
        inRecord = true;
        recordDepth = depth;
        if (xmlTextReaderIsEmptyElement(reader) == 1) {
          ProcessRegisterRecord(&record, makeNSLookup, blacklist);
          ClearRegisterRecord(&record);
          inRecord = false;
          recordDepth = -1;
        }
      }
      continue;
    }

    if (fieldType != REGISTER_FIELD_NONE) {
      if ((nodeType == XML_READER_TYPE_TEXT ||
           nodeType == XML_READER_TYPE_CDATA ||
           nodeType == XML_READER_TYPE_WHITESPACE ||
           nodeType == XML_READER_TYPE_SIGNIFICANT_WHITESPACE) &&
          depth > fieldDepth) {
        const xmlChar *value = xmlTextReaderConstValue(reader);
        if (value != NULL)
          check(AppendRegisterText(&fieldText, value), ERROR_STR_INVALIDSTRING);
      } else if (nodeType == XML_READER_TYPE_END_ELEMENT &&
                 depth == fieldDepth) {
        check(AddRegisterField(&record, fieldType, &fieldText),
              ERROR_STR_INVALIDSTRING);
        fieldType = REGISTER_FIELD_NONE;
        fieldDepth = -1;
      }
      continue;
    }

    if (nodeType == XML_READER_TYPE_ELEMENT && depth == recordDepth + 1) {
      fieldType = RegisterFieldType(xmlTextReaderConstLocalName(reader));
      if (fieldType != REGISTER_FIELD_NONE) {
        fieldDepth = depth;
        if (xmlTextReaderIsEmptyElement(reader) == 1) {
          check(AddRegisterField(&record, fieldType, &fieldText),
                ERROR_STR_INVALIDSTRING);
          fieldType = REGISTER_FIELD_NONE;
          fieldDepth = -1;
        }
      }
      continue;
    }

    if (nodeType == XML_READER_TYPE_END_ELEMENT && depth == recordDepth) {
      ProcessRegisterRecord(&record, makeNSLookup, blacklist);
      ClearRegisterRecord(&record);
      inRecord = false;
      recordDepth = -1;
    }
  }
  check(readResult == 0 && rootSeen && !inRecord &&
            fieldType == REGISTER_FIELD_NONE,
        ERROR_STR_INVALIDXML);
  check(WriteRegisterTimestamp(updateTime, timestampFile), ERROR_STR_FILEFAIL);
  result = true;

error:
  ClearRegisterText(&fieldText);
  ClearRegisterRecord(&record);
  if (reader != NULL)
    xmlFreeTextReader(reader);
  if (updateTime != NULL)
    xmlFree(updateTime);
  return result;
}

static TZapretBlacklist *CreateStagingBlacklist(
    const TZapretBlacklist *destination) {
  TZapretBlacklist *staging = NULL;
  uint32_t bucketCounts[NETFILTER_TYPE_COUNT] = {0};

  if (destination == NULL || destination->httpRules == NULL ||
      destination->dnsNames == NULL || destination->ipAddresses == NULL)
    return NULL;
  bucketCounts[NETFILTER_TYPE_HTTP] = destination->httpRules->bucketCount;
  bucketCounts[NETFILTER_TYPE_DNS] = destination->dnsNames->bucketCount;
  bucketCounts[NETFILTER_TYPE_IP] = destination->ipAddresses->bucketCount;
  staging = calloc(1, sizeof(*staging));
  if (staging == NULL)
    return NULL;
  if (!InitializeZapretBlacklist(staging, bucketCounts)) {
    free(staging);
    return NULL;
  }
  return staging;
}

static bool MoveStagedBlacklist(TZapretBlacklist *destination,
                                TZapretBlacklist *staging) {
  if (destination == NULL || staging == NULL)
    return false;
  if (!pfHashMapPrepareMoveEntries(destination->httpRules,
                                   staging->httpRules))
    return false;
  pfHashMapMoveEntries(destination->httpRules, staging->httpRules);
  pfHashSetMoveEntries(destination->dnsNames, staging->dnsNames);
  pfHashSetMoveEntries(destination->ipAddresses, staging->ipAddresses);
  return true;
}

TZapretBlacklist *ProcessRegisterZipArchive(char *registerZipArchive,
                                            bool makeNSLookup,
                                            char *timestampFile) {
  struct zip_source *zipSource = NULL;
  struct zip *zipArchive = NULL;
  struct zip_file *zipFile = NULL;
  struct zip_stat zipFileStat;
  void *decodedZipArchive = NULL;
  size_t decodedZipArchiveLength = 0;
  zip_error_t zipError;
  TZapretBlacklist *result = NULL;
  const uint32_t bucketCounts[NETFILTER_TYPE_COUNT] = {
      ZAPRET_HTTP_HASH_BUCKET_COUNT, ZAPRET_DNS_HASH_BUCKET_COUNT,
      ZAPRET_IP_HASH_BUCKET_COUNT};

  check(registerZipArchive != NULL, ERROR_STR_INVALIDINPUT);
  memset(&zipError, 0, sizeof(zip_error_t));
  result = calloc(1, sizeof(*result));
  check_mem(result);
  check(InitializeZapretBlacklist(result, bucketCounts), ERROR_STR_HASHERROR);
  decodedZipArchive = Base64Decode(
      registerZipArchive, strlen(registerZipArchive), &decodedZipArchiveLength);
  check(decodedZipArchive != NULL, ERROR_STR_INVALIDBASE64);
  zipSource = zip_source_buffer_create(
      decodedZipArchive, (zip_uint64_t)decodedZipArchiveLength, 0, &zipError);
  check(zipSource != NULL, ERROR_STR_ZIPERROR, zip_error_strerror(&zipError));
  zipArchive = zip_open_from_source(zipSource, 0, &zipError);
  check(zipArchive != NULL, ERROR_STR_ZIPERROR, zip_error_strerror(&zipError));
  zipSource = NULL;
  for (int i = 0; i < zip_get_num_entries(zipArchive, 0); i++) {
    check((zip_stat_index(zipArchive, i, 0, &zipFileStat) == 0),
          ERROR_STR_ZIPERROR, zip_strerror(zipArchive));
    if (strcasecmp(DUMP_XML_FILENAME, zipFileStat.name) == 0) {
      zipFile = zip_fopen_index(zipArchive, i, 0);
      check(zipFile != NULL, ERROR_STR_ZIPERROR, zip_strerror(zipArchive));
      check(ParseRegisterXml(ZipReadCallback, zipFile, makeNSLookup,
                             timestampFile, result) == true,
            ERROR_STR_INVALIDXML);
      break;
    }
  }
  check(zipFile != NULL, ERROR_STR_ZIPERROR, "dump.xml not found");
  zip_fclose(zipFile);
  zip_close(zipArchive);
  free(decodedZipArchive);
  TrimUnusedHeap();
  return result;
error:
  if (result != NULL) {
    DestroyZapretBlacklist(result);
    free(result);
  }
  if (zipFile != NULL)
    zip_fclose(zipFile);
  if (zipArchive != NULL)
    zip_close(zipArchive);
  else if (zipSource != NULL)
    zip_source_free(zipSource);
  if (decodedZipArchive != NULL)
    free(decodedZipArchive);
  TrimUnusedHeap();
  return NULL;
}

bool ProcessRegisterCustomBlacklist(bool makeNSLookup, char *customBlackList,
                                    TZapretBlacklist *result) {
  bool exitCode = false;
  int closeResult = -1;
  int customFD = -1;
  TZapretBlacklist *staging = NULL;

  if (customBlackList != NULL) {
    check(access(customBlackList, R_OK) == 0, ERROR_STR_INVALIDINPUT);
    check((customFD = open(customBlackList, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) !=
              -1,
          ERROR_STR_FILEFAIL);
    staging = CreateStagingBlacklist(result);
    check_mem(staging);
    check(ParseRegisterXml(FDReadCallback, &customFD, makeNSLookup, NULL,
                           staging) == true,
          ERROR_STR_INVALIDXML);
    closeResult = close(customFD);
    customFD = -1;
    check(closeResult == 0, ERROR_STR_FILEFAIL);
    check(MoveStagedBlacklist(result, staging), ERROR_STR_HASHERROR);
  }
  exitCode = true;
error:
  if (customFD != -1)
    close(customFD);
  if (staging != NULL) {
    DestroyZapretBlacklist(staging);
    free(staging);
  }
  if (customBlackList != NULL)
    TrimUnusedHeap();
  return exitCode;
}
