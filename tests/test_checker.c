#include "allheaders.h"

#include <curl/curl.h>
#include <libxml/parser.h>

#include "vendor/munit/munit.h"

#define main ZapretCheckerMain
#include "../zapret-checker.c"
#undef main

typedef enum {
  CHECKER_SCENARIO_IDLE,
  CHECKER_SCENARIO_RECONFIGURE,
  CHECKER_SCENARIO_SOAP_ARCHIVE,
  CHECKER_SCENARIO_SOAP_SUCCESS,
  CHECKER_SCENARIO_SOAP_FAILURE,
} TCheckerScenario;

typedef enum {
  IPSET_FAIL_NONE,
  IPSET_FAIL_PIPE,
  IPSET_FAIL_FORK,
  IPSET_FAIL_FDOPEN,
  IPSET_FAIL_WAIT,
} TIpsetFailure;

static TCheckerScenario checkerScenario = CHECKER_SCENARIO_IDLE;
static TIpsetFailure ipsetFailure = IPSET_FAIL_NONE;
static bool ipsetMockActive = false;
static bool signalMockActive = false;
static bool failConfiguration = false;
static int failHashCreationAt = -1;
static bool customBlacklistResult = true;
static bool archiveResultAvailable = true;
static bool enableIpset = false;
static bool onlyHTTPContext = false;
static bool zeroCooldown = false;
static bool shutdownDuringSOAP = false;
static int failSigactionAt = -1;
static size_t clearZapretCount = 0;
static size_t clearSOAPCount = 0;
static size_t configurationCount = 0;
static size_t hashCreateCount = 0;
static size_t hashDestroyCount = 0;
static size_t customBlacklistCount = 0;
static size_t startCount = 0;
static size_t stopCount = 0;
static size_t soapCount = 0;
static size_t smtpCount = 0;
static size_t archiveCount = 0;
static size_t sleepCount = 0;
static size_t pauseCount = 0;
static size_t curlInitCount = 0;
static size_t curlCleanupCount = 0;
static size_t pipeCount = 0;
static size_t forkCount = 0;
static size_t closeCount = 0;
static size_t waitCount = 0;
static size_t sigactionCount = 0;
static time_t lastSleep = 0;
static time_t mockTimes[4] = {0};
static size_t mockTimeCount = 0;
static size_t mockTimeIndex = 0;
static char configurationPath[PATH_MAX] = {0};
static char eventLog[256] = {0};
static size_t eventCount = 0;
static char *ipsetOutput = NULL;
static size_t ipsetOutputLength = 0;
static void (*installedHandlers[3])(int) = {0};

static void RecordEvent(char event) {
  munit_assert_size(eventCount + 1, <, sizeof(eventLog));
  eventLog[eventCount++] = event;
  eventLog[eventCount] = '\0';
}

static void ResetCheckerMocks(void) {
  checkerScenario = CHECKER_SCENARIO_IDLE;
  ipsetFailure = IPSET_FAIL_NONE;
  ipsetMockActive = false;
  signalMockActive = false;
  failConfiguration = false;
  failHashCreationAt = -1;
  customBlacklistResult = true;
  archiveResultAvailable = true;
  enableIpset = false;
  onlyHTTPContext = false;
  zeroCooldown = false;
  shutdownDuringSOAP = false;
  failSigactionAt = -1;
  clearZapretCount = 0;
  clearSOAPCount = 0;
  configurationCount = 0;
  hashCreateCount = 0;
  hashDestroyCount = 0;
  customBlacklistCount = 0;
  startCount = 0;
  stopCount = 0;
  soapCount = 0;
  smtpCount = 0;
  archiveCount = 0;
  sleepCount = 0;
  pauseCount = 0;
  curlInitCount = 0;
  curlCleanupCount = 0;
  pipeCount = 0;
  forkCount = 0;
  closeCount = 0;
  waitCount = 0;
  sigactionCount = 0;
  lastSleep = 0;
  memset(mockTimes, 0, sizeof(mockTimes));
  mockTimeCount = 0;
  mockTimeIndex = 0;
  memset(configurationPath, 0, sizeof(configurationPath));
  memset(eventLog, 0, sizeof(eventLog));
  eventCount = 0;
  free(ipsetOutput);
  ipsetOutput = NULL;
  ipsetOutputLength = 0;
  memset(installedHandlers, 0, sizeof(installedHandlers));
  flagMatrixShutdown = 0;
  flagMatrixReconfigure = 1;
  flagMatrixReload = 0;
}

static pfHashSet *AllocateMockSet(void) {
  pfHashSet *set = calloc(1, sizeof(*set) + sizeof(set->lookup[0]));
  if (set == NULL)
    return NULL;
  set->bucketCount = 1;
  return set;
}

static pfHashMap *AllocateMockMap(void) {
  pfHashMap *map = calloc(1, sizeof(*map) + sizeof(map->lookup[0]));
  if (map == NULL)
    return NULL;
  map->bucketCount = 1;
  return map;
}

static bool MockHashCreationAllowed(void) {
  if ((int)hashCreateCount == failHashCreationAt) {
    hashCreateCount++;
    return false;
  }
  hashCreateCount++;
  RecordEvent('H');
  return true;
}

static void DestroyMockSet(pfHashSet *set) {
  if (set == NULL)
    return;
  hashDestroyCount++;
  RecordEvent('D');
  for (uint32_t i = 0; i < set->bucketCount; i++) {
    pfHashSetNode *node = set->lookup[i];
    while (node != NULL) {
      pfHashSetNode *next = node->next;
      free(node->key);
      free(node);
      node = next;
    }
  }
  free(set);
}

static void DestroyMockMap(pfHashMap *map) {
  if (map == NULL)
    return;
  hashDestroyCount++;
  RecordEvent('D');
  for (uint32_t i = 0; i < map->bucketCount; i++) {
    pfHashMapNode *node = map->lookup[i];
    while (node != NULL) {
      pfHashMapNode *next = node->next;
      free(node->key);
      DestroyMockSet(node->values);
      free(node);
      node = next;
    }
  }
  free(map);
}

bool InitializeZapretBlacklist(
    TZapretBlacklist *blacklist,
    const uint32_t bucketCounts[NETFILTER_TYPE_COUNT]) {
  munit_assert_not_null(blacklist);
  munit_assert_not_null(bucketCounts);
  munit_assert_uint32(bucketCounts[NETFILTER_TYPE_HTTP], ==,
                      ZAPRET_HTTP_HASH_BUCKET_COUNT);
  munit_assert_uint32(bucketCounts[NETFILTER_TYPE_DNS], ==,
                      ZAPRET_DNS_HASH_BUCKET_COUNT);
  munit_assert_uint32(bucketCounts[NETFILTER_TYPE_IP], ==,
                      ZAPRET_IP_HASH_BUCKET_COUNT);
  if (!MockHashCreationAllowed() ||
      (blacklist->httpRules = AllocateMockMap()) == NULL)
    goto error;
  if (!MockHashCreationAllowed() ||
      (blacklist->dnsNames = AllocateMockSet()) == NULL)
    goto error;
  if (!MockHashCreationAllowed() ||
      (blacklist->ipAddresses = AllocateMockSet()) == NULL)
    goto error;
  return true;

error:
  DestroyZapretBlacklist(blacklist);
  return false;
}

void DestroyZapretBlacklist(TZapretBlacklist *blacklist) {
  if (blacklist == NULL)
    return;
  DestroyMockMap(blacklist->httpRules);
  DestroyMockSet(blacklist->dnsNames);
  DestroyMockSet(blacklist->ipAddresses);
  memset(blacklist, 0, sizeof(*blacklist));
}

static void FreeSOAPFields(TSOAPContext *context) {
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
}

void ClearSOAPContext(TSOAPContext *context) {
  clearSOAPCount++;
  RecordEvent('Q');
  if (context == NULL)
    return;
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
  context->dumpFormatVersion = NULL;
  context->dumpFormatVersionSocResources = NULL;
  context->webServiceVersion = NULL;
  context->docVersion = NULL;
  context->requestCode = NULL;
  context->requestResult = NULL;
  context->requestComment = NULL;
  context->registerZipArchive = NULL;
  context->socialZipArchive = NULL;
  context->resultResult = NULL;
  context->resultComment = NULL;
  context->operatorName = NULL;
  context->operatorINN = NULL;
  context->soapResult = false;
  context->resultCode = 0;
}

void ClearZapretContext(TZapretContext *context) {
  clearZapretCount++;
  RecordEvent('C');
  if (context == NULL)
    return;
  if (context->soapContext != NULL) {
    FreeSOAPFields(context->soapContext);
    free(context->soapContext);
  }
  free(context->smtpContext);
  free(context->httpThreadsContext);
  free(context->dnsThreadsContext);
  DestroyZapretBlacklist(&context->blacklist);
  if (context->requestXmlDoc != NULL)
    xmlFreeDoc(context->requestXmlDoc);
  free(context->blacklistHost);
  free(context->customBlacklist);
  free(context->timestampFile);
  free(context->redirectIpsetList);
  memset(context, 0, sizeof(*context));
}

bool ReadZapretConfiguration(TZapretContext *context,
                             const char *path) {
  munit_assert_not_null(context);
  munit_assert_not_null(path);
  configurationCount++;
  RecordEvent('R');
  snprintf(configurationPath, sizeof(configurationPath), "%s", path);
  if (failConfiguration)
    return false;

  context->redirectHTTPCount = 1;
  context->httpThreadsContext = calloc(1, sizeof(*context->httpThreadsContext));
  munit_assert_not_null(context->httpThreadsContext);
  if (!onlyHTTPContext) {
    context->redirectDNSCount = 1;
    context->dnsThreadsContext =
        calloc(1, sizeof(*context->dnsThreadsContext));
    munit_assert_not_null(context->dnsThreadsContext);
  }
  context->customBlacklist = strdup("custom.xml");
  munit_assert_not_null(context->customBlacklist);
  if (enableIpset) {
    context->redirectIpsetList = strdup("ZAPRET_MAIN");
    munit_assert_not_null(context->redirectIpsetList);
  }

  if (checkerScenario == CHECKER_SCENARIO_SOAP_ARCHIVE ||
      checkerScenario == CHECKER_SCENARIO_SOAP_SUCCESS ||
      checkerScenario == CHECKER_SCENARIO_SOAP_FAILURE) {
    context->blacklistHost = strdup("soap.example.test");
    context->requestXmlDoc = xmlNewDoc(BAD_CAST "1.0");
    context->smtpContext = calloc(1, sizeof(*context->smtpContext));
    context->blacklistCooldownPositive = zeroCooldown ? 0 : 10;
    context->blacklistCooldownNegative = zeroCooldown ? 0 : 4;
    munit_assert_not_null(context->blacklistHost);
    munit_assert_not_null(context->requestXmlDoc);
    munit_assert_not_null(context->smtpContext);
  }
  return true;
}

bool ProcessRegisterCustomBlacklist(bool makeNSLookup, char *customBlacklist,
                                    TZapretBlacklist *blacklist) {
  (void)makeNSLookup;
  munit_assert_string_equal(customBlacklist, "custom.xml");
  munit_assert_not_null(blacklist);
  customBlacklistCount++;
  RecordEvent('B');
  return customBlacklistResult;
}

static void RecordNetfilterStart(TNetfilterContext **contexts, size_t count,
                                 const void *blacklist) {
  if (count == 0) {
    munit_assert_null(contexts);
    return;
  }
  munit_assert_not_null(contexts);
  munit_assert_size(count, ==, 1);
  munit_assert_not_null(blacklist);
  startCount++;
  RecordEvent('S');
}

void StartHTTPNetfilterProcessing(TNetfilterContext **contexts, size_t count,
                                  const pfHashMap *httpRules) {
  RecordNetfilterStart(contexts, count, httpRules);
}

void StartDNSNetfilterProcessing(TNetfilterContext **contexts, size_t count,
                                 const pfHashSet *dnsNames) {
  RecordNetfilterStart(contexts, count, dnsNames);
}

void StopNetfilterProcessing(TNetfilterContext **contexts, size_t count) {
  if (count == 0) {
    munit_assert_null(contexts);
    return;
  }
  munit_assert_not_null(contexts);
  munit_assert_size(count, ==, 1);
  stopCount++;
  RecordEvent('T');
}

void PerformSOAPCommunication(TZapretContext *context) {
  munit_assert_not_null(context);
  soapCount++;
  RecordEvent('P');
  context->soapContext = calloc(1, sizeof(*context->soapContext));
  munit_assert_not_null(context->soapContext);
  context->soapContext->lastDumpDate = strdup("last-date");
  munit_assert_not_null(context->soapContext->lastDumpDate);
  if (checkerScenario == CHECKER_SCENARIO_SOAP_ARCHIVE) {
    context->soapContext->soapResult = true;
    context->soapContext->registerZipArchive = strdup("archive");
    munit_assert_not_null(context->soapContext->registerZipArchive);
  } else if (checkerScenario == CHECKER_SCENARIO_SOAP_SUCCESS) {
    context->soapContext->soapResult = true;
  }
  if (shutdownDuringSOAP)
    flagMatrixShutdown = 1;
}

bool SendSMTPMessage(TSMTPContext *smtpContext, TSOAPContext *soapContext) {
  munit_assert_not_null(smtpContext);
  munit_assert_not_null(soapContext);
  smtpCount++;
  RecordEvent('M');
  return true;
}

TZapretBlacklist *ProcessRegisterZipArchive(char *archive, bool makeNSLookup,
                                            char *timestampFile) {
  (void)makeNSLookup;
  (void)timestampFile;
  munit_assert_string_equal(archive, "archive");
  archiveCount++;
  RecordEvent('A');
  if (!archiveResultAvailable)
    return NULL;
  TZapretBlacklist *blacklist = calloc(1, sizeof(*blacklist));
  munit_assert_not_null(blacklist);
  blacklist->httpRules = AllocateMockMap();
  blacklist->dnsNames = AllocateMockSet();
  blacklist->ipAddresses = AllocateMockSet();
  munit_assert_not_null(blacklist->httpRules);
  munit_assert_not_null(blacklist->dnsNames);
  munit_assert_not_null(blacklist->ipAddresses);
  return blacklist;
}

void Base64Cleanup(void) { RecordEvent('X'); }

CURLcode curl_global_init(long flags) {
  munit_assert_long(flags, ==, CURL_GLOBAL_ALL);
  curlInitCount++;
  return CURLE_OK;
}

void curl_global_cleanup(void) { curlCleanupCount++; }

int __real_sigemptyset(sigset_t *set);
int __wrap_sigemptyset(sigset_t *set) {
  if (!signalMockActive)
    return __real_sigemptyset(set);
  memset(set, 0, sizeof(*set));
  return 0;
}

int __real_sigaction(int signalNumber, const struct sigaction *action,
                     struct sigaction *oldAction);
int __wrap_sigaction(int signalNumber, const struct sigaction *action,
                     struct sigaction *oldAction) {
  if (!signalMockActive)
    return __real_sigaction(signalNumber, action, oldAction);
  (void)oldAction;
  munit_assert_not_null(action);
  if ((int)sigactionCount == failSigactionAt) {
    errno = EINVAL;
    return -1;
  }
  munit_assert_size(sigactionCount, <, 3);
  installedHandlers[sigactionCount++] = action->sa_handler;
  if (sigactionCount == 1)
    munit_assert_int(signalNumber, ==, SIGTERM);
  else if (sigactionCount == 2)
    munit_assert_int(signalNumber, ==, SIGHUP);
  else
    munit_assert_int(signalNumber, ==, SIGINT);
  return 0;
}

unsigned int __wrap_sleep(unsigned int seconds) {
  sleepCount++;
  lastSleep = (time_t)seconds;
  if (checkerScenario == CHECKER_SCENARIO_RECONFIGURE && sleepCount == 1)
    flagMatrixReconfigure = 1;
  else
    flagMatrixShutdown = 1;
  return 0;
}

int __wrap_pause(void) {
  pauseCount++;
  if (checkerScenario == CHECKER_SCENARIO_RECONFIGURE && pauseCount == 1)
    flagMatrixReconfigure = 1;
  else
    flagMatrixShutdown = 1;
  return -1;
}

time_t __wrap_time(time_t *result) {
  time_t value = mockTimeIndex < mockTimeCount ? mockTimes[mockTimeIndex++] : 0;
  if (result != NULL)
    *result = value;
  return value;
}

int __real_pipe(int descriptors[2]);
int __wrap_pipe(int descriptors[2]) {
  if (!ipsetMockActive)
    return __real_pipe(descriptors);
  pipeCount++;
  if (ipsetFailure == IPSET_FAIL_PIPE) {
    errno = EMFILE;
    return -1;
  }
  descriptors[0] = 110;
  descriptors[1] = 111;
  return 0;
}

pid_t __real_fork(void);
pid_t __wrap_fork(void) {
  if (!ipsetMockActive)
    return __real_fork();
  forkCount++;
  if (ipsetFailure == IPSET_FAIL_FORK) {
    errno = EAGAIN;
    return -1;
  }
  return 321;
}

FILE *__real_fdopen(int descriptor, const char *mode);
FILE *__wrap_fdopen(int descriptor, const char *mode) {
  if (!ipsetMockActive)
    return __real_fdopen(descriptor, mode);
  munit_assert_int(descriptor, ==, 111);
  munit_assert_string_equal(mode, "w");
  if (ipsetFailure == IPSET_FAIL_FDOPEN) {
    errno = EMFILE;
    return NULL;
  }
  free(ipsetOutput);
  ipsetOutput = NULL;
  ipsetOutputLength = 0;
  return open_memstream(&ipsetOutput, &ipsetOutputLength);
}

int __real_close(int descriptor);
int __wrap_close(int descriptor) {
  if (!ipsetMockActive || (descriptor != 110 && descriptor != 111))
    return __real_close(descriptor);
  closeCount++;
  return 0;
}

pid_t __real_waitpid(pid_t child, int *status, int options);
pid_t __wrap_waitpid(pid_t child, int *status, int options) {
  if (!ipsetMockActive)
    return __real_waitpid(child, status, options);
  munit_assert_int(child, ==, 321);
  munit_assert_int(options, ==, 0);
  waitCount++;
  if (status != NULL)
    *status = 0;
  if (ipsetFailure == IPSET_FAIL_WAIT) {
    errno = ECHILD;
    return -1;
  }
  return child;
}

static int RunChecker(const char *configurationFile) {
  char *defaultArguments[] = {"zapret-checker", NULL};
  char *customArguments[] = {"zapret-checker", "--config",
                             (char *)configurationFile, NULL};
  signalMockActive = true;
  int result = configurationFile == NULL
                   ? ZapretCheckerMain(1, defaultArguments)
                   : ZapretCheckerMain(3, customArguments);
  signalMockActive = false;
  return result;
}

static MunitResult TestSignalConfiguration(const MunitParameter parameters[],
                                           void *fixture) {
  (void)parameters;
  (void)fixture;
  ResetCheckerMocks();
  signalMockActive = true;
  munit_assert_true(ConfigureSignalHandlers());
  signalMockActive = false;
  munit_assert_size(sigactionCount, ==, 3);

  flagMatrixShutdown = 0;
  installedHandlers[0](SIGTERM);
  munit_assert_int(flagMatrixShutdown, ==, 1);
  flagMatrixReconfigure = 0;
  installedHandlers[1](SIGHUP);
  munit_assert_int(flagMatrixReconfigure, ==, 1);
  flagMatrixReload = 0;
  installedHandlers[2](SIGINT);
  munit_assert_int(flagMatrixReload, ==, 1);

  ResetCheckerMocks();
  signalMockActive = true;
  failSigactionAt = 1;
  munit_assert_false(ConfigureSignalHandlers());
  signalMockActive = false;
  return MUNIT_OK;
}

static pfHashSet *BuildIpsetTable(void) {
  pfHashSet *set = AllocateMockSet();
  munit_assert_not_null(set);
  pfHashSetNode *first = calloc(1, sizeof(*first));
  pfHashSetNode *second = calloc(1, sizeof(*second));
  munit_assert_not_null(first);
  munit_assert_not_null(second);
  first->key = strdup("192.0.2.0/24");
  second->key = strdup("2001:db8::/32");
  munit_assert_not_null(first->key);
  munit_assert_not_null(second->key);
  first->next = second;
  set->lookup[0] = first;
  set->keyCount = 2;
  return set;
}

static MunitResult TestIpsetSerialization(const MunitParameter parameters[],
                                          void *fixture) {
  pfHashSet *ipAddresses = NULL;

  (void)parameters;
  (void)fixture;
  ResetCheckerMocks();
  ipAddresses = BuildIpsetTable();
  ipsetMockActive = true;
  UpdateIpsetList("ZAPRET_MAIN", ipAddresses);
  ipsetMockActive = false;
  munit_assert_not_null(ipsetOutput);
  munit_assert_not_null(strstr(
      ipsetOutput, "-exist create ZAPRET_TEMP hash:net maxelem 100000000\n"));
  munit_assert_not_null(
      strstr(ipsetOutput, "-exist add ZAPRET_TEMP 192.0.2.0/24\n"));
  munit_assert_not_null(
      strstr(ipsetOutput, "-exist add ZAPRET_TEMP 2001:db8::/32\n"));
  munit_assert_not_null(
      strstr(ipsetOutput, "swap ZAPRET_TEMP ZAPRET_MAIN\n"));
  munit_assert_not_null(strstr(ipsetOutput, "destroy ZAPRET_TEMP\n"));
  munit_assert_size(pipeCount, ==, 1);
  munit_assert_size(forkCount, ==, 1);
  munit_assert_size(closeCount, ==, 1);
  munit_assert_size(waitCount, ==, 1);
  DestroyMockSet(ipAddresses);

  UpdateIpsetList(NULL, NULL);
  return MUNIT_OK;
}

static MunitResult TestIpsetFailures(const MunitParameter parameters[],
                                     void *fixture) {
  static const TIpsetFailure failures[] = {
      IPSET_FAIL_PIPE, IPSET_FAIL_FORK, IPSET_FAIL_FDOPEN, IPSET_FAIL_WAIT,
  };

  (void)parameters;
  (void)fixture;
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    ResetCheckerMocks();
    pfHashSet *ipAddresses = BuildIpsetTable();
    ipsetFailure = failures[i];
    ipsetMockActive = true;
    UpdateIpsetList("ZAPRET_MAIN", ipAddresses);
    ipsetMockActive = false;
    DestroyMockSet(ipAddresses);
  }
  return MUNIT_OK;
}

static MunitResult TestReconfigurationLifecycle(
    const MunitParameter parameters[], void *fixture) {
  (void)parameters;
  (void)fixture;
  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_RECONFIGURE;
  customBlacklistResult = false;
  munit_assert_int(RunChecker("/tmp/test-config.xml"), ==, EXIT_SUCCESS);
  munit_assert_string_equal(configurationPath, "/tmp/test-config.xml");
  munit_assert_size(configurationCount, ==, 2);
  munit_assert_size(clearZapretCount, ==, 3);
  munit_assert_size(hashCreateCount, ==, 6);
  munit_assert_size(hashDestroyCount, ==, 6);
  munit_assert_size(customBlacklistCount, ==, 2);
  munit_assert_size(startCount, ==, 4);
  munit_assert_size(pauseCount, ==, 2);
  munit_assert_size(curlInitCount, ==, 1);
  munit_assert_size(curlCleanupCount, ==, 1);
  return MUNIT_OK;
}

static MunitResult TestSOAPArchiveReplacement(
    const MunitParameter parameters[], void *fixture) {
  (void)parameters;
  (void)fixture;
  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_SOAP_ARCHIVE;
  enableIpset = true;
  onlyHTTPContext = true;
  customBlacklistResult = false;
  ipsetMockActive = true;
  flagMatrixShutdown = 0;
  mockTimes[0] = 100;
  mockTimes[1] = 103;
  mockTimeCount = 2;
  munit_assert_int(RunChecker(NULL), ==, EXIT_SUCCESS);
  ipsetMockActive = false;
  munit_assert_size(soapCount, ==, 1);
  munit_assert_size(smtpCount, ==, 1);
  munit_assert_size(archiveCount, ==, 1);
  munit_assert_size(customBlacklistCount, ==, 2);
  munit_assert_size(stopCount, ==, 1);
  munit_assert_size(startCount, ==, 2);
  munit_assert_size(clearSOAPCount, ==, 1);
  munit_assert_size(sleepCount, ==, 1);
  munit_assert_int64(lastSleep, ==, 7);
  munit_assert_size(pipeCount, ==, 2);
  munit_assert_not_null(strstr(eventLog, "PMABTDDDSQ"));
  return MUNIT_OK;
}

static MunitResult TestSOAPSchedules(const MunitParameter parameters[],
                                     void *fixture) {
  (void)parameters;
  (void)fixture;
  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_SOAP_SUCCESS;
  mockTimes[0] = 200;
  mockTimes[1] = 215;
  mockTimeCount = 2;
  munit_assert_int(RunChecker(NULL), ==, EXIT_SUCCESS);
  munit_assert_int64(lastSleep, ==, 4);

  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_SOAP_FAILURE;
  mockTimes[0] = 300;
  mockTimes[1] = 301;
  mockTimeCount = 2;
  munit_assert_int(RunChecker(NULL), ==, EXIT_SUCCESS);
  munit_assert_int64(lastSleep, ==, 4);

  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_SOAP_FAILURE;
  zeroCooldown = true;
  mockTimes[0] = 400;
  mockTimes[1] = 401;
  mockTimeCount = 2;
  munit_assert_int(RunChecker(NULL), ==, EXIT_SUCCESS);
  munit_assert_int64(lastSleep, ==, 1);

  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_SOAP_SUCCESS;
  shutdownDuringSOAP = true;
  mockTimes[0] = 500;
  mockTimes[1] = 501;
  mockTimeCount = 2;
  munit_assert_int(RunChecker(NULL), ==, EXIT_SUCCESS);
  munit_assert_size(sleepCount, ==, 0);
  return MUNIT_OK;
}

static MunitResult TestMainFailures(const MunitParameter parameters[],
                                    void *fixture) {
  char *invalidArguments[] = {"zapret-checker", "--bad", NULL};

  (void)parameters;
  (void)fixture;
  ResetCheckerMocks();
  munit_assert_int(ZapretCheckerMain(2, invalidArguments), ==, EXIT_FAILURE);
  munit_assert_size(curlInitCount, ==, 0);

  ResetCheckerMocks();
  failConfiguration = true;
  munit_assert_int(RunChecker(NULL), ==, EXIT_FAILURE);
  munit_assert_size(clearZapretCount, ==, 2);
  munit_assert_size(curlCleanupCount, ==, 1);

  ResetCheckerMocks();
  failHashCreationAt = 1;
  munit_assert_int(RunChecker(NULL), ==, EXIT_FAILURE);
  munit_assert_size(hashCreateCount, ==, 2);
  munit_assert_size(hashDestroyCount, ==, 1);

  ResetCheckerMocks();
  checkerScenario = CHECKER_SCENARIO_SOAP_ARCHIVE;
  archiveResultAvailable = false;
  mockTimes[0] = 600;
  mockTimes[1] = 601;
  mockTimeCount = 2;
  munit_assert_int(RunChecker(NULL), ==, EXIT_SUCCESS);
  munit_assert_size(archiveCount, ==, 1);
  munit_assert_size(stopCount, ==, 0);
  return MUNIT_OK;
}

static MunitTest checkerTests[] = {
    {"/signal-configuration", TestSignalConfiguration, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/ipset-serialization", TestIpsetSerialization, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/ipset-failures", TestIpsetFailures, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/reconfiguration-lifecycle", TestReconfigurationLifecycle, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/soap-archive-replacement", TestSOAPArchiveReplacement, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/soap-schedules", TestSOAPSchedules, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {"/main-failures", TestMainFailures, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite checkerSuite = {
    "/checker", checkerTests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char **argv) {
  int result = munit_suite_main(&checkerSuite, NULL, argc, argv);
  free(ipsetOutput);
  return result;
}
