#include <curl/curl.h>
#include <libxml/xmlmemory.h>

#include "errorstrings.h"
#include "pfhash.h"
#include "sign.h"
#include "util.h"
#include "zapret-structures.h"

extern volatile sig_atomic_t flagMatrixShutdown;
extern volatile sig_atomic_t flagMatrixReconfigure;
extern volatile sig_atomic_t flagMatrixReload;

#define ZAPRET_DEFAULT_CONFIG_FILE \
  "/etc/zapret-checker/zapret-checker.xml"

/* configurationFile is borrowed and remains owned by the caller. */
extern bool ReadZapretConfiguration(TZapretContext *context,
                                    const char *configurationFile);

extern void ClearSOAPContext(TSOAPContext *context);
extern void ClearSMTPContext(TSMTPContext *context);
extern void ClearNetfilterContext(TNetfilterContext **context,
                                  size_t contextCount);
extern void ClearZapretContext(TZapretContext *context);

extern void PerformSOAPCommunication(TZapretContext *context);
extern void PerformSOAPCommunicationPrepared(
    TZapretContext *context, const void *requestFile, size_t requestFileLength,
    const void *signatureFile, size_t signatureFileLength);

extern bool SendSMTPMessage(TSMTPContext *smtpContext,
                            TSOAPContext *soapContext);

/* Initializes an empty, owned blacklist. blacklist must contain NULL members. */
extern bool InitializeZapretBlacklist(
    TZapretBlacklist *blacklist,
    const uint32_t bucketCounts[NETFILTER_TYPE_COUNT]);
extern void DestroyZapretBlacklist(TZapretBlacklist *blacklist);

/* Returns a newly allocated, owned blacklist or NULL on failure. */
extern TZapretBlacklist *ProcessRegisterZipArchive(char *registerZipArchive,
                                                   bool makeNSLookup,
                                                   char *timestampFile);
extern bool ProcessRegisterCustomBlacklist(bool makeNSLookup,
                                           char *customBlackList,
                                           TZapretBlacklist *result);

extern bool ProcessRawPacketHTTP(uint8_t *packet, size_t packetSize,
                                 TNetfilterContext *threadData,
                                 uint8_t hwAddr[8]);
extern bool ProcessRawPacketDNS(uint8_t *packet, size_t packetSize,
                                TNetfilterContext *threadData,
                                uint8_t hwAddr[8]);

extern TNetfilterContext **
InitNetfilterConfiguration(size_t count, char *redirectIface,
                           char *redirectHost, size_t netfilterQueue,
                           TNetfilterType threadType);
extern void StartHTTPNetfilterProcessing(TNetfilterContext **context,
                                         size_t contextCount,
                                         const pfHashMap *httpRules);
extern void StartDNSNetfilterProcessing(TNetfilterContext **context,
                                        size_t contextCount,
                                        const pfHashSet *dnsNames);
extern void StopNetfilterProcessing(TNetfilterContext **context,
                                    size_t contextCount);
