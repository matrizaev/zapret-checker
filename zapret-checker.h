#include <libxml/xmlmemory.h>
#include <curl/curl.h>
#include "pfhash.h"
#include "sign.h"
#include "util.h"
#include "zapret-structures.h"
#include "errorstrings.h"

extern volatile sig_atomic_t	flagMatrixShutdown;
extern volatile sig_atomic_t	flagMatrixReconfigure;
extern volatile sig_atomic_t	flagMatrixReload;

extern bool ReadZapretConfiguration (TZapretContext *context);

extern void ClearSOAPContext (TSOAPContext *context);
extern void ClearNetfilterContext(TNetfilterContext **context, size_t contextCount);
extern void ClearZapretContext (TZapretContext *context);

extern void PerformSOAPCommunication (TZapretContext *context);

extern void SendSMTPMessage (TSMTPContext *smtpContext, TSOAPContext *soapContext);

extern pfHashTable **ProcessRegisterZipArchive (char *registerZipArchive, bool makeNSLookup, char *timestampFile);
extern bool ProcessRegisterCustomBlacklist (bool makeNSLookup, char *customBlackList, pfHashTable **result);

extern bool ProcessRawPacketHTTP (uint8_t *packet, size_t packetSize, TNetfilterContext *threadData, uint8_t hwAddr[8]);
extern bool ProcessRawPacketDNS (uint8_t *packet, size_t packetSize, TNetfilterContext *threadData, uint8_t hwAddr[8]);

extern TNetfilterContext **InitNetfilterConfiguration(size_t count, char *redirectIface, char *redirectHost, size_t netfilterQueue, TNetfilterType threadType);
extern void StartNetfilterProcessing (TNetfilterContext **context, size_t contextCount, pfHashTable *hashTable);
extern void StopNetfilterProcessing(TNetfilterContext **context, size_t contextCount);