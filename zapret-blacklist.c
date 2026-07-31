#include "allheaders.h"

#include "zapret-checker.h"

bool InitializeZapretBlacklist(
    TZapretBlacklist *blacklist,
    const uint32_t bucketCounts[NETFILTER_TYPE_COUNT]) {
  bool result = false;

  if (blacklist == NULL || bucketCounts == NULL ||
      blacklist->httpRules != NULL || blacklist->dnsNames != NULL ||
      blacklist->ipAddresses != NULL)
    return false;
  blacklist->httpRules =
      pfHashMapCreate(NULL, bucketCounts[NETFILTER_TYPE_HTTP]);
  if (blacklist->httpRules == NULL)
    goto error;
  blacklist->dnsNames =
      pfHashSetCreate(NULL, bucketCounts[NETFILTER_TYPE_DNS]);
  if (blacklist->dnsNames == NULL)
    goto error;
  blacklist->ipAddresses =
      pfHashSetCreate(NULL, bucketCounts[NETFILTER_TYPE_IP]);
  if (blacklist->ipAddresses == NULL)
    goto error;
  result = true;

error:
  if (!result)
    DestroyZapretBlacklist(blacklist);
  return result;
}

void DestroyZapretBlacklist(TZapretBlacklist *blacklist) {
  if (blacklist == NULL)
    return;
  pfHashMapDestroy(blacklist->httpRules);
  pfHashSetDestroy(blacklist->dnsNames);
  pfHashSetDestroy(blacklist->ipAddresses);
  memset(blacklist, 0, sizeof(*blacklist));
}
