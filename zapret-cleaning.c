/*************************************************************************
* Модуль очистки памяти.                                                 *
*************************************************************************/

#include "allheaders.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "zapret-checker.h"

void ClearSOAPContext(TSOAPContext *context)
{
	if (context == NULL)
		return;
	if (context->dumpFormatVersion != NULL)
	{
		free (context->dumpFormatVersion);
		context->dumpFormatVersion = NULL;
	}
	if (context->dumpFormatVersionSocResources != NULL)
	{
		free (context->dumpFormatVersionSocResources);
		context->dumpFormatVersionSocResources = NULL;
	}
	if (context->webServiceVersion != NULL)
	{
		free (context->webServiceVersion);
		context->webServiceVersion = NULL;
	}
	if (context->docVersion != NULL)
	{
		free (context->docVersion);
		context->docVersion = NULL;
	}
	if (context->requestCode != NULL)
	{
		free (context->requestCode);
		context->requestCode = NULL;
	}	
	if (context->requestResult != NULL)
	{
		free (context->requestResult);
		context->requestResult = NULL;
	}
	if (context->requestComment != NULL)
	{
		free (context->requestComment);
		context->requestComment = NULL;
	}
	if (context->registerZipArchive != NULL)
	{
		free (context->registerZipArchive);
		context->registerZipArchive = NULL;
	}
	if (context->socialZipArchive != NULL)
	{
		free (context->socialZipArchive);
		context->socialZipArchive = NULL;
	}
	if (context->resultResult != NULL)
	{
		free (context->resultResult);
		context->resultResult = NULL;
	}
	if (context->resultComment != NULL)
	{
		free (context->resultComment);
		context->resultComment = NULL;
	}
	if (context->operatorName != NULL)
	{
		free (context->operatorName);
		context->operatorName = NULL;
	}
	if (context->operatorINN != NULL)
	{
		free (context->operatorINN);
		context->operatorINN = NULL;
	}
	if (context->privateKeyId != NULL)
	{
		context->privateKeyId = NULL;
	}
	if (context->privateKeyPassword != NULL)
	{
		context->privateKeyId = NULL;
	}
	context->soapResult = false;
	context->resultCode = 0;
}

void ClearNetfilterContext(TNetfilterContext **context, size_t contextCount)
{
	
	if (context == NULL || contextCount == 0)
		return;
	StopNetfilterProcessing(context, contextCount);
	for (size_t i = 0; i < contextCount; i++)
	{
		if (context[i] == NULL)
			continue;
		if (context[i]->redirectSocket != 0)
			close(context[i]->redirectSocket);
		if (context[i]->redirectNetworkPacket != NULL)
			free(context[i]->redirectNetworkPacket);
		if (context[i]->nfQueue != NULL)
			nfq_destroy_queue(context[i]->nfQueue);
		if (context[i]->nfqHandle != NULL)
			nfq_close (context[i]->nfqHandle);
		free(context[i]);
		context[i] = NULL;
	}
}

void ClearSMTPContext (TSMTPContext *context)
{
	if (context == NULL)
		return;
	if (context->smtpSender != NULL)
	{
		free (context->smtpSender);
	}	
	if (context->smtpHost != NULL)
	{
		free (context->smtpHost);
	}
	for (int i = 0; i < SMTP_RECIPIENTS_LIST_COUNT; i++)
		if (context->recipients[i] != NULL)
			curl_slist_free_all (context->recipients[i]);
	free (context);
}

void ClearZapretContext (TZapretContext *context)
{
	if (context == NULL)
		return;
	if (context->smtpContext != NULL)
	{
		ClearSMTPContext (context->smtpContext);
	}
	if (context->soapContext != NULL)
	{
		ClearSOAPContext (context->soapContext);
		if (context->soapContext->lastDumpDate != NULL)
			free (context->soapContext->lastDumpDate);
		if (context->soapContext->lastDumpDateUrgently != NULL)
			free (context->soapContext->lastDumpDateUrgently);
		if (context->soapContext->lastDumpDateSocResources != NULL)
			free (context->soapContext->lastDumpDateSocResources);
		free (context->soapContext);
	}
	ClearNetfilterContext (context->httpThreadsContext, context->redirectHTTPCount);
	free (context->httpThreadsContext);
	ClearNetfilterContext (context->dnsThreadsContext, context->redirectDNSCount);
	free (context->dnsThreadsContext);
	if (context->redirectHost != NULL)
	{
		free (context->redirectHost);
	}
	if (context->redirectIface != NULL)
	{
		free (context->redirectIface);
	}
	if (context->redirectIpsetList != NULL)
	{
		free (context->redirectIpsetList);
	}
	if (context->requestXmlDoc != NULL)
	{
		xmlFreeDoc (context->requestXmlDoc);
	}
	if (context->blacklistHost != NULL)
	{
		free (context->blacklistHost);
	}
	if (context->timestampFile != NULL)
	{
		free (context->timestampFile);
	}
	if (context->customBlacklist != NULL)
	{
		free (context->customBlacklist);
	}
	if (context->privateKeyId != NULL)
	{
		free (context->privateKeyId);
	}
	if (context->privateKeyPassword != NULL)
	{
		free (context->privateKeyPassword);
	}
	for (int i = 0; i < NETFILTER_TYPE_COUNT; i++)
		if (context->hashTables[i] != NULL)
		{
			pfHashDestroy(context->hashTables[i]);
		}
	memset (context, 0, sizeof(TZapretContext));
}