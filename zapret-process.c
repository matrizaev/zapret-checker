/*************************************************************************
* Модуль обработки дампа реестра запрещенных сайтов РосКомНадзора.       *
*************************************************************************/

#include "allheaders.h"
#include <zip.h>
#include <libxml/xmlmemory.h>
#include <idn2.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "zapret-checker.h"

#define DUMP_XML_FILENAME "dump.xml"


static void MakeNSLookup(char *host, pfHashTable *hashTable)
{
    struct addrinfo aiHints;
    struct addrinfo *aiResult = NULL, *aiPointer = NULL;

	if (host == NULL || hashTable == NULL)
		return;
	memset(&aiHints, 0, sizeof(struct addrinfo));
    aiHints.ai_family = AF_INET;
    aiHints.ai_socktype = SOCK_STREAM;
    aiHints.ai_flags = AI_PASSIVE;
    aiHints.ai_protocol = 0;
    aiHints.ai_canonname = NULL;
    aiHints.ai_addr = NULL;
    aiHints.ai_next = NULL;
	if (getaddrinfo(host, NULL, &aiHints, &aiResult) == 0)
	{
		for (aiPointer = aiResult; aiPointer != NULL; aiPointer = aiPointer->ai_next)
		{
			struct sockaddr_in* saddr = (struct sockaddr_in*)aiPointer->ai_addr;
			char *ipAddr = inet_ntoa(saddr->sin_addr);
			if (pfHashSet (hashTable, ipAddr, host) != true)
			{
				log_err(ERROR_STR_HASHERROR);
			}
		}
	}
	if (aiResult != NULL)
		freeaddrinfo(aiResult);
	return;
}

static bool ParseRegisterXml (xmlInputReadCallback readCallback, void * readCtx, bool makeNSLookup, char *timestampFile, pfHashTable **hashTables)
{
	xmlDoc *doc = NULL;
	xmlNodePtr node = NULL;
	xmlChar *nodeVal = NULL;
	bool result = false;
	FILE *tmpFile = NULL;

	check (readCtx != NULL && readCallback != NULL && hashTables != NULL, ERROR_STR_INVALIDINPUT);
	for (int i = 0; i < NETFILTER_TYPE_COUNT; i++)
	{
		check (hashTables[i] != NULL, ERROR_STR_INVALIDINPUT);
	}
	doc = xmlReadIO ((xmlInputReadCallback)readCallback, NULL, readCtx, NULL, "windows-1251", XML_PARSE_NOBLANKS | XML_PARSE_NONET);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	node = xmlDocGetRootElement (doc);
	check (node != NULL, ERROR_STR_INVALIDXML);
	if (timestampFile != NULL)
	{
		check ((access (timestampFile, W_OK)) == 0, ERROR_STR_INVALIDINPUT);
		tmpFile = fopen (timestampFile, "w");
		check (tmpFile != NULL, ERROR_STR_FILEFAIL);
		nodeVal = xmlGetProp (node, BAD_CAST "updateTime");
		check (nodeVal != NULL, ERROR_STR_INVALIDXML);
		check ((fwrite (nodeVal, xmlStrlen (nodeVal), 1, tmpFile)) > 0, ERROR_STR_FILEFAIL);
		fclose (tmpFile);
		tmpFile = NULL;
		xmlFree (nodeVal);
		nodeVal = NULL;
	}
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		bool httpURLFound = false;
		check (flagMatrixShutdown == 0 && flagMatrixReconfigure == 0, ERROR_STR_STOPRECONF);
		for (xmlNode *nodeChld = node->children; nodeChld != NULL; nodeChld = nodeChld->next)
		{
			if (nodeChld->type != XML_ELEMENT_NODE)
				continue;
			
			nodeVal = xmlNodeGetContent (nodeChld->xmlChildrenNode);
			char *tempString = TrimWhiteSpaces ((char *)nodeVal);
			if (!xmlStrcmp (nodeChld->name, BAD_CAST "url"))
			{
				check (tempString != NULL, ERROR_STR_INVALIDSTRING);
				if (!strncasecmp ("http://", tempString, strlen ("http://")))
				{
					char *host = NULL;
					char *url = NULL;
					host = tempString + strlen ("http://");
					url = index(host, '/');
					if (url != NULL)
						*url = '\0';
					if (index(host, ':') == NULL)
					{
						int idnResult = idn2_lookup_u8((uint8_t *)host, (uint8_t **)&host, 0);
						if (host != NULL && idnResult == IDN2_OK)
						{
							if (url == NULL)
								url = "/";
							else
							{
								*url = '/';
								char* sharp = index (url, '#');
								if (sharp != NULL)
									*sharp = '\0';
								DecodeURL (url);
							}
							LowerStringCase (host);
							if (pfHashSet (hashTables[NETFILTER_TYPE_HTTP], host, url) != true)
								log_err(ERROR_STR_HASHERROR);
							else
								httpURLFound = true;
							free(host);
						}
					}
				}
			}
			else if (!xmlStrcmp (nodeChld->name, BAD_CAST "domain"))
			{
				check (tempString != NULL, ERROR_STR_INVALIDSTRING);
				if (httpURLFound == false)
				{
					char *host = NULL;
					int idnResult = idn2_lookup_u8((uint8_t *)tempString, (uint8_t **)&host, 0);
					if (host != NULL && idnResult == IDN2_OK)
					{
						if (makeNSLookup == true)
						{
							MakeNSLookup (host, hashTables[NETFILTER_TYPE_IP]);
						}
						uint8_t *dnsNotation = String2DNSNotation (host);
						if (dnsNotation != NULL)
						{
							if (pfHashSet (hashTables[NETFILTER_TYPE_DNS], (char *)dnsNotation, NULL) != true)
								log_err(ERROR_STR_HASHERROR);
							free (dnsNotation);
						}
					}
					if (host != NULL)
						free(host);
				}
			}
			else if (!xmlStrcmp (nodeChld->name, BAD_CAST "ip"))
			{
				check (tempString != NULL, ERROR_STR_INVALIDSTRING);
				if (httpURLFound == false)
				{
					if (pfHashSet (hashTables[NETFILTER_TYPE_IP], tempString, NULL) != true)
					{
						log_err(ERROR_STR_HASHERROR);
					}
				}
			}
			else if (!xmlStrcmp (nodeChld->name, BAD_CAST "ipSubnet"))
			{
				check (tempString != NULL, ERROR_STR_INVALIDSTRING);
				if (httpURLFound == false)
				{
					if (pfHashSet (hashTables[NETFILTER_TYPE_IP], tempString, NULL) != true)
					{
						log_err(ERROR_STR_HASHERROR);
					}
				}
			}
			if (nodeVal != NULL)
			{
				xmlFree (nodeVal);
				nodeVal = NULL;
			}
		}
	}
	result = true;
error:
	if (tmpFile != NULL)
		fclose(tmpFile);
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return result;
}

pfHashTable **ProcessRegisterZipArchive (char *registerZipArchive, bool makeNSLookup, char *timestampFile)
{
	struct zip_source *zipSource = NULL;
	struct zip *zipArchive = NULL;
	struct zip_file *zipFile = NULL;
	struct zip_stat zipFileStat;
	void *decodedZipArchive = NULL;
	size_t decodedZipArchiveLength = 0;
	zip_error_t zipError;
	pfHashTable **result = NULL;
	
	check (registerZipArchive != NULL, ERROR_STR_INVALIDINPUT);
	memset (&zipError, 0, sizeof (zip_error_t));
	result = calloc (NETFILTER_TYPE_COUNT, sizeof(pfHashTable *));
	check_mem (result);
	for (int i = 0; i < NETFILTER_TYPE_COUNT; i++)
	{
		result[i] = pfHashCreate (NULL, 15013);
		check_mem (result[i]);
	}
	decodedZipArchive = Base64Decode (registerZipArchive, strlen (registerZipArchive), &decodedZipArchiveLength);
	check (decodedZipArchive != NULL, ERROR_STR_INVALIDBASE64);
	zipSource = zip_source_buffer_create (decodedZipArchive, (zip_uint64_t)decodedZipArchiveLength, 0, &zipError);
	check (zipSource != NULL, ERROR_STR_ZIPERROR, zip_strerror (zipArchive));
	zipArchive = zip_open_from_source (zipSource, 0, &zipError);
	check (zipArchive != NULL, ERROR_STR_ZIPERROR, zip_strerror (zipArchive));
	for (int i = 0; i < zip_get_num_entries (zipArchive, 0); i++)
	{
		check ((zip_stat_index (zipArchive, i, 0, &zipFileStat) == 0), ERROR_STR_ZIPERROR, zip_strerror (zipArchive));
		if (strcasecmp (DUMP_XML_FILENAME, zipFileStat.name) == 0)
		{
			zipFile = zip_fopen_index (zipArchive, i, 0);
			check (zipFile != NULL, ERROR_STR_ZIPERROR, zip_strerror (zipArchive));
			check(ParseRegisterXml ((xmlInputReadCallback)zip_fread, zipFile, makeNSLookup, timestampFile, result) == true, ERROR_STR_INVALIDXML);
			break;
		}
	}
	zip_fclose(zipFile);
	zip_close (zipArchive);
	free (decodedZipArchive);
	return result;
error:
	if (result != NULL)
	{
		for (int i = 0; i < NETFILTER_TYPE_COUNT; i++)
		{
			if (result[i] != NULL)
			{
				pfHashDestroy(result[i]);
				result[i] = NULL;
			}
		}
		free (result);
	}
	if (zipFile != NULL)
		zip_fclose(zipFile);
	if (zipArchive != NULL)
		zip_close (zipArchive);
	if (decodedZipArchive != NULL)
		free (decodedZipArchive);
	return NULL;
}

bool ProcessRegisterCustomBlacklist (bool makeNSLookup, char *customBlackList, pfHashTable **result)
{
	bool exitCode = false;
	int customFD = 0;
	if (customBlackList != NULL)
	{
		check (access (customBlackList, R_OK) == 0, ERROR_STR_INVALIDINPUT);
		check ((customFD = open (customBlackList, O_RDONLY)) != -1, ERROR_STR_FILEFAIL);
		check (ParseRegisterXml ((xmlInputReadCallback)read, (void *)(long)customFD, makeNSLookup, NULL, result) == true, ERROR_STR_INVALIDXML);
		close (customFD);
		customFD = 0;
	}
	exitCode = true;
error:
	if (customFD > 0)
		close (customFD);
	return exitCode;
}