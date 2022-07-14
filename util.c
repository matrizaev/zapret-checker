/**************************************************************************************************
	Various Utilities Module
	BASE64 encode and decode stuff is from
	http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
**************************************************************************************************/

#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/tree.h>
#include <time.h>
#include <curl/curl.h>
#include "util.h"

#include "errorstrings.h"

#define IP_DF 0x4000
#define IP4_HDRLEN 20

static unsigned char gEncodingTable[] = {	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
											'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
											'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
											'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
											'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
											'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
											'w', 'x', 'y', 'z', '0', '1', '2', '3',
											'4', '5', '6', '7', '8', '9', '+', '/'};
static unsigned char *gDecodingTable = NULL;
static unsigned int gModTable[] = {0, 2, 1};

void BuildgDecodingTable ()
{
	gDecodingTable = malloc (256);
	for (unsigned int i = 0; i < 64; i++)
		gDecodingTable[gEncodingTable[i]] = i;
}

char *Base64Encode (const void *data, size_t inputLength, size_t *outputLength)
{
	char *encodedData = NULL;

	check ((data != NULL) && (outputLength != NULL) && (inputLength > 0), ERROR_STR_INVALIDINPUT);
	*outputLength = 4 * ((inputLength + 2) / 3);
	encodedData = calloc (*outputLength + 1, 1);
	check_mem (encodedData);
	for (unsigned int i = 0, j = 0; i < inputLength;)
	{
		uint32_t octet_a = i < inputLength ? ((unsigned char *)(data))[i++] : 0;
		uint32_t octet_b = i < inputLength ? ((unsigned char *)(data))[i++] : 0;
		uint32_t octet_c = i < inputLength ? ((unsigned char *)(data))[i++] : 0;
		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
		encodedData[j++] = gEncodingTable[(triple >> 3 * 6) & 0x3F];
		encodedData[j++] = gEncodingTable[(triple >> 2 * 6) & 0x3F];
		encodedData[j++] = gEncodingTable[(triple >> 1 * 6) & 0x3F];
		encodedData[j++] = gEncodingTable[(triple >> 0 * 6) & 0x3F];
	}
	for (unsigned int i = 0; i < gModTable[inputLength % 3]; i++)
		encodedData[*outputLength - 1 - i] = '=';
	return encodedData;
error:
	if (encodedData != NULL)
		free (encodedData);
	return NULL;
}

void *Base64Decode (const char *data, size_t inputLength, size_t *outputLength)
{
	unsigned char *decodedData = NULL;

	check (((data != NULL) && (outputLength != NULL) && (inputLength >= BASE64_MINIMUM_LEN) && (inputLength % 4 == 0)), ERROR_STR_INVALIDINPUT);
	if (gDecodingTable == NULL)
		BuildgDecodingTable ();
	*outputLength = inputLength / 4 * 3;
	if (data[inputLength - 1] == '=')
		(*outputLength)--;
	if (data[inputLength - 2] == '=')
		(*outputLength)--;
	decodedData = calloc (*outputLength, 1);
	check_mem (decodedData);
	for (unsigned int i = 0, j = 0; i < inputLength;)
	{
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : gDecodingTable[(unsigned char)data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : gDecodingTable[(unsigned char)data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : gDecodingTable[(unsigned char)data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : gDecodingTable[(unsigned char)data[i++]];
		uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);
		if (j < *outputLength)
			decodedData[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *outputLength)
			decodedData[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *outputLength)
			decodedData[j++] = (triple >> 0 * 8) & 0xFF;
	}
error:
	return decodedData;
}

void Base64Cleanup ()
{
	if (gDecodingTable != NULL)
		free (gDecodingTable);
	gDecodingTable = NULL;
}

char *GetDateTime (const char *dateTimeFormat)
{
	time_t epochTime = 0;
	struct tm *t = NULL;
	char *requestTime = NULL;
	size_t length = 0;

	check (dateTimeFormat != NULL, ERROR_STR_INVALIDINPUT);
	epochTime = time (NULL);
	check (epochTime != -1, ERROR_STR_INVALIDTIME);
	t = localtime (&epochTime);
	check (t != NULL, ERROR_STR_INVALIDTIME);
	length = strlen (dateTimeFormat) * 2 + 1;
	requestTime = calloc (length, 1);
	check_mem (requestTime);
	check (strftime (requestTime, length, dateTimeFormat, t) != 0, ERROR_STR_INVALIDSTRING);
	return requestTime;
error:
	if (requestTime != NULL)
		free (requestTime);
	return NULL;
}

char *TrimWhiteSpaces (char *str)
{
	char *end = NULL;

	if (str == NULL)
		return NULL;
	while (isspace (*str)) str++;
	if (*str == 0)
		return NULL;
	end = str + strlen (str) - 1;
	while (end > str && isspace (*end)) end--;
	*(end + 1) = 0;
	return str;
}

bool ValidateXmlFile (const char *xmlFileName, const char *schemaFileName)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr schemaDoc = NULL;
	xmlSchemaParserCtxtPtr parserCtxt = NULL;
	xmlSchemaPtr schema = NULL;
	xmlSchemaValidCtxtPtr validCtxt = NULL;
	bool result = false;

	check ((xmlFileName != NULL) && (schemaFileName != NULL), ERROR_STR_INVALIDINPUT);
	doc = xmlParseFile (xmlFileName);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	schemaDoc = xmlReadFile (schemaFileName, NULL, XML_PARSE_NONET);
	check (schemaDoc != NULL, ERROR_STR_INVALIDXML);
	parserCtxt = xmlSchemaNewDocParserCtxt (schemaDoc);
	check (parserCtxt != NULL, ERROR_STR_INVALIDXML);
	schema = xmlSchemaParse (parserCtxt);
	check (schema != NULL, ERROR_STR_INVALIDXML);
	validCtxt = xmlSchemaNewValidCtxt (schema);
	check (validCtxt != NULL, ERROR_STR_INVALIDXML);
	check (xmlSchemaValidateDoc (validCtxt, doc) == 0, ERROR_STR_INVALIDXML);
	result = true;
error:
	if (validCtxt != NULL)
		xmlSchemaFreeValidCtxt (validCtxt);
	if (schema != NULL)
		xmlSchemaFree (schema);
	if (parserCtxt != NULL)
		xmlSchemaFreeParserCtxt (parserCtxt);
	if (schemaDoc != NULL)
		xmlFreeDoc (schemaDoc);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return result;
}

bool ValidateXmlFile2 (const char *xmlFileName, const char *schemaBuf, size_t schemaBufLen)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr schemaDoc = NULL;
	xmlSchemaParserCtxtPtr parserCtxt = NULL;
	xmlSchemaPtr schema = NULL;
	xmlSchemaValidCtxtPtr validCtxt = NULL;
	bool result = false;

	check ((xmlFileName != NULL) && (schemaBuf != NULL), ERROR_STR_INVALIDINPUT);
	doc = xmlParseFile (xmlFileName);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	schemaDoc = xmlReadMemory (schemaBuf, schemaBufLen, NULL, "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_HUGE | XML_PARSE_COMPACT);
	check (schemaDoc != NULL, ERROR_STR_INVALIDXML);
	parserCtxt = xmlSchemaNewDocParserCtxt (schemaDoc);
	check (parserCtxt != NULL, ERROR_STR_INVALIDXML);
	schema = xmlSchemaParse (parserCtxt);
	check (schema != NULL, ERROR_STR_INVALIDXML);
	validCtxt = xmlSchemaNewValidCtxt (schema);
	check (validCtxt != NULL, ERROR_STR_INVALIDXML);
	check (xmlSchemaValidateDoc (validCtxt, doc) == 0, ERROR_STR_INVALIDXML);
	result = true;
error:
	if (validCtxt != NULL)
		xmlSchemaFreeValidCtxt (validCtxt);
	if (schema != NULL)
		xmlSchemaFree (schema);
	if (parserCtxt != NULL)
		xmlSchemaFreeParserCtxt (parserCtxt);
	if (schemaDoc != NULL)
		xmlFreeDoc (schemaDoc);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return result;
}

char x2c(char *what)
{
	register char digit = 0;

	digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
	digit *= 16;
	digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
	return(digit);
}

void DecodeURL (char *inputStr)
{
	if (inputStr == NULL)
		return;
	for (char *tempStr = inputStr; *tempStr != '\0'; tempStr++, inputStr++)
	{
		switch (*tempStr)
		{
			case '%':
					{
						if (isxdigit(*(tempStr + 1)) && isxdigit(*(tempStr + 2)))
						{
							*inputStr = x2c(tempStr + 1);
							tempStr += 2;
						}
						else
							*inputStr = *tempStr;
						break;
					}
			case '+':
					{
						*inputStr = ' ';
						break;
					}
			default:
					{
						*inputStr = *tempStr;
					}
		}
	}
	*inputStr = '\0';
}

void LowerStringCase (char *inputStr)
{
	if (inputStr == NULL)
		return;
	while (*inputStr != '\0')
	{
		*inputStr = tolower (*inputStr);
		inputStr++;
	}
}

uint16_t checksum (uint16_t *addr, size_t len)
{
	size_t count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;
	
	if (addr == NULL || len == 0)
		return 0;
	
	while (count > 1)
	{
		sum += *(addr++);
		count -= 2;
	}

	if (count > 0)
	{
		sum += *(uint8_t *) addr;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	answer = ~sum;
	return answer;
}

void FillIPHeader (struct iphdr *ipHdr, uint32_t clientIP, uint32_t serverIP, uint16_t totalLength, uint8_t proto)
{
	uint16_t networkChecksum = 0;
	
	if (ipHdr == NULL)
		return;
	ipHdr->ihl = IP4_HDRLEN / 4;
	ipHdr->id = 0;
	ipHdr->version = 4;
	ipHdr->tos = 0;
	ipHdr->ttl = 64;
	ipHdr->frag_off |= htobe16(IP_DF);
	ipHdr->tot_len = htobe16(totalLength);
	ipHdr->saddr = serverIP;
	ipHdr->daddr = clientIP;
	ipHdr->check = 0;
	ipHdr->protocol = proto;
	networkChecksum = checksum ((uint16_t *) ipHdr, IP4_HDRLEN);
	ipHdr->check = networkChecksum;
}


/*************************************************************************
* Callback для libCURL.                                                  *
*************************************************************************/
static size_t WriteMemoryCallback (void *contents, size_t size, size_t nmemb, void *userp)
{
	char *tempBuffer = NULL;
	size_t realSize = size * nmemb;

	check (contents != NULL && userp != NULL, ERROR_STR_INVALIDINPUT);
	TMemoryStruct *mem = (TMemoryStruct *)userp;
	tempBuffer = realloc (mem->memory, mem->size + realSize);
	check_mem (tempBuffer);
	mem->memory = tempBuffer;
	memcpy (&(((unsigned char *)mem->memory)[mem->size]), contents, realSize);
	mem->size += realSize;
	return realSize;
error:
	return 0;
}


/*************************************************************************
* Взаимодействие с HTTP сервером.                                        *
*************************************************************************/
void *SendHTTPPost (const char *url, const void *payload, char *httpHeaders[], size_t httpHeadersCount, size_t inputLength, size_t *outputLength)
{
	
	CURL *curlHandle = NULL;
	CURLcode curlResult = 0;
	long httpCode = 0;
	char *httpUserAgent = "libcurl-agent/1.0";

	TMemoryStruct buffer = {.memory = NULL, .size = 0};
	struct curl_slist *headerList = NULL;
	
	check (url != NULL && outputLength != NULL && inputLength > 0, ERROR_STR_INVALIDINPUT);
	buffer.memory = malloc (1);
	check_mem (buffer.memory);
	buffer.size = 0;
	curlHandle = curl_easy_init ();
	check (curlHandle != NULL, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_URL, url);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_WRITEDATA, (void *)&buffer);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	if (httpHeaders != NULL)
	{
		for (size_t i = 0; i < httpHeadersCount; i++)
		{
			headerList = curl_slist_append (headerList, httpHeaders[i]);
			check (headerList != NULL, ERROR_STR_LIBCURL, "curl_slist_append");
		}
	}
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_USERAGENT, httpUserAgent);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_HTTPHEADER, headerList);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	if (payload != NULL)
	{
		curlResult = curl_easy_setopt (curlHandle, CURLOPT_POSTFIELDS, payload);
		check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
		curlResult = curl_easy_setopt (curlHandle, CURLOPT_POSTFIELDSIZE, inputLength);
		check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	}
	curlResult = curl_easy_perform (curlHandle);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_getinfo (curlHandle, CURLINFO_RESPONSE_CODE, &httpCode);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	check ((httpCode == 200), ERROR_STR_INVALIDHTTP, httpCode);
	curl_slist_free_all (headerList);
	curl_easy_cleanup (curlHandle);
	*outputLength = buffer.size;
	return buffer.memory;
error:
	if (headerList != NULL)
		curl_slist_free_all (headerList);
	if (buffer.memory != NULL)
		free (buffer.memory);
	if (curlHandle != NULL)
		curl_easy_cleanup (curlHandle);
	return NULL;
}


/*************************************************************************
* Преобразование строки в формате DNS в формат ASCIIZ строки.            *
* [3] w w w [7] e x a m p l e [3] c o m [0] ==> .www.example.com[0]      *
*************************************************************************/
bool DNSNotation2String (uint8_t *str)
{
	if (str == NULL)
		return false;
	uint8_t len = *str;
	size_t fullLen = strlen ((char *)str);
	while (*str != 0)
	{
		if (len > 63 || len > fullLen)
			return false;
		*str = '.';
		str += len + 1;
		len = *str;
	}
	return true;
}

uint8_t *String2DNSNotation (char *str)
{
	if (str == NULL)
		return NULL;
	size_t fullLen = strlen (str);
	uint8_t  *result = calloc (fullLen + 2, 1);
	if (result == NULL)
		return NULL;
	if (*str == '.')
		str++;
	uint8_t *dotPosition = result;
	uint8_t *outputPosition = result + 1;
	uint8_t len = 0;
	while (*str != 0)
	{
		if (*str == '.')
		{
			*dotPosition = len;
			dotPosition = outputPosition;
			len = 0;
		}
		else
		{
			*outputPosition = tolower(*str);
			len++;
		}
		str++;
		outputPosition++;
	}
	*dotPosition = len;
	return result;
}