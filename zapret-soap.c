/*************************************************************************
* Модуль получения выгрузки реестра запрещенных сайтов с                 *
*                                   SOAP-сервера РосКомНадзора.          *
*************************************************************************/


/**************************************************************************************************
	Communication architecture

start:
	SOAP:getLastDumpDateEx 														==> vigruzki.rkn.orene.ru
	SOAP:getLastDumpDateExResponse (&new_updateTime, &new_updateTimeUrgently)	<== vigruzki.rkn.orene.ru
	if (new_updateTime != updateTime) || (new_updateTimeUrgently != updateTimeUrgently)
	{
		SOAP:sendRequest (&operatorXml, &operatorXmlSignature)	==> vigruzki.rkn.orene.ru
		SOAP:sendRequestResponse (&result, &requestCode)			<== vigruzki.rkn.orene.ru
		do
		{
			SOAP:getResult (requestCode)							==> vigruzki.rkn.orene.ru
			SOAP:getResultResponse (&result, &registerZipArchive)	<== vigruzki.rkn.orene.ru
		} while (result != true);
	}
	updateTime = new_updateTime
	updateTimeUrgently = new_updateTimeUrgently
	sleep (context->blacklistCooldownNegative);
	goto start;
	
	
	
	
	soapState - Machine state.
	
	
	
	
**************************************************************************************************/

#include <libxml/parser.h>
#include <libxml/tree.h>
#include "zapret-checker.h"


/*************************************************************************
* Шаблон SOAP службы для libCURL.                                        *
*************************************************************************/
#define SOAP_SERVICE_TEMPLATE "http://%s/services/OperatorRequest/"
#define SOAP_ACTION_TEMPLATE "SOAPAction: \"" SOAP_SERVICE_TEMPLATE "%s\""

/*************************************************************************
* Перечисление SOAP методов.                                             *
*************************************************************************/
enum SoapMethodTypes 
{
	SOAP_METHOD_getLastDumpDateEx,
	SOAP_METHOD_sendRequest,
	SOAP_METHOD_getResult,
	SOAP_METHOD_getLastDumpDateExResponse,
	SOAP_METHOD_sendRequestResponse,
	SOAP_METHOD_getResultResponse,
	SOAP_METHOD_getResultSocResources,
	SOAP_METHOD_getResultSocResourcesResponse
};

const char * const soapMethods[] = {[SOAP_METHOD_getLastDumpDateEx]         = "getLastDumpDateEx",
									[SOAP_METHOD_sendRequest]               = "sendRequest",
									[SOAP_METHOD_getResult]                 = "getResult",
									[SOAP_METHOD_getLastDumpDateExResponse] = "getLastDumpDateExResponse",
									[SOAP_METHOD_sendRequestResponse]       = "sendRequestResponse",
									[SOAP_METHOD_getResultResponse]         = "getResultResponse",
									[SOAP_METHOD_getResultSocResources]         = "getResultSocResources",
									[SOAP_METHOD_getResultSocResourcesResponse] = "getResultSocResourcesResponse"
									};

#define GET_RESULT_WAITING_COUNT	          50

#define OPERATOR_TIME_FORMAT		"%Y-%m-%dT%T.000%z"

/*************************************************************************
* Генерирует plain-text дамп запроса оператора к SOAP серверу.           *
* Параметр requestTime обновляется в соотвествии с текущей датой.        *
*************************************************************************/
xmlChar *GenerateRequestXml (xmlDocPtr requestXmlDoc, size_t *outputLength)
{
	xmlNodePtr rootNode = NULL;
	xmlChar *result = NULL;
	char *requestTime = NULL;

	check (requestXmlDoc != NULL && outputLength != NULL, ERROR_STR_INVALIDINPUT);
	requestTime = GetDateTime (OPERATOR_TIME_FORMAT);
	check (requestTime != NULL, ERROR_STR_INVALIDSTRING);
	rootNode = xmlDocGetRootElement (requestXmlDoc);
	check (rootNode != NULL, ERROR_STR_INVALIDXML);
	for (rootNode = rootNode->children; rootNode != NULL; rootNode = rootNode->next)
	{
		if (rootNode->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (rootNode->name, BAD_CAST "requestTime"))
		{
			xmlNodeSetContentLen (rootNode, BAD_CAST requestTime, strlen (requestTime));
			break;
		}
	}
	xmlDocDumpMemoryEnc (requestXmlDoc, &result, (int *)outputLength, "windows-1251");
	check (result != NULL, ERROR_STR_INVALIDSTRING);
	free (requestTime);
	return result;
error:
	if (requestTime != NULL)
		free (requestTime);
	if (result != NULL)
		xmlFree (result);
	return NULL;
}


/*************************************************************************
* Обработка SOAP ответа на метод getLastDumpDateEx.                      *
*************************************************************************/
bool GetLastDumpDateResponse (TSOAPContext *context, const char *soapXml, size_t inputLength)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlChar *nodeVal = NULL;
	char *updateTime = NULL, *updateTimeUrgently = NULL;
	bool exitCode = false;

	check (soapXml != NULL && context != NULL && inputLength > 0, ERROR_STR_INVALIDINPUT);
	doc = xmlReadMemory (soapXml, inputLength, NULL, "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_HUGE | XML_PARSE_COMPACT);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	node = xmlDocGetRootElement (doc);
	check (node != NULL, ERROR_STR_INVALIDXML);
	check (xmlStrcmp (node->name, BAD_CAST "Envelope") == 0, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "Body"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "getLastDumpDateExResponse"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (updateTime == NULL && !xmlStrcmp (node->name, BAD_CAST "lastDumpDate"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			updateTime = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (updateTime != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (updateTimeUrgently == NULL && !xmlStrcmp (node->name, BAD_CAST "lastDumpDateUrgently"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			updateTimeUrgently = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (updateTimeUrgently != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->lastDumpDateSocResources == NULL && !xmlStrcmp (node->name, BAD_CAST "lastDumpDateSocResources"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->lastDumpDateSocResources  = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->lastDumpDateSocResources  != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->dumpFormatVersion == NULL && !xmlStrcmp (node->name, BAD_CAST "dumpFormatVersion"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->dumpFormatVersion = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->dumpFormatVersion != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->dumpFormatVersionSocResources == NULL && !xmlStrcmp (node->name, BAD_CAST "dumpFormatVersionSocResources"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->dumpFormatVersionSocResources = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->dumpFormatVersionSocResources != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->docVersion == NULL && !xmlStrcmp (node->name, BAD_CAST "docVersion"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->docVersion = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->docVersion != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->webServiceVersion == NULL && !xmlStrcmp (node->name, BAD_CAST "webServiceVersion"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->webServiceVersion = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->webServiceVersion != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
		}
	}
	check (updateTime != NULL && updateTimeUrgently != NULL && context->dumpFormatVersion != NULL && context->docVersion != NULL && context->webServiceVersion != NULL, ERROR_STR_INVALIDXML);
	if (context->lastDumpDate != NULL)
	{
		exitCode = (strcmp (updateTime, context->lastDumpDate) != 0);
		free (context->lastDumpDate);
	}
	else
		exitCode = true;
	if (context->lastDumpDateUrgently != NULL)
	{
		exitCode = exitCode || (strcmp (updateTimeUrgently, context->lastDumpDateUrgently) != 0);
		free (context->lastDumpDateUrgently);
	}
	else
		exitCode = true;
	context->lastDumpDate = updateTime;
	updateTime = NULL;
	context->lastDumpDateUrgently = updateTimeUrgently;
	updateTimeUrgently = NULL;
error:
	if (updateTime != NULL)
		free (updateTime);
	if (updateTimeUrgently != NULL)
		free (updateTimeUrgently);
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return exitCode;
}


/*************************************************************************
* Обработка SOAP ответа на метод SendRequest.                            *
*************************************************************************/
bool SendRequestResponse (TSOAPContext *context, const char *soapXml, size_t inputLength)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlChar *nodeVal = NULL;
	bool exitCode = false;

	check (soapXml != NULL && context != NULL && inputLength > 0, ERROR_STR_INVALIDINPUT);
	if (context->requestComment != NULL)
	{
		free (context->requestComment);
		context->requestComment = NULL;
	}
	if (context->requestCode != NULL)
	{
		free (context->requestCode);
		context->requestCode = NULL;
	}
	doc = xmlReadMemory (soapXml, inputLength, NULL, "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_HUGE | XML_PARSE_COMPACT);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	node = xmlDocGetRootElement (doc);
	check (node != NULL, ERROR_STR_INVALIDXML);
	check (xmlStrcmp (node->name, BAD_CAST "Envelope") == 0, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "Body"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "sendRequestResponse"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (context->requestResult == NULL && !xmlStrcmp (node->name, BAD_CAST "result"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->requestResult = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->requestResult != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->requestCode == NULL && !xmlStrcmp (node->name, BAD_CAST "code"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->requestCode = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->requestCode != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->requestComment == NULL && !xmlStrcmp (node->name, BAD_CAST "resultComment"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->requestComment = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->requestComment != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
		}
	}
	check (context->requestResult != NULL && context->requestCode != NULL && context->requestComment != NULL, ERROR_STR_INVALIDXML);
	exitCode = true;
error:
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return exitCode;
}


/*************************************************************************
* Обработка SOAP ответа на метод GetResult.                              *
*************************************************************************/
bool GetResultResponse (TSOAPContext *context, const char *soapXml, size_t inputLength)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlChar *nodeVal = NULL;
	bool exitCode = false;

	check (soapXml != NULL && context != NULL && inputLength > 0, ERROR_STR_INVALIDINPUT);
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
	if (context->registerZipArchive != NULL)
	{
		free (context->registerZipArchive);
		context->registerZipArchive = NULL;
	}
	doc = xmlReadMemory (soapXml, inputLength, NULL, "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_HUGE | XML_PARSE_COMPACT);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	node = xmlDocGetRootElement (doc);
	check (node != NULL, ERROR_STR_INVALIDXML);
	check (xmlStrcmp (node->name, BAD_CAST "Envelope") == 0, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "Body"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "getResultResponse"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (context->resultResult == NULL && !xmlStrcmp (node->name, BAD_CAST "result"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->resultResult = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->resultResult != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->registerZipArchive == NULL && !xmlStrcmp (node->name, BAD_CAST "registerZipArchive"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->registerZipArchive = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->registerZipArchive != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->resultComment == NULL && !xmlStrcmp (node->name, BAD_CAST "resultComment"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			if (nodeVal != NULL){
				context->resultComment = strdup(TrimWhiteSpaces ((char *)nodeVal));
				check (context->resultComment != NULL, ERROR_STR_INVALIDSTRING);
				xmlFree (nodeVal);
				nodeVal = NULL;
			}
			continue;
		}
		if (!xmlStrcmp (node->name, BAD_CAST "resultCode"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->resultCode = atoi ((char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		if (context->operatorName == NULL && !xmlStrcmp (node->name, BAD_CAST "operatorName"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			if (nodeVal != NULL) {
				context->operatorName = strdup(TrimWhiteSpaces ((char *)nodeVal));
				check (context->operatorName != NULL, ERROR_STR_INVALIDSTRING);
				xmlFree (nodeVal);
				nodeVal = NULL;
			}
			continue;
		}
		if (context->operatorINN == NULL && !xmlStrcmp (node->name, BAD_CAST "inn"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			if (nodeVal != NULL){
				context->operatorINN = strdup(TrimWhiteSpaces ((char *)nodeVal));
				check (context->operatorINN != NULL, ERROR_STR_INVALIDSTRING);
				xmlFree (nodeVal);
				nodeVal = NULL;
			}
		}
	}
	check ((context->resultResult != NULL), ERROR_STR_INVALIDXML);
	exitCode = true;
error:
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return exitCode;
}

/*************************************************************************
* Обработка SOAP ответа на метод GetResultSocResources.                  *
*************************************************************************/
bool GetResultSocResourcesResponse (TSOAPContext *context, const char *soapXml, size_t inputLength)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlChar *nodeVal = NULL;
	bool exitCode = false;

	check (soapXml != NULL && context != NULL && inputLength > 0, ERROR_STR_INVALIDINPUT);

	if (context->socialZipArchive != NULL)
	{
		free (context->socialZipArchive);
		context->socialZipArchive = NULL;
	}
	doc = xmlReadMemory (soapXml, inputLength, NULL, "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_NONET | XML_PARSE_HUGE | XML_PARSE_COMPACT);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	node = xmlDocGetRootElement (doc);
	check (node != NULL, ERROR_STR_INVALIDXML);
	check (xmlStrcmp (node->name, BAD_CAST "Envelope") == 0, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "Body"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (!xmlStrcmp (node->name, BAD_CAST "getResultResponse"))
			break;
	}
	check (node != NULL, ERROR_STR_INVALIDXML);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (context->socialZipArchive == NULL && !xmlStrcmp (node->name, BAD_CAST "registerZipArchive"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->socialZipArchive = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->socialZipArchive != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
	}
	check ((context->socialZipArchive != NULL), ERROR_STR_INVALIDXML);
	exitCode = true;
error:
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return exitCode;
}


/*************************************************************************
* Генерация SOAP запросов, результат в виде plain-text дампа.            *
*************************************************************************/
xmlChar *GenerateSOAPMessage (TSOAPContext *context, xmlDocPtr requestXmlDoc, const enum SoapMethodTypes method, size_t *outputLength)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr rootNode = NULL, chldNode = NULL;
	xmlNsPtr soapNs = NULL, tnsNs = NULL, xsiNs = NULL, xsdNs = NULL, wsdlNs = NULL, soapencNs = NULL;
	xmlChar *result = NULL, *requestXml = NULL;
	char *requestXmlBase64 = NULL;
	char *signature = NULL;

	check (context != NULL && outputLength != NULL, ERROR_STR_INVALIDINPUT);
	doc = xmlNewDoc (BAD_CAST "1.0");
	check (doc != NULL, ERROR_STR_INVALIDXML);
	rootNode = xmlNewNode (NULL, BAD_CAST "Envelope");
	check (rootNode != NULL, ERROR_STR_INVALIDXML);
	xmlDocSetRootElement (doc, rootNode);
	soapNs = xmlNewNs (rootNode, BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/", BAD_CAST "soap");
	check (soapNs != NULL, ERROR_STR_INVALIDXML);
	xsdNs = xmlNewNs (rootNode, BAD_CAST "http://www.w3.org/2001/XMLSchema", BAD_CAST "xsd");
	check (xsdNs != NULL, ERROR_STR_INVALIDXML);
	wsdlNs = xmlNewNs (rootNode, BAD_CAST "http://schemas.xmlsoap.org/wsdl/", BAD_CAST "wsdl");
	check (wsdlNs != NULL, ERROR_STR_INVALIDXML);
	soapencNs = xmlNewNs (rootNode, BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/", BAD_CAST "soapenc");
	check (soapencNs != NULL, ERROR_STR_INVALIDXML);
	tnsNs = xmlNewNs (rootNode, BAD_CAST "http://vigruzki.rkn.gov.ru/OperatorRequest/", BAD_CAST "tns");
	check (tnsNs != NULL, ERROR_STR_INVALIDXML);
	check (xmlNewNsProp (rootNode, soapNs, BAD_CAST "encodingStyle", BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/") != NULL, ERROR_STR_INVALIDXML);
	xsiNs = xmlNewNs (rootNode, BAD_CAST "http://www.w3.org/2001/XMLSchema-instance", BAD_CAST "xsi");
	check (xsiNs != NULL, ERROR_STR_INVALIDXML);
	xmlSetNs (rootNode, soapNs);
	rootNode = xmlNewChild (rootNode, soapNs, BAD_CAST "Body", NULL );
	check (rootNode != NULL, ERROR_STR_INVALIDXML);
	rootNode = xmlNewChild (rootNode, tnsNs, BAD_CAST soapMethods[method], NULL );
	check (rootNode != NULL, ERROR_STR_INVALIDXML);
	
	if (method == SOAP_METHOD_getLastDumpDateEx)
	{
		check (xmlNewNsProp (rootNode, xsiNs, BAD_CAST "nil", BAD_CAST "true") != NULL, ERROR_STR_INVALIDXML);
	}
	else if (method == SOAP_METHOD_sendRequest)
	{
		size_t signatureLen = 0;
		size_t requestLen = 0;
		check (requestXmlDoc != NULL, ERROR_STR_INVALIDINPUT);
		check (context->privateKeyId != NULL && context->privateKeyPassword != NULL, ERROR_STR_INVALIDINPUT);
		chldNode = xmlNewChild (rootNode, NULL, BAD_CAST "requestFile", NULL );
		check (chldNode != NULL, ERROR_STR_INVALIDXML);
		check (xmlNewNsProp (chldNode, xsiNs, BAD_CAST "type", BAD_CAST "xsd:base64Binary") != NULL, ERROR_STR_INVALIDXML);
		requestXml = GenerateRequestXml (requestXmlDoc, &requestLen);
		check (requestXml != NULL, ERROR_STR_INVALIDXML);
		signature = SigningPerform ((char *)requestXml, requestLen, &signatureLen, (uint8_t *)context->privateKeyPassword, strlen(context->privateKeyPassword), (uint8_t *)context->privateKeyId, strlen(context->privateKeyId));
		check (signature != NULL, ERROR_STR_INVALIDSIGNATURE);
		requestXmlBase64 = Base64Encode ((char *)requestXml, requestLen, &requestLen);
		check (requestXmlBase64 != NULL, ERROR_STR_INVALIDBASE64);
		xmlNodeSetContentLen (chldNode, BAD_CAST requestXmlBase64, requestLen);
		free (requestXmlBase64);
		requestXmlBase64 = NULL;
		xmlFree (requestXml);
		requestXml = NULL;
		chldNode = xmlNewChild (rootNode, NULL, BAD_CAST "signatureFile", NULL );
		check (chldNode != NULL, ERROR_STR_INVALIDXML);
		check (xmlNewNsProp (chldNode, xsiNs, BAD_CAST "type", BAD_CAST "xsd:base64Binary") != NULL, ERROR_STR_INVALIDXML);
		xmlNodeSetContentLen (chldNode, BAD_CAST signature, signatureLen);
		free (signature);
		signature = NULL;
		chldNode = xmlNewChild (rootNode, NULL, BAD_CAST "dumpFormatVersion", NULL );
		check (chldNode != NULL, ERROR_STR_INVALIDXML);
		check (xmlNewNsProp (chldNode, xsiNs, BAD_CAST "type", BAD_CAST "xsd:string") != NULL, ERROR_STR_INVALIDXML);
		xmlNodeSetContent (chldNode, BAD_CAST context->dumpFormatVersion);
	}
	else if (method == SOAP_METHOD_getResult || method == SOAP_METHOD_getResultSocResources)
	{
		check (context->requestCode != NULL, ERROR_STR_INVALIDINPUT);
		rootNode = xmlNewChild (rootNode, NULL, BAD_CAST "code", NULL );
		check (rootNode != NULL, ERROR_STR_INVALIDXML);
		check (xmlNewNsProp (rootNode, xsiNs, BAD_CAST "type", BAD_CAST "xsd:string") != NULL, ERROR_STR_INVALIDXML);
		xmlNodeSetContent (rootNode, BAD_CAST context->requestCode);
	}
	
	xmlDocDumpMemoryEnc (doc, &result, (int *)outputLength, "UTF-8");
	check (result != NULL, ERROR_STR_INVALIDXML);
	xmlFreeDoc (doc);
	return result;
error:
	if (signature != NULL)
		free (signature);
	if (requestXmlBase64 != NULL)
		free (requestXmlBase64);
	if (requestXml != NULL)
		xmlFree (requestXml);
	if (result != NULL)
		xmlFree (result);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return NULL;
}


/*************************************************************************
* Создание SOAPAction строки SOAP методов.                               *
*************************************************************************/
char *GenerateSoapActionString (char *blacklistHost, const enum SoapMethodTypes method)
{
	char *soapAction = NULL;
	
	soapAction = calloc (strlen (blacklistHost) + strlen (SOAP_ACTION_TEMPLATE) + strlen (soapMethods[method]) + 1, 1);
	check_mem (soapAction);
	check (sprintf (soapAction, SOAP_ACTION_TEMPLATE, blacklistHost, soapMethods[method]) > 0, ERROR_STR_INVALIDSTRING);
	return soapAction;
error:
	if (soapAction != NULL)
		free (soapAction);
	return NULL;
}

/*************************************************************************
* Получение выгрузки реестра запрещенных сайтов с SOAP сервера.          *
*************************************************************************/
void PerformSOAPCommunication (TZapretContext *context)
{
	char *response = NULL;
	int repeatCount = 0;
	char *soapService = NULL;
	char *soapAction = NULL;
	xmlChar *request = NULL;
	size_t resultSize = 0;

	#define HTTP_HEADER_COUNT 5
	char *httpHeaders[HTTP_HEADER_COUNT] = {"Accept: application/soap; text/xml",
											 "Content-Type: text/xml; charset=utf-8",
											 "Connection: close",
											 "Expect:",
											 NULL};
	
	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/	
	check (context != NULL, ERROR_STR_INVALIDINPUT);
	check (context->blacklistHost != NULL && context->requestXmlDoc != NULL, ERROR_STR_INVALIDINPUT);
	check (context->privateKeyId != NULL && context->privateKeyPassword != NULL, ERROR_STR_INVALIDINPUT);
	
	/*************************************************************************
	* Выделяем память под контекст SOAP.                                     *
	*************************************************************************/
	if (context->soapContext == NULL)
		context->soapContext = calloc (1, sizeof (TSOAPContext));
	check_mem(context->soapContext);
	context->soapContext->soapResult = false;
	context->soapContext->resultCode = 0;
	context->soapContext->privateKeyId = context->privateKeyId;
	context->soapContext->privateKeyPassword = context->privateKeyPassword;
	
	/*************************************************************************
	* Составляем URL строку HTTP подключения к SOAP серверу.                 *
	*************************************************************************/
	soapService = calloc (strlen (context->blacklistHost) + strlen (SOAP_SERVICE_TEMPLATE) + 1, 1);
	check_mem (soapService);
	check (sprintf (soapService, SOAP_SERVICE_TEMPLATE, context->blacklistHost) > 0, ERROR_STR_INVALIDSTRING);
	
	/*************************************************************************
	* Вызываем SOAP метод getLastDumpDateEx, в ответ                         *
	* получаем getLastDumpDateExResponse                                     *
	*************************************************************************/
	log_info ("SOAP: getLastDumpDateEx");
	request = GenerateSOAPMessage (context->soapContext, NULL, SOAP_METHOD_getLastDumpDateEx, &resultSize);
	check (request != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getLastDumpDateEx]);
	httpHeaders[HTTP_HEADER_COUNT - 1] = GenerateSoapActionString (context->blacklistHost, SOAP_METHOD_getLastDumpDateEx);
	check (httpHeaders[HTTP_HEADER_COUNT - 1] != NULL, ERROR_STR_INVALIDSTRING);
	response = SendHTTPPost (soapService, (char *)request, httpHeaders, HTTP_HEADER_COUNT, resultSize, &resultSize);
	check (response != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getLastDumpDateExResponse]);
	free (httpHeaders[HTTP_HEADER_COUNT - 1]);
	httpHeaders[HTTP_HEADER_COUNT - 1] = NULL;
	xmlFree (request);
	request = NULL;
	
	/*************************************************************************
	* Обрабатываем ответ getLastDumpDateExResponse, если обновления дампа    *
	* реестра запрещенных сайтов не требуется, выходим.                      *
	*************************************************************************/
	log_info ("SOAP: getLastDumpDateExResponse");	
	if (GetLastDumpDateResponse (context->soapContext, response, resultSize) != true)
	{
		check (context->soapContext->lastDumpDate != NULL && context->soapContext->lastDumpDateUrgently != NULL && context->soapContext->docVersion != NULL && context->soapContext->dumpFormatVersion != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getLastDumpDateExResponse]);
		context->soapContext->soapResult = true;
		free (response);
		return;
	}
	free (response);
	response = NULL;	
	
	/*************************************************************************
	* Вызываем SOAP метод sendRequest, в ответ                               *
	* получаем sendRequestResponse                                           *
	*************************************************************************/
	log_info ("SOAP: sendRequest");
	request = GenerateSOAPMessage (context->soapContext, context->requestXmlDoc, SOAP_METHOD_sendRequest, &resultSize);
	check (request != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_sendRequest]);
	httpHeaders[HTTP_HEADER_COUNT - 1] = GenerateSoapActionString (context->blacklistHost, SOAP_METHOD_sendRequest);
	check (httpHeaders[HTTP_HEADER_COUNT - 1] != NULL, ERROR_STR_INVALIDSTRING);
	response = SendHTTPPost (soapService, (char *)request, httpHeaders, HTTP_HEADER_COUNT, resultSize, &resultSize);
	check (response != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_sendRequestResponse]);
	free (httpHeaders[HTTP_HEADER_COUNT - 1]);
	httpHeaders[HTTP_HEADER_COUNT - 1] = NULL;
	xmlFree (request);
	request = NULL;
	
	/*************************************************************************
	* Обрабатываем ответ sendRequestResponse.                                *
	*************************************************************************/
	log_info ("SOAP: sendRequestResponse");
	check (SendRequestResponse (context->soapContext, response, resultSize) == true, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_sendRequestResponse]);
	free (response);
	response = NULL;

	/*************************************************************************
	* В цикле вызываем SOAP метод getResult, в ответ                         *
	* получаем getResultResponse, пока не получим дамп реестра запрещенных   *
	* сайтов или пока не истечет количество попыток.                         *
	*************************************************************************/		
	while ((repeatCount < GET_RESULT_WAITING_COUNT) && (context->soapContext->resultCode == 0) && (flagMatrixShutdown == 0) && (flagMatrixReconfigure == 0))
	{
		sleep (context->blacklistCooldownNegative);
		log_info ("SOAP: getResult");
		request = GenerateSOAPMessage (context->soapContext, NULL, SOAP_METHOD_getResult, &resultSize);
		check (request != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResult]);
		httpHeaders[HTTP_HEADER_COUNT - 1] = GenerateSoapActionString (context->blacklistHost, SOAP_METHOD_getResult);
		check (httpHeaders[HTTP_HEADER_COUNT - 1] != NULL, ERROR_STR_INVALIDSTRING);
		response = SendHTTPPost (soapService, (char *)request, httpHeaders, HTTP_HEADER_COUNT, resultSize, &resultSize);
		check (response != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResultResponse]);
		free (httpHeaders[HTTP_HEADER_COUNT - 1]);
		httpHeaders[HTTP_HEADER_COUNT - 1] = NULL;
		xmlFree (request);
		request = NULL;		
		
		
		/*************************************************************************
		* Обрабатываем ответ getResultResponse.                                  *
		*************************************************************************/
		log_info ("SOAP: getResultResponse");
		check (GetResultResponse (context->soapContext, response, resultSize) == true, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResultResponse]);
		free (response);
		response = NULL;
		
		repeatCount++;
	} 
	check (context->soapContext->resultCode == 1, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResultResponse]);
	context->soapContext->soapResult = true;

	log_info ("SOAP: getResultSocResources");
	request = GenerateSOAPMessage (context->soapContext, NULL, SOAP_METHOD_getResultSocResources, &resultSize);
	check (request != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResultSocResources]);
	httpHeaders[HTTP_HEADER_COUNT - 1] = GenerateSoapActionString (context->blacklistHost, SOAP_METHOD_getResultSocResources);
	check (httpHeaders[HTTP_HEADER_COUNT - 1] != NULL, ERROR_STR_INVALIDSTRING);
	response = SendHTTPPost (soapService, (char *)request, httpHeaders, HTTP_HEADER_COUNT, resultSize, &resultSize);
	check (response != NULL, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResultSocResourcesResponse]);
	log_info ("SOAP: getResultSocResourcesResponse");
	check (GetResultSocResourcesResponse(context->soapContext, response, resultSize) == true, ERROR_STR_SOAP, soapMethods[SOAP_METHOD_getResultSocResourcesResponse]);

error:
	if (response != NULL)
		free (response);
	if (soapService != NULL)
		free (soapService);
	if (soapAction != NULL)
		free (soapAction);
	if (request != NULL)
		xmlFree (request);
	if (httpHeaders[HTTP_HEADER_COUNT - 1] != NULL)
	{
		free (httpHeaders[HTTP_HEADER_COUNT - 1]);
		httpHeaders[HTTP_HEADER_COUNT - 1] = NULL;
	}
	return;
}
