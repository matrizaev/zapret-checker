/*************************************************************************
* Модуль чтения конфигурации.                                            *
*************************************************************************/

#include "allheaders.h"
#include "zapret-checker.h"
#include "zapret-configuration.h"

/*************************************************************************
* Путь к файлу конфигурации.                                             *
*************************************************************************/
#define DAEMON_CONFIG_PATH			"/etc/zapret-checker"
#define DAEMON_CONFIG_FILE			"zapret-checker.xml"


/*************************************************************************
* Шаблон SMTP службы для libCURL.                                        *
*************************************************************************/
#define SMTP_SERVICE_TEMPLATE "smtp://%s/"


/*************************************************************************
* Чтение раздела <redirect> конфигурации.                                *
*************************************************************************/
static bool ReadRedirectConfiguration (xmlNodePtr node, TZapretContext *context)
{
	xmlChar *nodeVal = NULL;
	bool result = false;

	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	check (context != NULL && node != NULL, ERROR_STR_INVALIDINPUT);
	check (!xmlStrcmp (node->name, BAD_CAST "redirect"), ERROR_STR_INVALIDINPUT);
	
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;
		
		/*************************************************************************
		* Считываем параметр host - адрес сервера для DNS и HTTP перенаправления.*
		*************************************************************************/
		if (context->redirectHost == NULL && !xmlStrcmp (node->name, BAD_CAST "host"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->redirectHost = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->redirectHost != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		
		/*************************************************************************
		* Считываем параметр http - номера очередей и колличество потоков        *
		*                                                     фильтрации HTTP.   *
		*************************************************************************/
		if (!xmlStrcmp (node->name, BAD_CAST "http"))
		{
			nodeVal = xmlGetProp (node, BAD_CAST "queue");
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->redirectHTTPQueue = atoi ((const char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = xmlGetProp (node, BAD_CAST "count");
			context->redirectHTTPCount = atoi ((const char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		
		/*************************************************************************
		* Считываем параметр dns - номер очередей и колличество потоков          *
		*                                                     фильтрации DNS.    *
		*************************************************************************/	
		if (!xmlStrcmp (node->name, BAD_CAST "dns"))
		{
			nodeVal = xmlGetProp (node, BAD_CAST "queue");
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->redirectDNSQueue = atoi ((const char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = xmlGetProp (node, BAD_CAST "count");
			context->redirectDNSCount = atoi ((const char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = NULL;			
			continue;
			
		}
		
		/*************************************************************************
		* Считываем параметр ipsetList - имя списка ipset для блокировки по IP.  *
		*************************************************************************/
		if (context->redirectIpsetList == NULL && !xmlStrcmp (node->name, BAD_CAST "ipsetList"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->redirectIpsetList = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->redirectIpsetList != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			
			/*************************************************************************
			* Считываем параметр nsLookup - флаг разрешения DNS-имён в IP-адреса.    *
			*************************************************************************/
			nodeVal = xmlGetProp (node, BAD_CAST "nsLookup");
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			if (!strcasecmp(TrimWhiteSpaces ((char *)nodeVal), "true"))
				context->redirectNSLookup = true;
			else
				context->redirectNSLookup = false;
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		
		/*************************************************************************
		* Считываем параметр iface - интерфейс, через который отправляются       *
		*                                             пакеты перенаправления.    *
		*************************************************************************/
		if (context->redirectIface == NULL && !xmlStrcmp (node->name, BAD_CAST "iface"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->redirectIface = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->redirectIface != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
		}
	}	
	if (context->redirectDNSCount > 0)
	{
		context->dnsThreadsContext = InitNetfilterConfiguration(context->redirectDNSCount, context->redirectIface, context->redirectHost, context->redirectDNSQueue, NETFILTER_TYPE_DNS);
		check_mem(context->dnsThreadsContext);
	}
	if (context->redirectHTTPCount > 0)
	{
		context->httpThreadsContext = InitNetfilterConfiguration(context->redirectHTTPCount, context->redirectIface, context->redirectHost, context->redirectHTTPQueue, NETFILTER_TYPE_HTTP);
		check_mem(context->httpThreadsContext);
	}
	result = true;
error:
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	return result;
}


/*************************************************************************
* Чтение раздела <smtp> конфигурации.                                    *
*************************************************************************/
static bool ReadSMTPConfiguration (xmlNodePtr node, TZapretContext *context)
{
	xmlChar *nodeVal = NULL;
	xmlChar *attachments = NULL;
	bool result = false;
	
	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	check (context != NULL && node != NULL && context->smtpContext == NULL, ERROR_STR_INVALIDINPUT);
	check (!xmlStrcmp (node->name, BAD_CAST "smtp"), ERROR_STR_INVALIDINPUT);
	
	/*************************************************************************
	* Выделяем память для хранения SMTP-контекста.                           *
	*************************************************************************/
	context->smtpContext = calloc (1, sizeof (TSMTPContext));
	check_mem (context->smtpContext);
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;

		/*************************************************************************
		* Считываем параметр host - адрес SMTP-сервера.                          *
		*************************************************************************/
		if (context->smtpContext->smtpHost == NULL && !xmlStrcmp (node->name, BAD_CAST "host"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->smtpContext->smtpHost = calloc (strlen ((char *)nodeVal) + strlen (SMTP_SERVICE_TEMPLATE) + 1, 1);
			check_mem (context->smtpContext->smtpHost);
			check (sprintf (context->smtpContext->smtpHost, SMTP_SERVICE_TEMPLATE, TrimWhiteSpaces ((char *)nodeVal)) > 0, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		
		/*************************************************************************
		* Считываем параметр sender - EMAIL-адрес отправителя.                   *
		*************************************************************************/
		if (context->smtpContext->smtpSender == NULL && !xmlStrcmp (node->name, BAD_CAST "sender"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->smtpContext->smtpSender = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->smtpContext->smtpSender != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		/*************************************************************************
		* Считываем параметры recipient - EMAIL-адреса получателей.              *
		* Аттрибут attachments означает необходимость получать дамп выгрузки.    *
		*************************************************************************/		
		if (!xmlStrcmp (node->name, BAD_CAST "recipient"))
		{
			attachments = xmlGetProp (node, BAD_CAST "attachments");
			check (attachments != NULL, ERROR_STR_INVALIDXML);
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			if (xmlStrcmp (attachments, BAD_CAST "true") == 0)
			{
				check ((context->smtpContext->recipients[0] = curl_slist_append (context->smtpContext->recipients[0], TrimWhiteSpaces ((char *)nodeVal))) != NULL, ERROR_STR_LIBCURL, "curl_slist_append");
			}
			else
			{
				check ((context->smtpContext->recipients[1] = curl_slist_append (context->smtpContext->recipients[1], TrimWhiteSpaces ((char *)nodeVal))) != NULL, ERROR_STR_LIBCURL, "curl_slist_append");
			}
			xmlFree (nodeVal);
			nodeVal = NULL;
			xmlFree (attachments);
			attachments = NULL;
		}
	}
	result = true;
error:
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (attachments != NULL)
		xmlFree (attachments);
	return result;
}


/*************************************************************************
* Чтение раздела <rknBlacklist> конфигурации.                            *
*************************************************************************/
static bool ReadBlacklistConfiguration (xmlNodePtr node, TZapretContext *context)
{
	xmlChar *nodeVal = NULL, *nodeAttr = NULL;
	bool result = false;
	int fd = -1;

	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/	
	check (context != NULL && node != NULL, ERROR_STR_INVALIDINPUT);
	check (!xmlStrcmp (node->name, BAD_CAST "rknBlacklist"), ERROR_STR_INVALIDINPUT);
	
	for (node = node->children; node != NULL; node = node->next)
	{
		if (node->type != XML_ELEMENT_NODE)
			continue;

		/*************************************************************************
		* Считываем параметр host - адрес SOAP-сервера РосКомНадзора.            *
		*************************************************************************/
		if (context->blacklistHost == NULL && !xmlStrcmp (node->name, BAD_CAST "host"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->blacklistHost = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->blacklistHost != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		/*************************************************************************
		* Считываем параметр privateKey - ID закрытого ключа для                 *
		*                                        формирования ЭЦП SOAP-запроса.  *
		*************************************************************************/		
		if (!xmlStrcmp (node->name, BAD_CAST "privateKey"))
		{
			nodeAttr = xmlGetProp (node, BAD_CAST "password");
			check (nodeAttr != NULL, ERROR_STR_INVALIDXML);
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->privateKeyId = strdup((char *)nodeVal);
			context->privateKeyPassword = strdup(TrimWhiteSpaces ((char *)nodeAttr));
			xmlFree (nodeVal);
			nodeVal = NULL;
			xmlFree (nodeAttr);
			nodeAttr = NULL;
			continue;
		}
		
		/*************************************************************************
		* Обработка блока параметров cooldown - время задержки между             *
		*                                       SOAP-запросами.                  *
		*************************************************************************/			
		if (!xmlStrcmp (node->name, BAD_CAST "cooldown"))
		{
			nodeVal = xmlGetProp (node, BAD_CAST "positive");
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->blacklistCooldownPositive = atoi ((const char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = xmlGetProp (node, BAD_CAST "negative");
			context->blacklistCooldownNegative = atoi ((const char *)nodeVal);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		
		/*************************************************************************
		* Обработка параметра timestampFile - метка последнего дампа SOAP.       *
		* Если файла нет, пытаемся создать.                                      *
		*************************************************************************/		
		if (context->timestampFile == NULL && !xmlStrcmp (node->name, BAD_CAST "timestampFile"))
		{
			nodeVal = xmlNodeGetContent (node->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->timestampFile = strdup(TrimWhiteSpaces ((char *)nodeVal));
			if (access(context->timestampFile, F_OK) != 0)
			{
				int fd = open (context->timestampFile, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				check(fd != -1, ERROR_STR_FILEFAIL);
			}
			check (context->timestampFile != NULL, ERROR_STR_INVALIDSTRING);
			xmlFree (nodeVal);
			nodeVal = NULL;
			continue;
		}
		
		/*************************************************************************
		* Обработка блока параметров request - XML-запрос SOAP-взаимодействия.   *
		*************************************************************************/			
		if (!xmlStrcmp (node->name, BAD_CAST "request"))
		{
			xmlNodePtr nodeChld = NULL;
			context->requestXmlDoc = xmlNewDoc (BAD_CAST "1.0");
			check (context->requestXmlDoc != NULL, ERROR_STR_INVALIDXML);
			nodeChld = xmlDocCopyNodeList (context->requestXmlDoc, node);
			check (nodeChld != NULL, ERROR_STR_INVALIDXML);
			xmlDocSetRootElement (context->requestXmlDoc, nodeChld);
		}
	}
	result = true;
error:
	if (fd != -1)
		close (fd);
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (nodeAttr != NULL)
		xmlFree (nodeAttr);
	return result;
}


/*************************************************************************
* Чтение конфигурационного файла.                                        *
* Память под контекст конфигурации должен быть заранее.                  *
*************************************************************************/
bool ReadZapretConfiguration (TZapretContext *context)
{
	xmlDoc	*doc	= NULL;
	xmlNode *docNode = NULL;
	xmlChar *nodeVal = NULL;
	bool result = false;

	/*************************************************************************
	* Проверка возможности считать файл конфигурации.                        *
	*************************************************************************/
	check (context != NULL, ERROR_STR_INVALIDINPUT);
	check (chdir (DAEMON_CONFIG_PATH) == 0, ERROR_STR_FILEFAIL);
	check (access (DAEMON_CONFIG_FILE, R_OK) == 0, ERROR_STR_FILEFAIL);
	check (ValidateXmlFile2 (DAEMON_CONFIG_FILE, configurationScheme, configurationSchemeLen) == true, ERROR_STR_INVALIDXML);

	/*************************************************************************
	* Цикл чтения и обработки узлов xml-файла конфигурации.                  *
	*************************************************************************/
	doc = xmlReadFile (DAEMON_CONFIG_FILE, "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_NONET);
	check (doc != NULL, ERROR_STR_INVALIDXML);
	docNode = xmlDocGetRootElement (doc);
	check (docNode != NULL, ERROR_STR_INVALIDXML);
	for (docNode = docNode->children; docNode != NULL; docNode = docNode->next)
	{
		if (docNode->type != XML_ELEMENT_NODE)
			continue;

		/*************************************************************************
		* Обработка блока параметров redirect - перенаправление HTTP и DNS.      *
		*************************************************************************/
		if (!xmlStrcmp (docNode->name, BAD_CAST "redirect"))
		{
			check (ReadRedirectConfiguration(docNode, context) == true, ERROR_STR_INVALIDXML);
			continue;
		}
		
		/*************************************************************************
		* Обработка блока параметров smtp - оповещение по email о результатах    *
		*                                                 SOAP-взаимодействия.   *
		*************************************************************************/
		if (!xmlStrcmp (docNode->name, BAD_CAST "smtp"))
		{
			check (ReadSMTPConfiguration(docNode, context) == true, ERROR_STR_INVALIDXML);
			continue;
		}
		
		/*************************************************************************
		* Обработка блока параметров rknBlacklist - взаимодействие с             *
		*                                           SOAP-сервером РосКомНадзора. *
		*************************************************************************/
		if (!xmlStrcmp (docNode->name, BAD_CAST "rknBlacklist"))
		{
			check (ReadBlacklistConfiguration(docNode, context) == true, ERROR_STR_INVALIDXML);
			continue;
		}
		
		/*************************************************************************
		* Обработка параметра customBlacklist - пользовательский файл с черным   *
		*                                       списком блокировки WEB-ресуров.  *
		*************************************************************************/
		if (context->customBlacklist == NULL && !xmlStrcmp (docNode->name, BAD_CAST "customBlacklist"))
		{
			nodeVal = xmlNodeGetContent (docNode->xmlChildrenNode);
			check (nodeVal != NULL, ERROR_STR_INVALIDXML);
			context->customBlacklist = strdup(TrimWhiteSpaces ((char *)nodeVal));
			check (context->customBlacklist != NULL, ERROR_STR_INVALIDSTRING);
			if (access(context->customBlacklist, R_OK) != 0)
			{
				free (context->customBlacklist);
				context->customBlacklist = NULL;
				log_info(ERROR_STR_CUSTOMBL);
			}
			xmlFree (nodeVal);
			nodeVal = NULL;
		}
	}
	result = true;
error:
	if (nodeVal != NULL)
		xmlFree (nodeVal);
	if (doc != NULL)
		xmlFreeDoc (doc);
	return result;
}

