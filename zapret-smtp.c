/*************************************************************************
* Модуль взаимодействия с SMTP сервером. Формирование и отправка         *
* информационных сообщений.                                              *
*************************************************************************/

#include <math.h>
#include "zapret-checker.h"

#define SMTP_PAYLOAD_STRING_SUCCESSFUL    "Successful iteration."
#define SMTP_PAYLOAD_STRING_UNSUCCESSFUL  "Unsuccessful iteration."
#define SMTP_PAYLOAD_STRING_UNCHANGED     "Timestamp has not been changed."
#define SMTP_TIME_FORMAT                  "%a, %d %b %Y %T %z"

/*************************************************************************
* Макрос итерирования по хеш-таблице.                                    *
*************************************************************************/
#define CycleHashTable() \
{ \
	while (node == NULL && intIndex < ipHashTable->numEntries) \
	{ \
		node = ipHashTable->lookup[intIndex]; \
		if (node == NULL) \
			intIndex++; \
	} \
	if (node == NULL) \
	{ \
		payloadIndex++; \
		intIndex = 0; \
		data = NULL; \
		continue; \
	} \
}

/*************************************************************************
* Предварительно подготовленный массив строк EMAIL.                      *
*************************************************************************/
static	TMemoryStruct smtpPayloadText[] = 
{
/*0*/	{.memory = "From: <", .size = strlen("From: <")},
/*1*/	{.memory = NULL, .size = 0},
/*2*/	{.memory = ">\r\nTo: <", .size = strlen(">\r\nTo: <")},
/*3*/	{.memory = NULL, .size = 0},
/*4*/	{.memory = ">\r\nSubject: Zapret-checker's periodical notification.\r\nMime-version: 1.0\r\nDate: ", .size = strlen(">\r\nSubject: Zapret-checker's periodical notification.\r\nMime-version: 1.0\r\nDate: ")},
/*5*/	{.memory = NULL, .size = 0},
/*6*/	{.memory = "\r\nContent-Type: multipart/mixed; boundary=frontier\r\n\r\n--frontier\r\nContent-type: text/html; charset=utf-8\r\n\r\n<!DOCTYPE html><html><head><meta charset = \"utf-8\"></head><body><h1>", .size = strlen("\r\nContent-Type: multipart/mixed; boundary=frontier\r\n\r\n--frontier\r\nContent-type: text/html; charset=utf-8\r\n\r\n<!DOCTYPE html><html><head><meta charset = \"utf-8\"></head><body><h1>")},
/*7*/	{.memory = NULL, .size = 0},
/*8*/	{.memory = "</h1><p><a href=\"http://vigruzki.rkn.gov.ru/docs/description_for_operators_actual.pdf\">ISP instructions version: ", .size = strlen("</h1><p><a href=\"http://vigruzki.rkn.gov.ru/docs/description_for_operators_actual.pdf\">ISP instructions version: ")},
/*9*/	{.memory = NULL, .size = 0},
/*10*/	{.memory = "</a></p><p>Request comment: ", .size = strlen("</a></p><p>Request comment: ")},
/*11*/	{.memory = NULL, .size = 0},
/*12*/	{.memory = "</p><p>Result comment: ", .size = strlen("</p><p>Result comment: ")},
/*13*/	{.memory = NULL, .size = 0},
/*14*/	{.memory = "</p><p>Result code: ", .size = strlen("</p><p>Result code: ")},
/*15*/	{.memory = NULL, .size = 0},
/*16*/	{.memory = "</p><p>Operator name: ", .size = strlen("</p><p>Operator name: ")},
/*17*/	{.memory = NULL, .size = 0},
/*18*/	{.memory = "</p><p>Operator INN: ", .size = strlen("</p><p>Operator INN: ")},
/*19*/	{.memory = NULL, .size = 0},
/*20*/	{.memory = "</p><p>Dump format version: ", .size = strlen("</p><p>Dump format version: ")},
/*21*/	{.memory = NULL, .size = 0},
/*22*/	{.memory = "</p><p>Web service version: ", .size = strlen("</p><p>Web service version: ")},
/*23*/	{.memory = NULL, .size = 0},
/*24*/	{.memory = "</p><p>Request code: ", .size = strlen("</p><p>Request code: ")},
/*25*/	{.memory = NULL, .size = 0},
/*26*/	{.memory = "</p><p>Last dump date: ", .size = strlen("</p><p>Last dump date: ")},
/*27*/	{.memory = NULL, .size = 0},
/*28*/	{.memory = "</p><p>Last dump date urgently: ", .size = strlen("</p><p>Last dump date urgently: ")},
/*29*/	{.memory = NULL, .size = 0},
/*30*/	{.memory = "</p><p>Request result: ", .size = strlen("</p><p>Request result: ")},
/*31*/	{.memory = NULL, .size = 0},
/*32*/	{.memory = "</p><p>Response result: ", .size = strlen("</p><p>Response result: ")},
/*33*/	{.memory = NULL, .size = 0},
/*34*/	{.memory = "</p><p>Техническая поддержка: <a href=\"mailto:zapret-support@rkn.gov.ru\">zapret-support@rkn.gov.ru</a></p><body></html>\r\n", .size = strlen("</p><p>Техническая поддержка: <a href=\"mailto:zapret-support@rkn.gov.ru\">zapret-support@rkn.gov.ru</a></p><body></html>\r\n")},
/*35*/	{.memory = "\r\n\r\n--frontier\r\nContent-Type: application/x-zip-compressed; name=\"register.zip\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"register.zip\"\r\n\r\n", .size = strlen("\r\n\r\n--frontier\r\nContent-Type: application/x-zip-compressed; name=\"register.zip\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"register.zip\"\r\n\r\n")},
/*36*/	{.memory = NULL, .size = 0},
/*37*/	{.memory = "\r\n\r\n--frontier--\r\n", .size = strlen("\r\n\r\n--frontier--\r\n")}
};

static const size_t smtpPayloadTextCount = 38;


/*************************************************************************
* libCURL callback для обработки массива строка EMAIL.                   *
*************************************************************************/
static size_t SMTPPayloadCallback (void *ptr, size_t size, size_t nmemb, void *userp)
{
	static struct curl_slist *recipient = NULL;
	static char *data = NULL;
	static size_t len = 0;
	static size_t payloadIndex = 0;
	size_t bufferSize = size * nmemb;
	static char payloadRecipientPattern[256] = ">, <";

	if (ptr == NULL || bufferSize == 0)
		return 0;
	if (data == NULL)
	{
		while (payloadIndex < smtpPayloadTextCount)
		{
			if (payloadIndex == 3)
			{
				if (recipient == NULL)
				{
					if (smtpPayloadText[3].memory != NULL)
						recipient = (struct curl_slist *)smtpPayloadText[3].memory;
					else
					{
						payloadIndex = 0;
						data = NULL;
						len = 0;
						recipient = NULL;
						return 0;
					}
				}
				else
				{
					recipient = recipient->next;
					if (recipient == NULL)
					{
						payloadIndex++;
						continue;
					}
				}
				data = payloadRecipientPattern;
				len = strlen(recipient->data);
				if (len > 250)
					len = 250;
				memcpy (data + 4, recipient->data, len);
				len += 4;
				data[len + 1] = '\0';
				break;
			}
			if ((userp == NULL || smtpPayloadText [36].memory == NULL) && payloadIndex == 35)
				payloadIndex = smtpPayloadTextCount - 1;
			if (smtpPayloadText [payloadIndex].memory != NULL)
			{
				data = smtpPayloadText [payloadIndex].memory;
				len = smtpPayloadText [payloadIndex].size;
				break;
			}
			else
				payloadIndex++;
		}
	}
	if (data != NULL)
	{
		if (len <= bufferSize)
		{
			size_t retLen = len;
			memcpy (ptr, data, len);
			data = NULL;
			len = 0;
			payloadIndex++;
			return retLen;
		}
		else
		{
			memcpy (ptr, data, bufferSize);
			len -= bufferSize;
			data += bufferSize;
			return bufferSize;
		} 
	}
	payloadIndex = 0;
	data = NULL;
	len = 0;
	recipient = NULL;
	return 0;
}


/*************************************************************************
* Обновляем массив строк EMAIL в соотвествии с текущим SOAP контекстом.  *
*************************************************************************/
bool UpdatePayloadText (TSMTPContext *smtpContext, TSOAPContext *soapContext)
{
	bool result = false;
	
	check (smtpContext != NULL && soapContext != NULL, ERROR_STR_INVALIDINPUT);
	smtpPayloadText[1].memory = smtpContext->smtpSender;
	smtpPayloadText[5].memory = GetDateTime (SMTP_TIME_FORMAT);
	check_mem (smtpPayloadText[5].memory);
	if ((soapContext->soapResult == true) && (soapContext->registerZipArchive != NULL))
		smtpPayloadText[7].memory = SMTP_PAYLOAD_STRING_SUCCESSFUL;
	else if ((soapContext->soapResult == true) && (soapContext->registerZipArchive == NULL))
		smtpPayloadText[7].memory = SMTP_PAYLOAD_STRING_UNCHANGED;
	else
		smtpPayloadText[7].memory = SMTP_PAYLOAD_STRING_UNSUCCESSFUL;

	smtpPayloadText[9].memory = soapContext->docVersion;
	smtpPayloadText[11].memory = soapContext->requestComment;
	smtpPayloadText[13].memory = soapContext->resultComment;
	smtpPayloadText[15].memory = calloc ((size_t)log10 (abs (soapContext->resultCode) + 1) + 3, 1);
	check_mem (smtpPayloadText[15].memory);
	check (sprintf (smtpPayloadText[15].memory, "%d", soapContext->resultCode) > 0, ERROR_STR_INVALIDSTRING);
	smtpPayloadText[17].memory = soapContext->operatorName;
	smtpPayloadText[19].memory = soapContext->operatorINN;
	smtpPayloadText[21].memory = soapContext->dumpFormatVersion;
	smtpPayloadText[23].memory = soapContext->webServiceVersion;
	smtpPayloadText[25].memory = soapContext->requestCode;
	smtpPayloadText[27].memory = soapContext->lastDumpDate;
	smtpPayloadText[29].memory = soapContext->lastDumpDateUrgently;
	smtpPayloadText[31].memory = soapContext->requestResult;
	smtpPayloadText[33].memory = soapContext->resultResult;
	smtpPayloadText[36].memory = soapContext->registerZipArchive;
	
	if (smtpPayloadText[1].memory != NULL)
		smtpPayloadText[1].size =  strlen(smtpPayloadText[1].memory);
	else
		smtpPayloadText[1].size = 0;
	
	for (size_t i = 5; i <= 33; i+=2)
	{
		if (smtpPayloadText[i].memory != NULL)
			smtpPayloadText[i].size =  strlen(smtpPayloadText[i].memory);
		else
			smtpPayloadText[i].size = 0;
	}
	
	if (smtpPayloadText[36].memory != NULL)
		smtpPayloadText[36].size =  strlen(smtpPayloadText[36].memory);
	else
		smtpPayloadText[36].size = 0;
	
	result = true;
error:
	return result;
}

/*************************************************************************
* Формируем и посылаем информационны сообщения EMAIL.                    *
*************************************************************************/
void SendSMTPMessage (TSMTPContext *smtpContext, TSOAPContext *soapContext)
{
	CURL *curlHandle = NULL;
	CURLcode curlResult = 0;

	if (smtpContext == NULL)
		return;
	check (soapContext != NULL && smtpContext->smtpHost != NULL && smtpContext->smtpSender != NULL, ERROR_STR_INVALIDINPUT);
	check ((curlHandle = curl_easy_init ()) != NULL, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_URL, smtpContext->smtpHost);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_MAIL_FROM, smtpContext->smtpSender);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_READFUNCTION, SMTPPayloadCallback);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	curlResult = curl_easy_setopt (curlHandle, CURLOPT_UPLOAD, 1L);
	check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
	check (UpdatePayloadText(smtpContext, soapContext) == true, ERROR_STR_INITIALIZATION);
	for (int i = 0; i < 2; i++)
	{
		if (smtpContext->recipients[i] != NULL)
		{
			smtpPayloadText[3].memory = smtpContext->recipients[i];
			if (i == 1)
			{
				curlResult = curl_easy_setopt (curlHandle, CURLOPT_READDATA, (void *)soapContext->registerZipArchive);
				check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
			}
			else
			{
				curlResult = curl_easy_setopt (curlHandle, CURLOPT_READDATA, NULL);
				check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
			}
			curlResult = curl_easy_setopt (curlHandle, CURLOPT_MAIL_RCPT, smtpContext->recipients[i]);
			check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
			curlResult = curl_easy_perform (curlHandle);
			check (curlResult == CURLE_OK, ERROR_STR_LIBCURL, curl_easy_strerror (curlResult));
		}
	}
error:
	if (curlHandle != NULL)
		curl_easy_cleanup (curlHandle);
	if (smtpPayloadText[5].memory != NULL)
	{
		free (smtpPayloadText[5].memory);
		smtpPayloadText[5].memory = NULL;
		smtpPayloadText[5].size = 0;
	}
	if (smtpPayloadText[15].memory != NULL)
	{
		free (smtpPayloadText[15].memory);
		smtpPayloadText[15].memory = NULL;
		smtpPayloadText[15].size = 0;
	}	
	return;
}
