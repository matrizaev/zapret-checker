/*************************************************************************
* Модуль обработки HTTP пакетов.                                         *
*************************************************************************/

#include "allheaders.h"
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include "zapret-checker.h"

/*************************************************************************
* Сверяем запрос с реестром запрещённых сайтов.                          *
* Пример HTTP запроса:                                                   *
* GET {URI} HTTP/x.x\r\n                                                 *
* Header1: Value1\r\n                                                    *
* ...                                                                    *
* HeaderN: ValueN\r\n                                                    *
* \r\n                                                                   *
*************************************************************************/
static bool CheckURL(pfHashTable *httpHashTable, uint8_t *httpPacket, uint16_t dataLen)
{
	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	
	if (httpPacket == NULL || httpHashTable == NULL || dataLen <= 0)
		return false;

	/*************************************************************************
	* Находим конец HTTP заголовка и записываем туда '\0' для корректной     *
	* работы строковых функций.                                              *
	*************************************************************************/
	char *httpHeader = memmem(httpPacket, dataLen, "\r\n\r\n", 4);
	if (httpHeader == NULL)
		return false;
	else
		*httpHeader = 0;

	/*************************************************************************
	* Обрабатываем только GET запросы.                                       *
	*************************************************************************/
	httpHeader = (char *)httpPacket;
	if (strncmp (httpHeader, "GET ", 4) != 0)
		return false;

	/*************************************************************************
	* Ищем начало URL.                                                       *
	*************************************************************************/
	httpHeader += 4;
	while (*httpHeader == ' ' && *httpHeader != 0)
		httpHeader++;

	/*************************************************************************
	* URL может быть в формате URI + Host заголовок или                      *
	* URL может быть полностью в строке запроса.                             *
	*************************************************************************/		
	if (*httpHeader == '/')
	{

		/*************************************************************************
		* Выделяем URL в отдельную ASCII строку.                                 *
		*************************************************************************/
		char *url = httpHeader;
		httpHeader = strchr (httpHeader, ' ');
		if (httpHeader == NULL)
			return false;
		*httpHeader = 0;

		/*************************************************************************
		* Ищем заголовок HOST:xxxxxxx\r\n                                        *
		* Затем ищём начало значения заголовка HOST.                             *
		*************************************************************************/
		httpHeader++;
		httpHeader = strcasestr (httpHeader, "host:");
		if (httpHeader == NULL)
			return false;
		httpHeader += 5;
		while (*httpHeader == ' ')
		{
			if (*httpHeader == 0)
				return false;
			httpHeader++;
		}

		/*************************************************************************
		* Выделяем значение заголовка HOST в отдельную ASCII строку.             *
		*************************************************************************/
		char *host = httpHeader;
		while (*httpHeader != 0  && *httpHeader != '\r' && *httpHeader != '\n')
		{
			*httpHeader = tolower(*httpHeader);
			httpHeader++;
		}
		*httpHeader = 0;

		/*************************************************************************
		* Преобразуем host к нижнему регистру.                                   *
		* Выполняем преобразование URL Decode над строкой.                       *
		*************************************************************************/
		DecodeURL (url);
		if (pfHashCheckExists (httpHashTable, host, url))
		{
			return true;
		}
	}
	else if (strncasecmp (httpHeader, "http://", 7) == 0)
	{
		httpHeader += 7;
		char *host = httpHeader;

		/*************************************************************************
		* Преобразуем host к нижнему регистру.                                   *
		*************************************************************************/
		while (*httpHeader != ' ' && *httpHeader != '/' && *httpHeader != '\r' && *httpHeader != '\n')
		{
			if (*httpHeader == 0)
				return false;
			*httpHeader = tolower(*httpHeader);
			httpHeader++;
		}
		switch (*httpHeader)
		{
			case ' ':
				{
					char *url = "/";
					*httpHeader = 0;
					if (pfHashCheckExists (httpHashTable, host, url))
					{
						return true;
					}
					break;
				}
			case '/':
				{
					*httpHeader = '\0';
					TStringList *data = pfHashFind (httpHashTable, host);
					if (data == NULL)
						return false;
					*httpHeader = '/';
					char *url = httpHeader;
					httpHeader = strchr (httpHeader, ' ');
					if (httpHeader == NULL)
						return false;
					*httpHeader = '\0';
					DecodeURL (url);
					if (StringListFind (data, url) == true)
					{
						return true;
					}
					break;
				}
			default:
				return false;
		}
	}
	return false;
}

static void PrepareTcpAckPacket(uint8_t *redirectNetworkPacket, uint32_t clientIP, uint16_t clientPort, uint32_t serverIP, uint16_t serverPort, uint32_t ackNum, uint32_t seqNum)
{
	if (redirectNetworkPacket == NULL)
		return;
	
	TPseudoHeader *psHdr = (TPseudoHeader *)(redirectNetworkPacket + PSEUDO_HDR_OFFSET);
	psHdr->srcAddr = serverIP;
	psHdr->dstAddr = clientIP;
	psHdr->length = htobe16(sizeof (struct tcphdr));
	psHdr->proto = IPPROTO_TCP;
	psHdr->zero = 0;
	
	struct tcphdr *tcpHdr = (struct tcphdr *)(redirectNetworkPacket + IP4_HDRLEN);
	tcpHdr->ack = 1;
	tcpHdr->doff = sizeof (struct tcphdr) / 4;
	tcpHdr->window = htobe16 (65535);
	tcpHdr->dest = clientPort;
	tcpHdr->source = serverPort;
	tcpHdr->seq = seqNum;
	tcpHdr->ack_seq = ackNum;
	tcpHdr->psh = 0;
	tcpHdr->check = 0;
	tcpHdr->fin = 0;
	tcpHdr->rst = 0;
	uint16_t networkChecksum = checksum ((uint16_t *) (psHdr), TCP_PSEUDO_LEN + sizeof (struct tcphdr));
	tcpHdr->check = networkChecksum;
	FillIPHeader ((struct iphdr *)(redirectNetworkPacket), clientIP, serverIP, IP4_HDRLEN + sizeof (struct tcphdr), IPPROTO_TCP);

	return;
}

static void PrepareHTTPRedirectPacket(uint8_t *redirectNetworkPacket, size_t redirectDataLen, uint32_t clientIP, uint32_t serverIP)
{
	if (redirectNetworkPacket == NULL)
		return;
	TPseudoHeader *psHdr = (TPseudoHeader *)(redirectNetworkPacket + PSEUDO_HDR_OFFSET);
	psHdr->srcAddr = serverIP;
	psHdr->dstAddr = clientIP;
	psHdr->length = htobe16(redirectDataLen - IP4_HDRLEN);
	psHdr->proto = IPPROTO_TCP;
	psHdr->zero = 0;
	
	struct tcphdr *tcpHdr = (struct tcphdr *)(redirectNetworkPacket + IP4_HDRLEN);
	tcpHdr->psh = 1;
	tcpHdr->fin = 1;
	tcpHdr->check = 0;
	uint16_t networkChecksum = checksum ((uint16_t *) (psHdr), TCP_PSEUDO_LEN + redirectDataLen - IP4_HDRLEN);
	tcpHdr->check = networkChecksum;
	FillIPHeader ((struct iphdr *)(redirectNetworkPacket), clientIP, serverIP, redirectDataLen, IPPROTO_TCP);

	return;
}

/*static void PrepareTcpRstPacket (uint8_t *packet, uint32_t clientIP, uint16_t clientPort, uint32_t serverIP, uint16_t serverPort, uint32_t ackNum, uint32_t seqNum)
{
	if (packet == NULL)
		return;
	TPseudoHeader *psHdr = (TPseudoHeader *)(packet + PSEUDO_HDR_OFFSET);
	psHdr->srcAddr = clientIP;
	psHdr->dstAddr = serverIP;
	psHdr->length = htobe16(sizeof (struct tcphdr));
	psHdr->proto = IPPROTO_TCP;
	psHdr->zero = 0;
	struct tcphdr *tcpHdr = (struct tcphdr *)(packet + IP4_HDRLEN);
	tcpHdr->source = clientPort;
	tcpHdr->dest = serverPort;
	tcpHdr->ack = 0;
	tcpHdr->rst = 1;
	tcpHdr->psh = 0;
	tcpHdr->window = 0;
	tcpHdr->check = 0;
	tcpHdr->seq = seqNum;
	tcpHdr->ack_seq = ackNum;
	uint16_t networkChecksum = checksum ((uint16_t *) (psHdr), TCP_PSEUDO_LEN + sizeof (struct tcphdr));
	tcpHdr->check = networkChecksum;
	FillIPHeader ((struct iphdr *)(packet), serverIP, clientIP, IP4_HDRLEN + sizeof (struct tcphdr), IPPROTO_TCP);
	
	return;
}*/


/*************************************************************************
* Модуль обработки HTTP пакетов.                                         *
*************************************************************************/
bool ProcessRawPacketHTTP (uint8_t *packet, size_t packetSize, TNetfilterContext *threadData,  uint8_t hwAddr[8])
{
	

	/*************************************************************************
	* Проверка корректности входных параметров.                              *
	*************************************************************************/
	if (packet == NULL || threadData == NULL)
		return false;
	
	struct iphdr *ipHdr = (struct iphdr *)(packet);
	

	/*************************************************************************
	* Поддерживается только IPV4.                                            *
	*************************************************************************/	
	if (ipHdr->version != 4)
		return false;

	/*************************************************************************
	* Поддерживается только TCP, пакет должен был цельным.                   *
	*************************************************************************/	
	uint16_t totalLen = be16toh(ipHdr->tot_len);
	if (ipHdr->protocol != IPPROTO_TCP || packetSize < totalLen)
		return false;

	/*************************************************************************
	* Находим начало TCP.                                                    *
	*************************************************************************/	
	uint16_t iphLen = (ipHdr->ihl << 2);
	packet += iphLen;
	struct tcphdr *tcpHdr = (struct tcphdr *)(packet);

	/*************************************************************************
	* Находим начало HTTP.                                                    *
	*************************************************************************/	
	uint16_t tcphLen = (tcpHdr->doff << 2);
	packet += tcphLen;

	if ((iphLen + tcphLen) > totalLen)
		return false;
	
	uint16_t dataLen = (totalLen - iphLen - tcphLen);

	/*************************************************************************
	* Если запрос запрещён, подделываем ответ.                               *
	*************************************************************************/
	bool result = false;
	if (CheckURL (threadData->hashTable, packet, dataLen))
	{
		struct sockaddr_ll sin;
		memset (&sin, 0, sizeof (struct sockaddr_ll));
		sin.sll_family = AF_PACKET;
		sin.sll_protocol = htons(ETH_P_IP);
		sin.sll_ifindex = threadData->ifIndex;
		sin.sll_pkttype = PACKET_OUTGOING;
		sin.sll_halen = ETH_ALEN;
		memcpy(&sin.sll_addr, hwAddr, ETH_ALEN);
		
		/*************************************************************************
		* Подготавливаем и посылаем ACK - подтверждение пакета с HTTP запросом.  *
		*************************************************************************/
		PrepareTcpAckPacket(threadData->redirectNetworkPacket, ipHdr->saddr, tcpHdr->source, ipHdr->daddr, tcpHdr->dest, htobe32(be32toh(tcpHdr->seq) + dataLen), tcpHdr->ack_seq);
		sendto (threadData->redirectSocket, threadData->redirectNetworkPacket, IP4_HDRLEN + sizeof (struct tcphdr), 0, (struct sockaddr *) &sin, sizeof (struct sockaddr_ll));
		
		/*************************************************************************
		* Подготавливаем и посылаем HTTP редирект.                               *
		*************************************************************************/
		PrepareHTTPRedirectPacket(threadData->redirectNetworkPacket, threadData->redirectDataLen, ipHdr->saddr, ipHdr->daddr);
		sendto (threadData->redirectSocket, threadData->redirectNetworkPacket, threadData->redirectDataLen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr_ll));

		result = true;
	}
	return result;
}